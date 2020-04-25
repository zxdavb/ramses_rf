"""Message processor."""

import logging
from typing import Optional

from . import parsers
from .const import COMMAND_MAP, DEVICE_MAP, DOMAIN_MAP, MSG_FORMAT_10, MSG_FORMAT_18
from .entity import DEVICE_CLASSES, Device, Domain, Zone

_LOGGER = logging.getLogger(__name__)  # evohome.message


class Message:
    """The message class."""

    def __init__(self, pkt, gateway) -> None:
        """Create a message, assumes a valid packet."""
        self._gateway = gateway
        self._packet = packet = pkt.packet
        self.date = pkt.date
        self.time = pkt.time

        self.rssi = packet[0:3]
        self.verb = packet[4:6]  # -I, RP, RQ, or -W
        self.seq_no = packet[7:10]  # sequence number (as used by 31D9)?

        self.device_id = {}
        for dev, i in enumerate(range(11, 32, 10)):
            self.device_id[dev] = packet[i : i + 9]  # noqa: E203

        self.code = packet[41:45]

        self.payload_length = int(packet[46:49])
        self.raw_payload = packet[50:]
        self._payload = None

        self._repr = None

        self._is_valid = None
        self._is_valid = self.is_valid

    def __repr__(self) -> str:
        """Represent the entity as a string."""

        def name(idx) -> str:
            """Return a friendly device name, of length 10 characters."""
            device_id = self.device_id[idx]

            if device_id[:2] == "--":
                return f"{'':<10}"  # No device ID

            if device_id[:2] == "63":
                return "<null dev>"  # Null device ID

            if idx == 2 and device_id == self.device_id[0]:
                return "<announce>"  # Broadcast?

            dev = self._gateway.device_by_id.get(device_id)
            if dev and dev._friendly_name:
                return f"{dev._friendly_name}"

            # TODO: would we ever get here?
            device_type = DEVICE_MAP.get(device_id[:2], f"{device_id[:2]:>3}")
            return f"{device_type}:{self.device_id[idx][3:]}"

        if self._repr:
            return self._repr

        device_names = [name(x) for x in range(3) if name(x) != f"{'':<10}"] + [""] * 2

        # TODO: the following is a bit dodgy & needs fixing
        if len(self.raw_payload) < 9:
            raw_payload1 = self.raw_payload
            raw_payload2 = ""
        else:
            raw_payload1 = f"{self.raw_payload[:7]}..."[:11]
            raw_payload2 = self.raw_payload
        # raw_payload2 = self.raw_payload if len(self.raw_payload) > 8 else ""

        if self._gateway.config["known_devices"]:
            msg_format = MSG_FORMAT_18
        else:
            msg_format = MSG_FORMAT_10

        xxx = self._payload if self._payload else raw_payload2
        xxx = {} if self._payload == {} else xxx

        self._repr = msg_format.format(
            device_names[0],
            device_names[1],
            self.verb,
            COMMAND_MAP.get(self.code, f"unknown_{self.code}"),
            raw_payload1,
            xxx,
        )

        return self._repr

    @property
    def payload(self) -> Optional[dict]:
        """Return the payload."""
        return self._payload

    @property
    def is_valid(self) -> bool:  # Main code here
        """Return True if the message payload is valid.

        All exceptions are to be trapped, and logged appropriately.
        """

        if self._is_valid is not None:
            return self._is_valid

        try:  # determine which parser to use
            payload_parser = getattr(parsers, f"parser_{self.code}".lower())
        except AttributeError:  # there's no parser for this command code!
            payload_parser = getattr(parsers, "parser_unknown")

        try:
            self._payload = payload_parser(self.raw_payload, self)  # TODO: messy
        except AssertionError:  # for development only?
            # beware: HGI80 can send parseable but 'odd' packets +/- get invalid reply
            _LOGGER.exception("%s", self._packet, extra=self.__dict__)
            return False
        # except (LookupError, TypeError, ValueError):  # shouldn't happen
        #     _LOGGER.exception("%s", self._packet, extra=self.__dict__)
        #     return False

        try:
            self._create_entities()  # but not if: self.device_id[0][:2] != "18"
        except AssertionError:  # unknown device type, or zone_idx > 12
            _LOGGER.exception("%s", self._packet, extra=self.__dict__)
            return False

        # any remaining messages are valid, so: log them
        _LOGGER.info("%s", self, extra=self.__dict__)
        return True  # self._is_valid = True

    def _create_entities(self) -> None:
        """Discover and create new devices, domains and zones."""

        def _ent(ent_cls, ent_id, ent_by_id, ents) -> None:
            try:  # does the system already know about this entity?
                _ = ent_by_id[ent_id]
            except KeyError:  # this is a new entity, so create it
                ent_by_id.update({ent_id: ent_cls(ent_id, self._gateway)})
                ents.append(ent_by_id[ent_id])

        def get_device(dev_id) -> None:
            """Get a Device, create it if required."""
            assert dev_id[:2] in DEVICE_MAP
            dev_cls = DEVICE_CLASSES.get(dev_id[:2], Device)
            _ent(dev_cls, dev_id, self._gateway.device_by_id, self._gateway.devices)

        def get_domain(domain_id) -> None:  # TODO
            """Get a Domain, create it if required."""
            assert domain_id in DOMAIN_MAP
            _ent(Domain, domain_id, self._gateway.domain_by_id, self._gateway.domains)

        def get_zone(zone_idx) -> None:
            """Get a Zone, create it if required."""  # TODO: other zone types?
            assert int(zone_idx, 16) < 12  # TODO: > 11 not for Hometronic
            zone_cls = Zone  # DhwZone if zone_idx == "HW" else Zone  # TODO
            _ent(zone_cls, zone_idx, self._gateway.zone_by_id, self._gateway.zones)

        if self.device_id[0][:2] == "18":
            return

        for dev in range(3):  # discover devices
            if self.device_id[dev][:2] not in ["63", "--"]:
                get_device(self.device_id[dev])

        # discover zones and domains
        if isinstance(self._payload, dict):
            if self._payload.get("domain_id") is not None:
                get_domain(self._payload["domain_id"])

            if self._payload.get("zone_idx") is not None:
                get_zone(self._payload["zone_idx"])

        elif isinstance(self._payload, list):
            if self.device_id[0][:2] == "01" and self.verb == " I":
                if self.code in ["2309", "30C9"]:  # almost all sync cycles
                    for i in range(0, len(self.raw_payload), 6):
                        get_zone(self.raw_payload[i : i + 2])

                elif self.code == "000A":  # the few remaining sync cycles
                    for i in range(0, len(self.raw_payload), 12):
                        get_zone(self.raw_payload[i : i + 2])

    def update_entities(self) -> None:
        """Update the system state with the message data."""

        def _update_entity(data: dict) -> None:
            if "domain_id" in self.payload:
                self._gateway.domain_by_id[self.payload["domain_id"]].update(self)
            elif "zone_idx" in self.payload:
                self._gateway.zone_by_id[self.payload["zone_idx"]].update(self)
            else:
                self._gateway.device_by_id[self.device_id[0]].update(self)

        if not self.is_valid or self.device_id[0][:2] == "18":  # TODO: _id[2] too?
            return

        # who was the message from? There's one special (non-evohome) case...
        idx = self.device_id[0] if self.device_id[0][:2] != "--" else self.device_id[2]
        self._gateway.device_by_id[idx].update(self)

        # what was the message about: system, domain, or zone?
        if self.payload is None:
            return

        if isinstance(self.payload, list):  # 0009 is domains, others are zones
            # assert self.code in ["0009", "000A", "2309", "30C9"]
            [_update_entity(zone) for zone in self.payload]
            return

        if "zone_idx" in self.payload:
            if self.code == "0418":
                return
            elif self.code == "0008":
                return
            # assert self.code in ["12B0", "2309", "3150"]
            _update_entity(self.payload)

        elif "domain_id" in self.payload:
            pass

        elif self.code in ["1FD4", "22D9", "3220"]:  # is for opentherm...
            _update_entity(self.payload)  # TODO: needs checking

        elif "parent_zone_idx" in self.payload:  # is for a device...
            _update_entity(self.payload)

        else:  # is for a device...
            _codes = []
            _codes += ["0100", "042F", "1060", "10A0", "10E0", "1100", "1260", "12A0"]
            _codes += ["1F09", "1F41", "22F1", "2309", "2E04", "30C9", "313F", "31E0"]
            _codes += ["3B00", "3EF0", "22D0"]
            assert self.code in _codes
            _update_entity(self.payload)

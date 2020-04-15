"""Message processor."""

import logging
from typing import Optional

from . import parsers
from .const import COMMAND_MAP, DEVICE_MAP, MESSAGE_FORMAT
from .entity import DEVICE_CLASSES, Device, DhwZone, Zone

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

        self._repr = MESSAGE_FORMAT.format(
            device_names[0],
            device_names[1],
            self.verb,
            COMMAND_MAP.get(self.code, f"unknown_{self.code}"),
            raw_payload1,
            self._payload if self._payload else raw_payload2,
        )

        return self._repr

    @property
    def is_valid(self) -> bool:
        """Return True if the message payload is valid.

        All exceptions are to be trapped, and logged appropriately.
        """

        def harvest_new_entities() -> None:
            """Discover and create new devices and zones (and domains?).

            Assumes a valid payload.
            """
            # TODO: what about domains, e.g. DHW

            def get_device(gateway, dev_id) -> None:
                """Get a Device, create it if required."""
                assert dev_id[:2] in DEVICE_MAP

                try:  # does the system already know about this entity?
                    _ = gateway.device_by_id[dev_id]
                except KeyError:  # this is a new entity, so create it
                    device_cls = DEVICE_CLASSES.get(dev_id[:2], Device)
                    gateway.device_by_id.update({dev_id: device_cls(dev_id, gateway)})

            def get_zone(gateway, zone_idx) -> None:
                """Get a Zone, create it if required."""  # TODO: other zone types?
                assert int(zone_idx, 16) <= 11  # TODO: not for Hometronic

                try:  # does the system already know about this entity?
                    _ = gateway.zone_by_id[zone_idx]
                except KeyError:  # this is a new entity, so create it
                    zone_cls = DhwZone if zone_idx == "HW" else Zone  # TODO: HW?
                    gateway.zone_by_id.update({zone_idx: zone_cls(zone_idx, gateway)})

            for dev in range(3):  # discover devices
                if dev == 0 and self.device_id[dev][:2] == "18":
                    break  # but DEV -> HGI would be OK
                if self.device_id[dev][:2] in ["63", "--"]:
                    continue
                get_device(self._gateway, self.device_id[dev])

            if self.device_id[0][:2] == "01" and self.verb == " I":  # discover zones
                if self.code == "2309":  # almost all sync cycles, with 30C9
                    for i in range(0, len(self.raw_payload), 6):
                        get_zone(self._gateway, self.raw_payload[i : i + 2])
                elif self.code == "000A":  # the few remaining sync cycles
                    for i in range(0, len(self.raw_payload), 12):
                        get_zone(self._gateway, self.raw_payload[i : i + 2])

        if self._is_valid is not None:
            return self._is_valid

        try:  # determine which parser to use
            payload_parser = getattr(parsers, f"parser_{self.code}".lower())
        except AttributeError:
            payload_parser = getattr(parsers, "parser_unknown")

        try:
            self._payload = payload_parser(self.raw_payload, self)  # TODO: messy
        except AssertionError:  # for development only?
            # beware: HGI80 can send parseable but 'odd' packets & get invalid reply
            _LOGGER.exception("%s", self, extra=self.__dict__)
            return False
        except (LookupError, TypeError, ValueError):  # shouldn't happen
            _LOGGER.exception("%s", self, extra=self.__dict__)
            return False

        try:
            harvest_new_entities()  # will ignore if: self.device_id[0][:2] != "18"
        except AssertionError:  # unknown device type, or zone_idx > 12
            _LOGGER.exception("%s", self, extra=self.__dict__)
            return False

        # any remaining messages are valid, so: log them
        _LOGGER.info("%s", self, extra=self.__dict__)
        return True

    @property
    def payload(self) -> Optional[dict]:
        """Return the payload."""
        return self._payload

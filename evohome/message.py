"""Message processor."""

import logging
from typing import Optional

from . import parsers
from .const import COMMAND_MAP, DEVICE_MAP, MESSAGE_FORMAT
from .entity import DEVICE_CLASSES, Device, DhwZone, Zone

_LOGGER = logging.getLogger(__name__)  # evohome.message
_LOGGER.setLevel(logging.INFO)  # INFO or DEBUG


class Message:
    """The message class."""

    def __init__(self, pkt, gateway) -> None:
        """Initialse the class, assumes a valid packet."""
        self._gateway = gateway
        self._packet = packet = pkt.packet
        self._timestamp = pkt.timestamp
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

        self._payload = self._is_valid_payload = None
        self._repr = None

    def __repr__(self) -> str:
        """Represent the entity as a string."""

        if self._repr:
            return self._repr

        def _dev_name(idx) -> str:
            """Return a friendly device name."""
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

            device_type = DEVICE_MAP.get(device_id[:2], f"{device_id[:2]:>3}")
            return f"{device_type}:{self.device_id[idx][3:]}"

        device_names = [_dev_name(x) for x in range(3) if _dev_name(x) != f"{'':<10}"]
        if len(device_names) < 2:
            # ---  I --- --:------ --:------ 10:138822 1FD4 003 000EC6
            # ---  x --- --:------ --:------ --:------ .... from HGI
            device_names += ["", ""]

        if len(self.raw_payload) < 9:
            raw_payload1 = self.raw_payload
            raw_payload2 = ""
        else:
            raw_payload1 = f"{self.raw_payload[:7]}..."[:11]  # TODO: needs fixing
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
    def is_valid_payload(self) -> bool:
        """Return True if the payload is valid."""
        if self._is_valid_payload is None:  # TODO: messy, needs fixing
            self._is_valid_payload = bool(self.payload)  # TODO: remove bool()?
        return self._is_valid_payload

    @property
    def payload(self) -> Optional[dict]:
        """Return the payload."""

        def harvest_new_entities(self):
            def get_device(gateway, device_id):
                """Get a Device, create it if required."""
                assert device_id[:2] not in ["63", "--"]
                assert device_id[:2] in DEVICE_MAP

                try:  # does the system already know about this entity?
                    entity = gateway.device_by_id[device_id]
                except KeyError:  # no, this is a new entity, so create it
                    device_class = DEVICE_CLASSES.get(device_id[:2], Device)
                    entity = device_class(device_id, gateway)

                return entity

            def get_zone(gateway, zone_idx):
                """Get a Zone, create it if required."""
                assert int(zone_idx, 16) <= 11  # TODO: not for Hometronic

                try:  # does the system already know about this entity?
                    entity = gateway.zone_by_id[zone_idx]
                except KeyError:  # no, this is a new entity, so create it
                    zone_class = DhwZone if zone_idx == "HW" else Zone  # RadValve
                    entity = zone_class(zone_idx, gateway)  # TODO: other zone types?

                return entity

            # Discover new (unknown) devices
            for dev in range(3):
                if self.device_id[dev][:2] in ["--", "63"]:
                    continue
                if dev == 0 and self.device_id[dev][:2] == "18":
                    break  # DEV -> HGI is OK?
                get_device(self._gateway, self.device_id[dev])

            # Discover new (unknown) zones
            if self.device_id[0][:2] == "01" and self.verb == " I":
                if self.code == "2309":  # almost all sync cycles with 30C9
                    for i in range(0, len(self.raw_payload), 6):
                        # TODO: add only is payload valid
                        get_zone(self._gateway, self.raw_payload[i : i + 2])

                elif self.code == "000A":  # the few remaining sync cycles
                    for i in range(0, len(self.raw_payload), 12):
                        # TODO: add only if payload valid
                        get_zone(self._gateway, self.raw_payload[i : i + 2])

        if self._is_valid_payload is False:
            return
        if self._is_valid_payload is True:
            return self._payload
        # self._is_valid_payload is None...

        try:
            if self.device_id[0][:2] != "18":  # TODO: may interfere with discovery
                harvest_new_entities(self)
        except AssertionError:  # for dev only?
            self._is_valid_payload = False
            _LOGGER.exception("%s", self, extra=self.__dict__)
            return

        try:  # determine which parser to use
            payload_parser = getattr(parsers, f"parser_{self.code}".lower())
        except AttributeError:
            payload_parser = getattr(parsers, "parser_unknown")

        try:
            if payload_parser:
                self._payload = payload_parser(self.raw_payload, self)

        except AssertionError:  # for development only?
            self._is_valid_payload = False
            # users can send valid (but unparseable) packets & get odd reply
            # if "18" not in [self.device_id[0][:2], self.device_id[1][:2]]:
            _LOGGER.exception("%s", self, extra=self.__dict__)
            return

        except (LookupError, TypeError, ValueError):
            self._is_valid_payload = False
            _LOGGER.exception("%s", self, extra=self.__dict__)
            return

        # TODO: Should just be True by now? If not True, then what?
        self._is_valid_payload = bool(self._payload)
        _LOGGER.info("%s", self, extra=self.__dict__)

        return self._payload

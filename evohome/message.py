"""Message processor."""

import logging
from typing import Optional

from . import parsers
from .const import (
    COMMAND_EXPOSES_ZONE,
    COMMAND_LENGTH,
    COMMAND_LOOKUP,
    COMMAND_MAP,
    COMMAND_SCHEMA,
    DEVICE_LOOKUP,
    DEVICE_MAP,
    HGI_DEV_ID,
    MESSAGE_FORMAT,
    MESSAGE_REGEX,
    NON_DEV_ID,
    NUL_DEV_ID,
    SYSTEM_MODE_MAP,
    ZONE_MODE_MAP,
    ZONE_TYPE_MAP,
)
from .entity import DEVICE_CLASSES, Device, DhwZone, Zone

_LOGGER = logging.getLogger(__name__)  # evohome.message
_LOGGER.setLevel(logging.INFO)  # INFO or DEBUG


class Message:
    """The message class."""

    def __init__(self, gateway, packet, timestamp) -> None:
        self._gateway = gateway
        self._packet = packet
        self._timestamp = timestamp

        self.rssi_val = packet[0:3]  # RSSI value
        self.verb = packet[4:6]  # -I, RP, RQ, or -W
        self.seq_no = packet[7:10]  # sequence number (as used by 31D9)?

        self.device_id = {}
        self.device_type = {}
        self.device_number = {}

        self.code = packet[41:45]

        for dev, i in enumerate(range(11, 32, 10)):
            self.device_id[dev] = packet[i : i + 9]  # noqa: E203
            self.device_type[dev] = DEVICE_MAP.get(
                self.device_id[dev][:2], f"{self.device_id[dev][:2]:>3}"
            )

        self.payload_length = int(packet[46:49])
        self.raw_payload = packet[50:]

        self._payload = None
        self._is_valid_payload = None

    def __str__(self) -> str:
        def _dev_name(idx) -> str:
            """Return a friendly device name."""
            if self.device_id[idx] == NON_DEV_ID:
                return f"{'':<10}"

            if self.device_id[idx] == NUL_DEV_ID:
                return "NUL:------"

            if idx == 2 and self.device_id[2] == self.device_id[0]:
                return "<announce>"  # "<broadcast"

            # friendly_name = self._gateway.device_by_id[self.device_id[idx]]._friendly_name
            # if friendly_name:
            #     return f"{friendly_name[:10]}"

            return f"{self.device_type[idx]}:{self.device_id[idx][3:]}"

        if len(self.raw_payload) < 9:
            raw_payload = self.raw_payload
        else:
            raw_payload = (self.raw_payload[:7] + "...")[:11]

        device_names = [_dev_name(x) for x in range(3) if _dev_name(x) != f"{'':<10}"]

        payload = self._payload

        message = MESSAGE_FORMAT.format(
            device_names[0] if device_names[0] else "",
            device_names[1] if device_names[1] else "",
            self.verb,
            COMMAND_MAP.get(self.code, f"unknown_{self.code}"),
            raw_payload,
            payload if payload else raw_payload if len(raw_payload) > 8 else "",
        )

        return message

    @property
    def is_valid_payload(self) -> bool:
        if self._is_valid_payload is None:
            self._is_valid_payload = bool(self.payload)

        return self._is_valid_payload

    @property
    def payload(self) -> Optional[dict]:
        def harvest_new_entities(self):
            def get_device(gateway, device_id):
                """Get a Device, create it if required."""
                assert device_id not in [NUL_DEV_ID, HGI_DEV_ID, NON_DEV_ID]

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
                if self.device_type[dev] == "HGI":
                    break  # DEV -> HGI is OK?
                if self.device_type[dev] in [" --", "ALL"]:
                    continue
                get_device(self._gateway, self.device_id[dev])

            # Discover new (unknown) zones
            if self.device_type[0] == "CTL" and self.verb == " I":
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

        try:  # determine which parser to use
            payload_parser = getattr(parsers, f"parser_{self.code}".lower())
        except AttributeError:
            payload_parser = getattr(parsers, "parser_unknown")

        try:  # use that parser and (naughty) harvest
            # if "HGI" not in [self.device_type[0], self.device_type[1]]:
            if self.device_type[0] != "HGI":
                # TODO: may interfere with discovery
                harvest_new_entities(self)  # TODO: shouldn't be sharing this try block

            if payload_parser:
                self._payload = payload_parser(self.raw_payload, self)

        except AssertionError:  # for dev only?
            self._is_valid_payload = False

            # if "HGI" not in [self.device_type[0], self.device_type[1]]:
            _LOGGER.exception(
                "%s", str(self),
                extra={"date": self._timestamp[:10], "time": self._timestamp[11:]}
            )
            return

        except (LookupError, TypeError, ValueError):
            self._is_valid_payload = False

            _LOGGER.exception(
                "%s", str(self),
                extra={"date": self._timestamp[:10], "time": self._timestamp[11:]}
            )
            return

        _LOGGER.info(
            "%s", str(self),
            extra={"date": self._timestamp[:10], "time": self._timestamp[11:]}
        )

        return self._payload

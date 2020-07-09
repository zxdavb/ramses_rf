"""Message processor."""

from datetime import datetime as dt
import logging
from typing import Any, Optional, Tuple, Union

from . import parsers
from .const import (
    CODE_MAP,
    DEVICE_TYPES,
    MSG_FORMAT_10,
    MSG_FORMAT_18,
    NON_DEVICE,
    NUL_DEVICE,
    Address,
    __dev_mode__,
)
from .devices import Device
from .zones import create_zone as EvoZone

_LOGGER = logging.getLogger(__name__)


class Message:
    """The message class."""

    def __init__(self, gateway, pkt) -> None:
        """Create a message, assumes a valid packet."""
        self._gwy = gateway
        self._pkt = packet = pkt.packet

        # HACK: prefer Device(s) (but don't create here), otherwise keep as Address(es)
        self.src = gateway.device_by_id.get(pkt.src_addr.id, pkt.src_addr)
        self.dst = gateway.device_by_id.get(pkt.dst_addr.id, pkt.dst_addr)

        self.devs = pkt.addrs
        self.date = pkt.date
        self.time = pkt.time
        self.dtm = dt.fromisoformat(f"{pkt.date}T{pkt.time}")

        self.rssi = packet[0:3]
        self.verb = packet[4:6]
        self.seqn = packet[7:10]  # sequence number (as used by 31D9)?
        self.code = packet[41:45]

        self.len = int(packet[46:49])  # TODO:  is useful? / is user used?
        self.raw_payload = packet[50:]

        self._payload = self._str = None
        self._is_array = self._is_fragment = self._is_valid = None

        _ = self.is_valid
        # _ = self.is_fragment_WIP

        if self.code != "000C":  # TODO: assert here, or in is_valid()
            assert self.is_array == isinstance(self.payload, list)

    def __repr__(self) -> str:
        return self._pkt

    def __str__(self) -> str:
        """Represent the entity as a string."""

        def display_name(dev: Union[Address, Device]) -> str:
            """Return a formatted device name, uses a friendly name if there is one."""
            if dev is NON_DEVICE:
                return f"{'':<10}"

            if dev is NUL_DEVICE:
                return "NUL:------"

            if dev.id in self._gwy.known_devices:
                if self._gwy.known_devices[dev.id].get("friendly_name"):
                    return self._gwy.known_devices[dev.id]["friendly_name"]

            return f"{DEVICE_TYPES.get(dev.type, f'{dev.type:>3}')}:{dev.id[3:]}"

        if self._str:
            return self._str

        if self._gwy.config["known_devices"]:
            msg_format = MSG_FORMAT_18
        else:
            msg_format = MSG_FORMAT_10

        if self.src.id == self.devs[0].id:
            src = display_name(self.src)
            dst = display_name(self.dst) if self.dst is not self.src else ""
        else:
            src = ""
            dst = display_name(self.src)

        code = CODE_MAP.get(self.code, f"unknown_{self.code}")
        payload = self.raw_payload if self.len < 4 else f"{self.raw_payload[:5]}..."[:9]

        self._str = msg_format.format(src, dst, self.verb, code, payload, self._payload)
        return self._str

    def __eq__(self, other) -> bool:
        return all(
            self.verb == other.verb,
            self.code == other.code,
            self.src.id == other.src.id,
            self.dst.id == other.dst.id,
            self.raw_payload == other.raw_payload,
        )

    @property
    def payload(self) -> Any:  # Any[dict, List[dict]]:
        """Return the payload."""
        return self._payload

    @property
    def is_array(self) -> bool:
        """Return True if the message's raw payload is an array.

        Note that the corresponding parsed payload may not match, e.g. 000C.
        """

        if self._is_array is not None:
            return self._is_array

        if self.code in ("000C", "1FC9"):  # also: 0005?
            # grep -E ' (I|RP).* 000C '  #  from 01:/30: (VMS) only
            # grep -E ' (I|RP).* 1FC9 '  #  from 01:/13:/other (not W)
            self._is_array = self.verb in (" I", "RP")

        elif self.verb not in (" I", "RP") or self.src is not self.dst:
            self._is_array = False

        # 045  I --- 01:158182 --:------ 01:158182 0009 003 0B00FF (or: FC00FF)
        # 045  I --- 01:145038 --:------ 01:145038 0009 006 FC00FFF900FF
        elif self.code in ("0009") and self.src.type == "01":
            # grep -E ' I.* 01:.* 01:.* 0009 [0-9]{3} F' (and: grep -v ' 003 ')
            self._is_array = self.verb == " I" and self.raw_payload[:1] == "F"

        elif self.code in ("000A", "2309", "30C9") and self.src.type == "01":
            # grep ' I.* 01:.* 01:.* 000A '
            # grep ' I.* 01:.* 01:.* 2309 ' | grep -v ' 003 '  # TODO: some non-arrays
            # grep ' I.* 01:.* 01:.* 30C9 '
            self._is_array = self.verb == " I" and self.src is self.dst

        # 055  I --- 02:001107 --:------ 02:001107 22C9 024 0008340A28010108340A...
        # 055  I --- 02:001107 --:------ 02:001107 22C9 006 0408340A2801
        # 055  I --- 02:001107 --:------ 02:001107 3150 010 00640164026403580458
        # 055  I --- 02:001107 --:------ 02:001107 3150 010 00000100020003000400
        elif self.code in ("22C9", "3150") and self.src.type == "02":
            # grep -E ' I.* 02:.* 02:.* 22C9 '
            # grep -E ' I.* 02:.* 02:.* 3150' | grep -v FC
            self._is_array = self.verb == " I" and self.src is self.dst
            self._is_array = self._is_array if self.raw_payload[:1] != "F" else False

        # 095  I --- 23:100224 --:------ 23:100224 2249 007 007EFF7EFFFFFF
        # 095  I --- 23:100224 --:------ 23:100224 2249 007 007EFF7EFFFFFF
        elif self.code in ("2249") and self.src.type == "23":
            self._is_array = self.verb == " I" and self.src is self.dst
            # self._is_array = self._is_array if self.raw_payload[:1] != "F" else False

        else:
            self._is_array = False

        return self._is_array

    @property
    def is_fragment_WIP(self) -> bool:
        """Return True if the raw payload is a fragment of a message."""

        # if not self._is_valid:
        #     return
        if self._is_fragment is not None:
            return self._is_fragment

        # packets have a maximum length of 48 (decimal)
        # if self.code == "000A" and self.verb == " I":
        #     self._is_fragment = True if len(???.zones) > 8 else None
        # el
        if self.code == "0404" and self.verb == "RP":
            self._is_fragment = True
        elif self.code == "22C9" and self.verb == " I":
            self._is_fragment = None  # max length 24!
        else:
            self._is_fragment = False

        return self._is_fragment

    @property
    def is_valid(self) -> bool:  # Main code here
        """Parse the payload, return True if the message payload is valid.

        All exceptions are trapped, and logged appropriately.
        """

        if self._is_valid is not None:
            return self._is_valid

        try:  # determine which parser to use
            payload_parser = getattr(parsers, f"parser_{self.code}".lower())

        except AttributeError:  # there's no parser for this command code!
            payload_parser = getattr(parsers, "parser_unknown")

        try:  # run the parser
            self._payload = payload_parser(self.raw_payload, self)  # TODO: messy
            assert isinstance(self.payload, dict) or isinstance(self.payload, list)

        except AssertionError:  # for development only?
            # beware: HGI80 can send parseable but 'odd' packets +/- get invalid reply
            if self.src.type == "18":  # TODO: should be a warning
                _LOGGER.exception("%s", self._pkt, extra=self.__dict__)
            else:
                _LOGGER.exception("%s", self._pkt, extra=self.__dict__)
            self._is_valid = False
            return self._is_valid

        else:
            self._is_valid = True

        # any remaining messages are valid, so: log them
        if False and __dev_mode__:  # a hack to colourize by cycle
            if self.src.type == "01" and self.verb == " I":
                if (
                    self.code == "1F09"
                    or self.code in ("2309", "30C9", "000A")
                    and isinstance(self.payload, list)
                ):
                    _LOGGER.warning("%s", self, extra=self.__dict__)
                else:
                    _LOGGER.info("%s", self, extra=self.__dict__)
            else:
                _LOGGER.info("%s", self, extra=self.__dict__)
        elif False and __dev_mode__:  # a hack to colourize by verb
            if " I" in str(self):
                _LOGGER.info("%s", self, extra=self.__dict__)
            elif "RP" in str(self):
                _LOGGER.warning("%s", self, extra=self.__dict__)
            else:
                _LOGGER.error("%s", self, extra=self.__dict__)
        else:
            _LOGGER.info("%s", self, extra=self.__dict__)

        return self._is_valid

    def create_devices(self) -> Tuple[Device, Optional[Device]]:
        """Parse the payload and create any new device(s).

        Only 000C requires a valid message.
        """

        if self.src.type in ("01", "23"):
            self._gwy.get_device(self.dst, controller=self.src)

        elif self.dst.type in ("01", "23"):
            self._gwy.get_device(self.src, controller=self.dst)

        elif self.code == "1F09" and self.verb == " I":
            # this is sufficient, no need for: "000A", "2309", "30C9" (list)
            # maybe also: "0404", "0418", "313F", "2E04"
            self._gwy.get_device(self.dst, controller=self.src)

        elif self.code == "31D9" and self.verb == " I":
            self._gwy.get_device(self.dst, controller=self.src)

        # this is pretty reliable...
        elif self.code == "000C" and self.verb == "RP":
            self._gwy.get_device(self.dst, controller=self.src)
            if self._is_valid:
                [
                    self._gwy.get_device(
                        Address(id=d, type=d[:2]),
                        controller=self.src,
                        parent_000c=self.payload["zone_idx"],
                    )
                    for d in self.payload["actuators"]
                ]

        # special case - needs a Device, not an Address - TODO: is it needed at all?
        elif isinstance(self.src, Device) and self.src.is_controller:
            self._gwy.get_device(self.dst, controller=self.src)

        # special case - needs a Device, not an Address - TODO: is it needed at all?
        elif isinstance(self.dst, Device) and self.dst.is_controller:
            self._gwy.get_device(self.src, controller=self.dst)

        else:  # finally, a catch-all
            self._gwy.get_device(self.src)
            if self.dst is not self.src:
                self._gwy.get_device(self.dst)

        # maybe what was an Address can now be a Device
        if not isinstance(self.src, Device):
            self.src = self._gwy.device_by_id[self.src.id]
        if not isinstance(self.dst, Device) and self.dst.type not in ("--", "63"):
            self.dst = self._gwy.device_by_id[self.dst.id]

    def create_entities(self) -> None:
        """Discover and create new entities (zones, ufh_zones).

        Requires a valid message.
        """

        # if not self._is_valid:  # TODO: not needed
        #     return

        # This filter will improve teh quality of data / reduce processing time
        if self.src.type not in ("01", "02", "23"):  # self._gwy.system_by_id:
            return

        # TODO: also process ufh_idx (but never domain_id)
        if isinstance(self._payload, dict):
            if self._payload.get("zone_idx"):  # TODO: parent_zone too?
                domain_type = "zone_idx"
            else:
                return
            # EvoZone(self._gwy, self._payload[domain_type], self.src)

        elif isinstance(self._payload, list):
            if self.code in ("000A", "2309", "30C9"):  # the sync_cycle pkts
                domain_type = "zone_idx"
            # elif self.code in ("22C9", "3150"):  # UFH zone
            # domain_type = "ufh_idx"
            else:
                return
            [EvoZone(self._gwy, d[domain_type], self.src) for d in self.payload]

        else:  # should never get here
            raise TypeError

    def update_entities(self) -> None:  # TODO: needs work
        """Update the state of entities (devices, zones, ufh_zones).

        Requires a valid message.
        """

        if not self._is_valid:
            return

        # TODO: where does this go? here, or _create?
        # ASSERT: parent_idx heuristics using the data in known_devices.json
        if isinstance(self.payload, dict):  # and __dev_mode__
            # assert self.src.id in self._gwy.known_devices
            if self.src.id in self._gwy.known_devices:
                idx = self._gwy.known_devices[self.src.id].get("zone_idx")
                if idx and self._gwy.device_by_id[self.src.id].parent_000c:
                    assert idx == self._gwy.device_by_id[self.src.id].parent_000c
                if idx and "parent_idx" in self.payload:
                    assert idx == self.payload["parent_idx"]

        # some empty payloads may still be useful (e.g. RQ/3EF1/{})
        try:
            self._gwy.device_by_id[self.src.id].update(self)
        except KeyError:  # some devices aren't created if they're filtered out
            return

        # if payload is {} (empty dict; lists shouldn't ever be empty)
        if not self.payload:
            return

        # lists only useful to devices (c.f. 000C)
        if isinstance(self.payload, dict) and "zone_idx" in self.payload:
            evo = self.src._evo  # TODO: needs device?
            if evo is None and isinstance(self.dst, Device):
                evo = self.dst._evo

            if evo is not None and self.payload["zone_idx"] in evo.zone_by_id:
                evo.zone_by_id[self.payload["zone_idx"]].update(self)

            # elif self.payload.get("ufh_idx") in ...:  # TODO: is this needed?
            #     pass

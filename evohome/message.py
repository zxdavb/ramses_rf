"""Message processor."""

from collections import namedtuple
from datetime import datetime as dt
import logging
from typing import Any

from . import parsers
from .const import (
    __dev_mode__,
    CODE_MAP,
    DEVICE_TYPES,
    MSG_FORMAT_10,
    MSG_FORMAT_18,
    NON_DEV_ID,
    NUL_DEV_ID,
)

# from .devices import DEVICE_CLASS, Device, create_device
from .domains import create_domain

Address = namedtuple("DeviceAddress", "addr, type")
NON_DEVICE = Address(addr="", type="--")

_LOGGER = logging.getLogger(__name__)


class Message:
    """The message class."""

    def __init__(self, gateway, pkt) -> None:
        """Create a message, assumes a valid packet."""
        self._gwy = gateway
        self._evo = gateway.evo
        self._pkt = packet = pkt.packet

        self.devs = pkt.addrs
        self.src = gateway.device_by_id.get(pkt.src_addr.id, pkt.src_addr)
        self.dst = gateway.device_by_id.get(pkt.dst_addr.id, pkt.dst_addr)

        self.date = pkt.date
        self.time = pkt.time
        self.dtm = dt.fromisoformat(f"{pkt.date}T{pkt.time}")

        self.rssi = packet[0:3]
        self.verb = packet[4:6]
        self.seq_no = packet[7:10]  # sequence number (as used by 31D9)?
        self.code = packet[41:45]

        self.len = int(packet[46:49])  # TODO:  is useful? / is user used?
        self.raw_payload = packet[50:]

        self._payload = self._str = None
        self._is_array = self._is_fragment = self._is_valid = None

        self._is_valid = self._parse_payload()
        self._is_fragment = self.is_fragment_WIP

        if self.code != "000C":  # TODO: assert here, or in is_valid()
            assert self.is_array == isinstance(self.payload, list)

    def __str__(self) -> str:
        """Represent the entity as a string."""

        def display_name(dev) -> str:
            """Return a formatted device name, uses a friendly name if there is one."""
            if dev.id == NON_DEV_ID:
                return f"{'':<10}"

            if dev.id == NUL_DEV_ID:
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
            dst = display_name(self.dst) if self.dst.id != self.src.id else ""
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
            # self.seq_no == other.seq_no,
            self.code == other.code,
            self.src == other.src,
            self.dst == other.dst,
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
            return self._is_array

        if self.verb not in (" I", "RP") or self.src.id != self.dst.id:
            self._is_array = False
            return self._is_array

        # 045  I --- 01:158182 --:------ 01:158182 0009 003 0B00FF (or: FC00FF)
        # 045  I --- 01:145038 --:------ 01:145038 0009 006 FC00FFF900FF
        if self.code in ("0009") and self.src.type == "01":
            # grep -E ' I.* 01:.* 01:.* 0009 [0-9]{3} F' (and: grep -v ' 003 ')
            self._is_array = self.verb == " I" and self.raw_payload[:1] == "F"

        elif self.code in ("000A", "2309", "30C9") and self.src.type == "01":
            # grep ' I.* 01:.* 01:.* 000A '
            # grep ' I.* 01:.* 01:.* 2309 ' | grep -v ' 003 '  # TODO: some non-arrays
            # grep ' I.* 01:.* 01:.* 30C9 '
            self._is_array = self.verb == " I" and self.src.id == self.dst.id

        # 055  I --- 02:001107 --:------ 02:001107 22C9 024 0008340A28010108340A...
        # 055  I --- 02:001107 --:------ 02:001107 22C9 006 0408340A2801
        # 055  I --- 02:001107 --:------ 02:001107 3150 010 00640164026403580458
        # 055  I --- 02:001107 --:------ 02:001107 3150 010 00000100020003000400
        elif self.code in ("22C9", "3150") and self.src.type == "02":
            # grep -E ' I.* 02:.* 02:.* 22C9 '
            # grep -E ' I.* 02:.* 02:.* 3150' | grep -v FC
            self._is_array = self.verb == " I" and self.src.id == self.dst.id
            self._is_array = self._is_array if self.raw_payload[:1] != "F" else False

        # 095  I --- 23:100224 --:------ 23:100224 2249 007 007EFF7EFFFFFF
        # 095  I --- 23:100224 --:------ 23:100224 2249 007 007EFF7EFFFFFF
        elif self.code in ("2249") and self.src.type == "23":
            self._is_array = self.verb == " I" and self.src.id == self.dst.id
            # self._is_array = self._is_array if self.raw_payload[:1] != "F" else False

        else:
            self._is_array = False

        return self._is_array

    @property
    def is_fragment_WIP(self) -> bool:
        """Return True if the raw payload is a fragment of a message."""

        if self._is_fragment is not None:
            return self._is_fragment

        # packets have a maximum length of 48 (decimal)
        if self.code == "000A" and self.verb == " I":
            self._is_fragment = True if len(self._evo.zones) > 8 else None
        elif self.code == "0404" and self.verb == "RP":
            self._is_fragment = True
        elif self.code == "22C9" and self.verb == " I":
            self._is_fragment = None  # max length 24!
        else:
            self._is_fragment = False

        return self._is_fragment

    @property
    def is_valid(self) -> bool:
        """Return True if the message payload is valid."""

        return self._is_valid

    def _parse_payload(self) -> bool:  # Main code here
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
            return False

        # STATE: update parser state (last packet code) - not needed?
        if self._evo is not None and self._evo.ctl.id == self.src.id:
            self._evo._prev_code = self.code if self.verb == " I" else None
        # TODO: add state for 000C?

        # for dev_id in self.dev_addr:  # TODO: leave in, or out?
        #     assert dev_id[:2] in DEVICE_TYPES  # incl. "--", "63"

        # any remaining messages are valid, so: log them
        if False and __dev_mode__:  # a hack to colourize by verb
            if " I" in str(self):
                _LOGGER.info("%s", self, extra=self.__dict__)
            elif "RP" in str(self):
                _LOGGER.warning("%s", self, extra=self.__dict__)
            else:
                _LOGGER.error("%s", self, extra=self.__dict__)
        else:
            _LOGGER.info("%s", self, extra=self.__dict__)

        return True  # self._is_valid = True

    def _create_entities(self) -> None:
        """Discover and create new devices, domains and zones."""

        # STEP 0: discover devices by harvesting zone_actuators payload
        # if self.code == "000C" and self.verb == "RP":  # or: from CTL/000C
        #     [_device(d, self.payload["zone_idx"]) for d in self.payload["actuators"]]

        # self.src = self._evo.device_by_id[self.src.id]
        # self.dst = self._evo.device_by_id.get(self.dst.id)

        # STEP 2: discover domains and zones by eavesdropping regular pkts
        if self.src.id not in self._gwy.system_by_id:
            return

        # if self.src.type != "01" and self.verb == " I":
        #     return

        if isinstance(self._payload, dict):
            if self._payload.get("domain_id"):
                domain_type = "domain_id"
            elif self._payload.get("zone_idx"):  # TODO: parent_zone too?
                domain_type = "zone_idx"
            else:
                return
            create_domain(self._gwy, self._payload[domain_type], self.src)

        else:  # elif isinstance(self._payload, list):
            if self.code == "0009":
                domain_type = "domain_id"
            elif self.code in ("000A", "2309", "30C9"):  # the sync_cycle pkts
                domain_type = "zone_idx"
            # elif self.code in ("22C9", "3150"):  # UFH zone
            # domain_type = "ufh_idx"
            else:
                return
            [create_domain(self._gwy, d[domain_type], self.src) for d in self.payload]

    def _update_entities(self) -> None:  # TODO: needs work
        """Update the system state with the message data."""

        if self._evo is None:
            return

        # CHECK: confirm parent_idx heuristics using the data in known_devices.json
        if False and __dev_mode__ and isinstance(self.payload, dict):
            # assert self.src.id in self._gwy.known_devices
            if self.src.id in self._gwy.known_devices:
                idx = self._gwy.known_devices[self.src.id].get("zone_idx")
                if idx and self._evo.device_by_id[self.src.id].parent_000c:
                    assert idx == self._evo.device_by_id[self.src.id].parent_000c
                if idx and "parent_idx" in self.payload:
                    assert idx == self.payload["parent_idx"]

        if not self.payload:  # should be {} (possibly empty) or [...] (never empty)
            return  # TODO: will stop useful RQs getting to update()? (e.g. RQ/3EF1)

        try:
            self._evo.device_by_id[self.src.id].update(self)
        except KeyError:  # some devices weren't created because they were filtered
            return

        if self.code != "0418":  # update domains & zones
            if "domain_id" in self.payload:
                self._evo.domain_by_id[self.payload["domain_id"]].update(self)
            if "zone_idx" in self.payload:
                self._evo.zone_by_id[self.payload["zone_idx"]].update(self)

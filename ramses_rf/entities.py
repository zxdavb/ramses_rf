#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser."""

import logging
from typing import List

from .const import Discover, __dev_mode__

from .protocol import I_, RP, RQ, W_  # noqa: F401, isort: skip
from .protocol import (  # noqa: F401, isort: skip
    _0001,
    _0002,
    _0004,
    _0005,
    _0006,
    _0008,
    _0009,
    _000A,
    _000C,
    _000E,
    _0016,
    _0100,
    _01D0,
    _01E9,
    _0404,
    _0418,
    _042F,
    _0B04,
    _1030,
    _1060,
    _1081,
    _1090,
    _10A0,
    _10E0,
    _1100,
    _1260,
    _1280,
    _1290,
    _1298,
    _12A0,
    _12B0,
    _12C0,
    _12C8,
    _12F0,
    _1300,
    _1F09,
    _1F41,
    _1FC9,
    _1FD4,
    _2249,
    _22C9,
    _22D0,
    _22D9,
    _22F1,
    _22F3,
    _2309,
    _2349,
    _2389,
    _2D49,
    _2E04,
    _30C9,
    _3120,
    _313F,
    _3150,
    _31D9,
    _31DA,
    _31E0,
    _3220,
    _3B00,
    _3EF0,
    _3EF1,
    _PUZZ,
)

DEFAULT_BDR_ID = "13:000730"
DEFAULT_EXT_ID = "17:000730"
DEFAULT_THM_ID = "03:000730"

_QOS_TX_LIMIT = 12

DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


def discover_decorator(fnc):
    # NOTE: only need to Wrap top-level entities
    def wrapper(self, discover_flag=Discover.ALL) -> None:

        if self._gwy.config.disable_discovery:
            return
        if not discover_flag:
            return
        return fnc(self, discover_flag=discover_flag)

    return wrapper


class Entity:
    """The Device/Zone base class.

    This class is mainly concerned with the entity's state database.
    """

    def __init__(self, gwy) -> None:
        self._loop = gwy._loop

        self._gwy = gwy
        self.id = None

        self._msgs = {}
        self._msgz = {}

        self._qos_tx_count = 0  # the number of pkts Tx'd with no matching Rx

    def _qos_function(self, pkt, reset=False) -> None:
        if reset:
            self._qos_tx_count = 0
            return

        self._qos_tx_count += 1
        if self._qos_tx_count == _QOS_TX_LIMIT:
            _LOGGER.warning(
                f"{pkt} < Sending now deprecated for {self} "
                "(consider adjusting device_id filters)"
            )  # TODO: take whitelist into account

    def _discover(self, discover_flag=Discover.ALL) -> None:
        pass

    def _handle_msg(self, msg) -> None:  # TODO: beware, this is a mess
        if (
            self._gwy.pkt_protocol is None
            or msg.src.id != self._gwy.pkt_protocol._hgi80.get("device_id")
        ):
            self._qos_function(msg._pkt, reset=True)

        if msg.verb in (I_, RP):
            self._msgs[msg.code] = msg

        if msg.code not in self._msgz:
            self._msgz[msg.code] = {msg.verb: {msg._pkt._ctx: msg}}
        elif msg.verb not in self._msgz[msg.code]:
            self._msgz[msg.code][msg.verb] = {msg._pkt._ctx: msg}
        else:
            self._msgz[msg.code][msg.verb][msg._pkt._ctx] = msg

        # TODO:
        # if msg.verb == RP and msg._pkt._idx in self._msgz[msg.code].get(I_, []):
        #     assert msg.raw_payload == self._msgz[msg.code][I_][msg._pkt._idx].raw_payload, (
        #         f"\r\n{msg._pkt} ({msg._pkt._idx}),"
        #         f"\r\n{self._msgz[msg.code][I_][msg._pkt._idx]._pkt} ({msg._pkt._idx})"
        #     )
        #     del self._msgz[msg.code][I_][msg._pkt._idx]

        # elif msg.verb == I_ and msg._pkt._idx in self._msgz[msg.code].get(RP, []):
        #     assert msg.raw_payload == self._msgz[msg.code][RP][msg._pkt._idx].raw_payload, (
        #         f"\r\n{msg._pkt} ({msg._pkt._idx}),"
        #         f"\r\n{self._msgz[msg.code][RP][msg._pkt._idx]._pkt} ({msg._pkt._idx})"
        #     )
        #     del self._msgz[msg.code][RP][msg._pkt._idx]

    @property
    def _msg_db(self) -> List:  # a flattened version of _msgz[code][verb][indx]
        """Return a flattened version of _msgz[code][verb][indx]."""
        return [m for c in self._msgz.values() for v in c.values() for m in v.values()]

    # @property
    # def _pkt_db(self) -> Dict:
    #     """Return a flattened version of ..."""
    #     return {msg.dtm: msg._pkt for msg in self._msgs_db}

    def _make_cmd(self, code, dest_id, payload, verb=RQ, **kwargs) -> None:
        self._send_cmd(self._gwy.create_cmd(verb, dest_id, code, payload, **kwargs))

    def _send_cmd(self, cmd, **kwargs) -> None:
        if self._gwy.config.disable_sending:
            _LOGGER.info(f"{cmd} < Sending is disabled")
            return

        if self._qos_tx_count > _QOS_TX_LIMIT:
            _LOGGER.info(f"{cmd} < Sending is deprecated for {self}")
            return

        if getattr(self, "has_battery", None) and cmd.dst.id == self.id:
            _LOGGER.info(f"{cmd} < Sending inadvisable for {self} (has a battery)")

        cmd._source_entity = self
        # self._msgs.pop(cmd.code, None)  # NOTE: Cause of DHW bug
        self._gwy.send_cmd(cmd)

    def _msg_value(self, code, *args, **kwargs) -> dict:
        if isinstance(code, (str, tuple)):  # a code or a tuple of codes
            return self._msg_value_code(code, *args, **kwargs)
        return self._msg_value_msg(code, *args, **kwargs)  # assume is a Message

    def _msg_value_code(self, code, verb=None, key=None, **kwargs) -> dict:

        assert (
            not isinstance(code, tuple) or verb is None
        ), f"Unsupported: using a tuple ({code}) with a verb ({verb})"

        if verb:
            try:
                msgs = self._msgz[code][verb]
            except KeyError:
                msg = None
            else:
                msg = max(msgs.values()) if msgs else None
        elif isinstance(code, tuple):
            msgs = [m for m in self._msgs.values() if m.code in code]
            msg = max(msgs) if msgs else None
        else:
            msg = self._msgs.get(code)

        return self._msg_value_msg(msg, key=key, **kwargs)

    def _msg_value_msg(self, msg, key=None, zone_idx=None, domain_id=None) -> dict:

        if msg is None:
            return
        elif msg._expired:
            delete_msg(msg)

        if domain_id:
            idx, val = "domain_id", domain_id
        elif zone_idx:
            idx, val = "zone_idx", zone_idx
        else:
            idx = val = None

        if isinstance(msg.payload, list) and idx:
            msg_dict = {
                k: v for d in msg.payload for k, v in d.items() if d[idx] == val
            }
        elif isinstance(msg.payload, list):
            # TODO: this isn't ideal: e.g. a controller is being treated like a 'stat
            #  I 101 --:------ --:------ 12:126457 2309 006 0107D0-0207D0  # is a CTL
            msg_dict = msg.payload[0]
        else:
            msg_dict = msg.payload

        assert (
            not domain_id and not zone_idx or msg_dict.get(idx) == val
        ), f"{msg_dict} < Coding error: key={idx}, val={val}"

        if key:
            return msg_dict.get(key)
        return {
            k: v
            for k, v in msg_dict.items()
            if k not in ("dhw_idx", "domain_id", "zone_idx") and k[:1] != "_"
        }

    @property
    def _codes(self) -> dict:
        return {
            "codes": sorted([k for k, v in self._msgs.items()]),
        }

    @property
    def controller(self):  # -> Optional[Controller]:
        """Return the entity's controller, if known."""

        return self._ctl  # TODO: if the controller is not known, try to find it?


def delete_msg(msg) -> None:
    """Remove the msg from all state databases."""
    entities = [msg.src]
    if hasattr(msg.src, "_evo"):
        entities.append(msg.src._evo)
        if msg.src._evo._dhw:
            entities.append(msg.src._evo._dhw)
        entities.extend(msg.src._evo.zones)

    # remove the msg from all the state DBs
    for obj in entities:
        if msg in obj._msgs.values():
            del obj._msgs[msg.code]
        try:
            del obj._msgz[msg.code][msg.verb][msg._pkt._ctx]
        except KeyError:
            pass

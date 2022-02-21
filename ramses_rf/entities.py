#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser."""

import logging
from inspect import getmembers, isclass
from sys import modules
from typing import Optional

from .const import Discover, __dev_mode__
from .protocol.ramses import CODES_SCHEMA, NAME

# skipcq: PY-W2000
from .protocol import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
)

DEFAULT_BDR_ID = "13:000730"
DEFAULT_EXT_ID = "17:000730"
DEFAULT_THM_ID = "03:000730"

_QOS_TX_LIMIT = 12

DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


def class_by_attr(name: str, attr: str) -> dict:
    """Return a mapping of a (unique) attr of classes in a module to that class.

    For example:
      {"OTB": OtbGateway, "CTL": Controller}
      {"RAD": RadZone, "UFH": UfhZone}
      {"evohome": Evohome}
    """

    return {
        getattr(c[1], attr): c[1]
        for c in getmembers(
            modules[name],
            lambda m: isclass(m) and m.__module__ == name and hasattr(m, attr),
        )
    }


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

        self._msgs = {}  # code, should be code/ctx? ?deprecate
        self._msgz = {}  # code/verb/ctx, should be code/ctx/verb?

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

    @property
    def _msg_db(self) -> list:  # a flattened version of _msgz[code][verb][indx]
        """Return a flattened version of _msgz[code][verb][indx]."""
        return [m for c in self._msgz.values() for v in c.values() for m in v.values()]

    # @property
    # def _pkt_db(self) -> dict:
    #     """Return a flattened version of ..."""
    #     return {msg.dtm: msg._pkt for msg in self._msgs_db}

    def _make_cmd(self, code, dest_id, payload="00", verb=RQ, **kwargs) -> None:
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

    def _msg_flag(self, code, key, idx) -> Optional[bool]:
        if flags := self._msg_value(code, key=key):
            return bool(flags[idx])

    def _msg_value(self, code, *args, **kwargs):
        if isinstance(code, (str, tuple)):  # a code or a tuple of codes
            return self._msg_value_code(code, *args, **kwargs)
        return self._msg_value_msg(code, *args, **kwargs)  # assume is a Message

    def _msg_value_code(self, code, verb=None, key=None, **kwargs) -> Optional[dict]:

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

    @staticmethod
    def _msg_value_msg(msg, key=None, zone_idx=None, domain_id=None) -> Optional[dict]:

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
            k: (CODES_SCHEMA[k][NAME] if k in CODES_SCHEMA else None)
            for k in sorted(self._msgs)
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

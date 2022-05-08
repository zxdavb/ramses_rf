#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Entity is the base of all RAMSES-II objects: devices and also system/zone constructs.
"""

import logging
import sqlite3
from inspect import getmembers, isclass
from sys import modules
from typing import Optional

from .const import (
    SZ_DEVICE_ID,
    SZ_DOMAIN_ID,
    SZ_NAME,
    SZ_ZONE_IDX,
    Discover,
    __dev_mode__,
)
from .protocol import Message
from .protocol.ramses import CODES_SCHEMA
from .protocol.transport import PacketProtocolPort

# skipcq: PY-W2000
from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    _1FC9,
)

_QOS_TX_LIMIT = 12  # TODO: needs work

DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


def class_by_attr(name: str, attr: str) -> dict:  # TODO: change to __module__
    """Return a mapping of a (unique) attr of classes in a module to that class.

    For example:
      {DEV_TYPE.OTB: OtbGateway, DEV_TYPE.CTL: Controller}
      {ZON_ROLE.RAD: RadZone,    ZON_ROLE.UFH: UfhZone}
      {"evohome": Evohome}
    """

    return {
        getattr(c[1], attr): c[1]
        for c in getmembers(
            modules[name],
            lambda m: isclass(m) and m.__module__ == name and getattr(m, attr, None),
        )
    }


def discover_decorator(fnc):
    # NOTE: only need to Wrap top-level entities
    def wrapper(self, discover_flag=Discover.DEFAULT) -> None:

        if self._gwy.config.disable_discovery:
            return
        if not discover_flag:
            return
        return fnc(self, discover_flag=discover_flag)

    return wrapper


class MessageDB:
    """Maintain/utilize an entity's state database."""

    def __init__(self, gwy) -> None:
        self.db = sqlite3.connect("file::memory:?cache=shared")

        self._msgs = {}  # code, should be code/ctx? ?deprecate
        self._msgz = {}  # code/verb/ctx, should be code/ctx/verb?

    def _handle_msg(self, msg) -> None:  # TODO: beware, this is a mess
        """Store a msg in _msgs[code] (only latest I/RP) and _msgz[code][verb][ctx]."""

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
        """Return a flattened version of _msgz[code][verb][index].

        The idx is one of:
         - a simple index (e.g. zone_idx, domain_id)
         - a compund ctx (e.g. 0005/000C/0418)
         - True (an array of elements, each with its own idx),
         - False (no idx, is usu. 00),
         - None (not deteminable, rare)
        """
        return [m for c in self._msgz.values() for v in c.values() for m in v.values()]

    def _get_msg_by_hdr(self, hdr) -> Optional[Message]:
        """Return a msg, if any, that matches a header."""

        code, verb, _, *args = hdr.split("|")

        try:
            if args and (ctx := args[0]):
                msg = self._msgz[code][verb][ctx]
            elif False in self._msgz[code][verb]:
                msg = self._msgz[code][verb][False]
            elif None in self._msgz[code][verb]:
                msg = self._msgz[code][verb][None]
        except KeyError:
            return None

        if msg._pkt._hdr != hdr:
            raise LookupError

        return msg

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

    @staticmethod  # FIXME: messy (uses msg, others use code - move to Message?)
    def _msg_value_msg(msg, key=None, zone_idx=None, domain_id=None) -> Optional[dict]:

        if msg is None:
            return
        elif msg._expired:
            _delete_msg(msg)

        if msg.code == _1FC9:  # NOTE: list of lists/tuples
            return [x[1] for x in msg.payload]

        if domain_id:
            idx, val = SZ_DOMAIN_ID, domain_id
        elif zone_idx:
            idx, val = SZ_ZONE_IDX, zone_idx
        else:
            idx = val = None

        if isinstance(msg.payload, dict):
            msg_dict = msg.payload

        elif idx:
            msg_dict = {
                k: v for d in msg.payload for k, v in d.items() if d[idx] == val
            }
        else:
            # TODO: this isn't ideal: e.g. a controller is being treated like a 'stat
            #  I 101 --:------ --:------ 12:126457 2309 006 0107D0-0207D0  # is a CTL
            msg_dict = msg.payload[0]

        assert (
            not domain_id and not zone_idx or msg_dict.get(idx) == val
        ), f"{msg_dict} < Coding error: key={idx}, val={val}"

        if key:
            return msg_dict.get(key)
        return {
            k: v
            for k, v in msg_dict.items()
            if k not in ("dhw_idx", SZ_DOMAIN_ID, SZ_ZONE_IDX) and k[:1] != "_"
        }


class Entity(MessageDB):
    """The ultimate base class for Devices/Zones/Systems.

    This class is mainly concerned with:
     - if the entity can Rx packets (e.g. can the HGI send it an RQ)
    """

    _SLUG = None

    def __init__(self, gwy) -> None:
        super().__init__(gwy)

        self._gwy = gwy
        self.id = None

        self._qos_tx_count = 0  # the number of pkts Tx'd with no matching Rx

        if not self._gwy.config.disable_discovery and isinstance(
            self._gwy.pkt_protocol, PacketProtocolPort
        ):  # TODO: here, or in reap_xxx()?
            gwy._loop.call_soon_threadsafe(self._start_discovery)

    def __str__(self) -> str:
        return f"{self.id} ({self._SLUG})"

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

    def _start_discovery(self) -> None:
        pass

    def _discover(self, *, discover_flag=Discover.DEFAULT) -> None:
        pass

    def _handle_msg(self, msg) -> None:  # TODO: beware, this is a mess
        """Store a msg in _msgs[code] (only latest I/RP) and _msgz[code][verb][ctx]."""

        super()._handle_msg(msg)  # store the message in the database

        if (
            self._gwy.pkt_protocol is None
            or msg.src.id != self._gwy.pkt_protocol._hgi80.get(SZ_DEVICE_ID)
        ):
            self._qos_function(msg._pkt, reset=True)

    def _make_cmd(self, code, dest_id, payload="00", verb=RQ, **kwargs) -> None:
        self._send_cmd(self._gwy.create_cmd(verb, dest_id, code, payload, **kwargs))

    def _send_cmd(self, cmd, **kwargs) -> None:
        if self._gwy.config.disable_sending:
            _LOGGER.info(f"{cmd} < Sending is disabled")
            return

        if self._qos_tx_count > _QOS_TX_LIMIT:
            _LOGGER.info(f"{cmd} < Sending is deprecated for {self}")
            return

        cmd._source_entity = self
        # self._msgs.pop(cmd.code, None)  # NOTE: Cause of DHW bug
        self._gwy.send_cmd(cmd)  # BUG, should be: await async_send_cmd()

    @property
    def traits(self) -> dict:
        """Return the codes seen by the entity."""

        codes = {
            k: (CODES_SCHEMA[k][SZ_NAME] if k in CODES_SCHEMA else None)
            for k in sorted(self._msgs)
            if self._msgs[k].src is (self if hasattr(self, "addr") else self.ctl)
        }

        return {"_sent": list(codes.keys())}


def _delete_msg(msg) -> None:
    """Remove the msg from all state databases."""

    entities = [msg.src]
    if getattr(msg.src, "tcs", None):
        entities.append(msg.src.tcs)
        if msg.src.tcs.dhw:
            entities.append(msg.src.tcs.dhw)
        entities.extend(msg.src.tcs.zones)

    # remove the msg from all the state DBs
    for obj in entities:
        if msg in obj._msgs.values():
            del obj._msgs[msg.code]
        try:
            del obj._msgz[msg.code][msg.verb][msg._pkt._ctx]
        except KeyError:
            pass

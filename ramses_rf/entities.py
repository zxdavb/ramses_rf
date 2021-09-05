#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser."""

import logging
from typing import List

from .const import DISCOVER_ALL

from .protocol import I_, RP, RQ, W_, __dev_mode__  # noqa: F401, isort: skip

DEFAULT_BDR_ID = "13:000730"
DEFAULT_EXT_ID = "17:000730"
DEFAULT_THM_ID = "03:000730"

DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


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

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        pass

    def _handle_msg(self, msg) -> None:  # TODO: beware, this is a mess
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

        if msg.verb in (I_, RP):  # TODO: deprecate
            self._msgs[msg.code] = msg

    @property
    def _msg_db(self) -> List:  # a flattened version of _msgz[code][verb][indx]
        """Return a flattened version of _msgz[code][verb][indx]."""
        return [m for c in self._msgz.values() for v in c.values() for m in v.values()]

    # @property
    # def _pkt_db(self) -> Dict:
    #     """Return a flattened version of ..."""
    #     return {msg.dtm: msg._pkt for msg in self._msgs_db}

    def _send_cmd(self, code, dest_id, payload, verb=RQ, **kwargs) -> None:
        self._msgs.pop(code, None)  # TODO: remove old one, so we can tell if RP'd rcvd
        self._gwy.send_cmd(self._gwy.create_cmd(verb, dest_id, code, payload, **kwargs))
        # was: self._gwy.send_cmd(Command(verb, code, payload, dest_id, **kwargs))

    def _msg_value(
        self, code, verb=None, key=None, zone_idx=None, domain_id=None
    ) -> dict:

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
        ), f"{msg_dict} << Coding error: key={idx}, val={val}"

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

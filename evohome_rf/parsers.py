#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome RF - payload processors."""

from datetime import datetime as dt, timedelta as td
import logging
from typing import Optional, Union

from .const import (
    ATTR_DHW_VALVE_HTG,
    ATTR_DHW_VALVE,
    ATTR_HTG_CONTROL,
    CODE_SCHEMA,
    CODE_0005_ZONE_TYPE,
    CODE_000C_DEVICE_TYPE,
    CODE_0418_DEVICE_CLASS,
    CODE_0418_FAULT_STATE,
    CODE_0418_FAULT_TYPE,
    CODES_SANS_DOMAIN_ID,
    DOMAIN_TYPE_MAP,
    MAY_USE_DOMAIN_ID,
    MAY_USE_ZONE_IDX,
    SYSTEM_MODE_MAP,
    ZONE_MODE_MAP,
    _dev_mode_,
)
from .helpers import dev_hex_to_id, dtm_from_hex as _dtm, dts_from_hex
from .opentherm import OPENTHERM_MESSAGES, OPENTHERM_MSG_TYPE, ot_msg_value, parity
from .ramses import HINTS_CODE_SCHEMA as HINTS_CODES
from .schema import MAX_ZONES

DEV_MODE = _dev_mode_

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


def _idx_new(seqx, msg) -> dict:
    # TODO: To rationalise
    assert len(seqx) == 2, seqx

    if msg.code in CODES_SANS_DOMAIN_ID:  # don't idx, even though some != "00"
        return {}

    if seqx in ("F8", "F9", "FA", "FB", "FC", "FD", "FE"):
        return {
            "domain_id": seqx,
        }

    # finally:
    assert seqx == "00", seqx
    return {}


def _idx(seqx, msg) -> dict:
    """Check the index of a payload (usually a domain id or a zone idx).

    Determine if a payload has an entity id, and return: {"id_name": seqx} or {}.

    The challenge is that payloads starting with (e.g.):
    - "00" are *often not* a zone idx, and
    - "01", "02", etc. *may not* be a zone idx

    Anything in the range F0-FF appears to be a domain id (no false +ve/-ves).
    """
    if msg.code in CODES_SANS_DOMAIN_ID:  # don't idx, even though some != "00"
        # 1F09: "FF" (I), "00" (RP), "F8" (W, after 1FC9)
        # 1FC9: dict is currently encoded in a way that id/idx is not used
        # 2E04: payload[:2] is system mode, would fail final assert
        return {}

    # 045  I --- 03:183434 --:------ 03:183434 1060 003 00FF00
    if {"03", "12", "22"} & {msg.src.type} and msg.src.type == msg.devs[2].type:
        # CM92x can do heating (other_idx = 01) and optionally cooling (other_idx = 01)
        # msg.code in ("0008", "0009", "1030", "1060", "1100", "2309", "1030", "313F"):
        if msg.code not in ("1030", "2309"):
            assert seqx == "00"
            return {}
        assert int(seqx, 16) < msg._gwy.config[MAX_ZONES]
        return {
            "other_idx": seqx,
        }  # TODO: Should be parent_idx, but still a WIP

    elif msg.code in ("0002", "2D49"):  # non-evohome: hometronics
        return {
            "other_idx": seqx,
        }

    # TODO: 000C to a UFC should be ufh_ifx, not zone_idx
    elif msg.code == "000C":  # an exception to the usual rules
        if msg.verb == " I":
            return {}
        if msg.raw_payload[2:4] in ("0D", "0E"):  # ("000D", "000E", "010E")
            return {
                "domain_id": "FA",
            }
        if msg.raw_payload[2:4] == "0F":
            return {
                "domain_id": "FC",
            }
        if msg.src.type == "02":  # in (msg.src.type, msg.dst.type):  # TODO: above
            assert int(seqx, 16) < 8
            if msg.raw_payload[4:6] == "7F":
                return {
                    "ufh_idx": seqx,
                    "zone_id": None,
                }
            assert int(msg.raw_payload[4:6], 16) < msg._gwy.config[MAX_ZONES]
            return {
                "ufh_idx": seqx,
                "zone_id": msg.raw_payload[4:6],
            }
        if msg.dst.type == "02":
            assert int(seqx, 16) < 8
            return {
                "ufh_idx": seqx,
            }

        assert int(seqx, 16) < msg._gwy.config[MAX_ZONES]
        return {
            "zone_idx": seqx,
        }

    elif msg.code == "0016":  # WIP, not normally {"uses_zone_idx": True}
        if {"12", "22"} & {msg.src.type, msg.dst.type}:
            assert int(seqx, 16) < msg._gwy.config[MAX_ZONES]
            idx_name = (
                "zone_idx" if msg.src.type in ("01", "02", "18") else "parent_idx"
            )
            return {
                idx_name: seqx,
            }

    elif msg.code == "0418":  # does have domain_id/zone_idx, but uses log_idx
        assert int(seqx, 16) < 64  # a 'null' RP has no log_idx == 0
        return {}  # a 'null' RP has no log_idx

    elif msg.code == "10A0":  # can be 2 DHW zones per system
        assert seqx in ("00", "01")
        return {
            "dhw_idx": seqx,
        }

    elif msg.code == "22C9":  # these are UFH-specific
        assert int(seqx, 16) < 8  # this can be a "00", maybe zone_idx, see below
        return {
            "ufh_idx": seqx,
        }  # TODO: confirm is / is not zone_idx

    elif msg.code in ("31D9", "31DA"):  # ventilation
        assert seqx in ("00", "01", "21")
        return {
            "vent_id": seqx,
        }

    elif msg.code in MAY_USE_DOMAIN_ID and seqx in DOMAIN_TYPE_MAP:
        # no false +ve/-ves, although FF is not a true domain
        return {
            "domain_id": seqx,
        }

    elif msg.code in MAY_USE_ZONE_IDX:
        assert int(seqx, 16) < msg._gwy.config[MAX_ZONES]
        if {"01", "02", "23"} & {msg.src.type, msg.dst.type}:  # to/from a controller
            if msg.src.type == "02" and msg.src == msg.dst:
                idx_name = "ufh_idx"
            elif msg.src.type in ("01", "02", "23", "18"):
                idx_name = "zone_idx"
            else:
                idx_name = "parent_idx"
            return {
                idx_name: seqx,
            }

        # 055  I 028 03:094242 --:------ 03:094242 30C9 003 010B22
        elif msg.src.type == "03":  # TODO: WIP
            return {
                "parent_idx": seqx,
            }  # not zone_idx

    elif msg.code in ("????"):
        assert seqx == "FF"  # only a few "FF"
        return {}

    assert seqx == "00"
    return {}


def parser_decorator(func):
    """Decode the payload (or meta-data) of any message with useful information.

    Also includes some basic payload validation via ASSERTs (e.g payload length).
    """

    def wrapper(*args, **kwargs) -> Optional[dict]:
        """Check the length of a payload."""

        payload, msg = args[0], args[1]

        if msg.src.type in ("08", "31"):  # Honeywell Jasper HVAC
            return func(*args, **kwargs)

        if msg.verb == " W":  # TODO: WIP, need to check _idx()
            # these are OK to parse Ws:
            if msg.code in ("0001",):
                return {**_idx(payload[:2], msg), **func(*args, **kwargs)}
            # 045  W --- 12:010740 01:145038 --:------ 2309 003 0401F4
            if msg.code in ("2309", "2349") and msg.src.type in ("12", "22", "34"):
                assert int(payload[:2], 16) < msg._gwy.config[MAX_ZONES]
                return func(*args, **kwargs)
            # TODO: these are WIP
            if msg.code == "1F09":
                assert payload[:2] == "F8"
                return func(*args, **kwargs)
            if msg.code in ("1FC9",):
                return func(*args, **kwargs)
            # assert payload[:2] in ("00", "FC")  # ("1100", "2309", "2349")
            return func(*args, **kwargs)

        if msg.verb != "RQ":  # i.e. in (" I", "RP")
            result = func(*args, **kwargs)
            if isinstance(result, list):
                return result
            return {
                **_idx(payload[:2], msg),
                **result,
            }

        # except for 18:, these should return nothing - 000A is rq_len 1 or 3?
        # grep -E 'RQ.* 002 ' | grep -vE ' (0004|0016|3EF1) '
        # grep -E 'RQ.* 001 ' | grep -vE ' (000A|1F09|22D9|2309|313F|31DA|3EF0) '

        # # HACK: to keep logs clean - will need cleaning up eventually
        # if msg.src.type == "18" and msg.verb == "RQ":
        #     if msg.code in ("10A0", "12B0", "2349", "30C9"):
        #         assert msg.len <= 2
        #         return {**_idx(payload[:2], msg)}

        # some packets have more than just a domain_id
        if msg.code == "0006":
            assert msg.len == 1, msg.len
            return {
                **_idx(payload[:2], msg),
                **func(*args, **kwargs),
            }

        if msg.code == "000C":
            assert msg.len == 2, msg.len
            return {
                **_idx(payload[:2], msg),
                **func(*args, **kwargs),
            }

        if msg.code in ("0004", "0016", "12B0", "30C9"):
            assert msg.len == 2, msg.len  # 12B0, 30C9 will RP to 1
            return {
                **_idx(payload[:2], msg),
            }

        if msg.code == "2349":
            assert msg.len in (1, 2, 7), msg.len  # native evohome is 7
            return {
                **_idx(payload[:2], msg),
            }

        if msg.code in ("000A", "2309"):
            if msg.src.type in ("12", "22"):  # is rp_length
                assert msg.len == 6 if msg.code == "000A" else 3, msg.len
            else:
                assert msg.len in (1, 2), msg.len  # incl. 34:, rq_length
            return {
                **_idx(payload[:2], msg),
            }

        if msg.code == "0005":
            assert msg.len == 2, msg.len
            return func(*args, **kwargs)  # has no domain_id

        if msg.code == "0100":  # 04: will RQ language
            assert msg.len in (1, 5), msg.len  # len(RQ) = 5, but 00 accepted
            return func(*args, **kwargs)  # no context

        if msg.code == "0404":
            return {
                **_idx(payload[:2], msg),
                **func(*args, **kwargs),
            }

        if msg.code == "0418":
            assert msg.len == 3, msg.len
            assert payload[:4] == "0000", payload[:4]
            assert int(payload[4:6], 16) <= 63, payload[4:6]
            return {
                "log_idx": payload[4:6],
            }

        if msg.code == "10A0":
            # 045 RQ --- 07:045960 01:145038 --:------ 10A0 006 0013740003E4
            # 037 RQ --- 18:013393 01:145038 --:------ 10A0 001 00
            # 054 RP --- 01:145038 18:013393 --:------ 10A0 006 0013880003E8
            assert msg.len == 6 if msg.src.type == "07" else 1, msg.len
            return func(*args, **kwargs)

        if msg.code == "1100":
            assert payload[:2] in ("00", "FC"), payload[:2]
            if msg.len > 2:  # these RQs have payloads!
                return func(*args, **kwargs)
            return {
                **_idx(payload[:2], msg),
            }

        if msg.code in ("1260", "10E0", "1F41", "1FC9", "2E04"):  # TODO: Check these
            # These have only been seen when sent by 18:
            assert payload == "FF" if msg.code == "2E04" else "00"  # so: msg.len == 1
            return {}

        if msg.code in ("0008", "1F09", "22D9", "313F", "3B00", "3EF0"):
            # 061 RQ --- 04:189082 01:145038 --:------ 1F09 001 00
            # 067 RQ --- 01:187666 10:138822 --:------ 22D9 001 00
            # 045 RQ --- 04:056061 01:145038 --:------ 313F 001 00
            # 045 RQ --- 01:158182 13:209679 --:------ 3EF0 001 00
            # 065 RQ --- 01:078710 10:067219 --:------ 3EF0 001 00
            assert payload == "00", payload  # implies: msg.len == 1
            return {}

        if msg.code in ("31D9", "31DA"):  # ventilation
            # 047 RQ --- 32:168090 30:082155 --:------ 31DA 001 21
            assert msg.len == 1, msg.len
            return {
                **_idx(payload[:2], msg),
            }

        if msg.code == "3220":  # CTL -> OTB (OpenTherm)
            assert msg.len == 5, msg.len
            return func(*args, **kwargs)

        if msg.code == "3EF1":
            # 082 RQ --- 31:110943 13:068890 --:------ 3EF1 001 00
            # 082 RQ --- 22:091267 01:140959 --:------ 3EF1 002 0700
            # 088 RQ --- 22:054901 13:133379 --:------ 3EF1 002 0000
            if msg.len > 1:
                assert payload[2:] == "00", payload[2:]  # implies: msg.len >= 2
            return {
                **_idx(payload[:2], msg),
            }

        hint = (
            " (OK to ignore)"
            if "18" in (msg.src.type, msg.dst.type)
            else " - please report this as an issue"
        )
        assert msg.code in HINTS_CODES, f"Code not known{hint}"
        assert False, f"Code {msg.code} not known to support an RQ{hint}"

    return wrapper


def _bool(value: str) -> Optional[bool]:  # either 00 or C8
    """Return a boolean."""
    assert value in ("00", "C8", "FF"), value
    return {"00": False, "C8": True}.get(value)


def _date(value: str) -> Optional[str]:  # YY-MM-DD
    """Return a date string in the format YY-MM-DD."""
    assert len(value) == 8, value
    if value == "FFFFFFFF":
        return
    return dt(
        year=int(value[4:8], 16),
        month=int(value[2:4], 16),
        day=int(value[:2], 16) & 0b11111,  # 1st 3 bits: DayOfWeek
    ).strftime("%Y-%m-%d")


def _percent(value: str) -> Optional[float]:  # a percentage 0-100% (0.0 to 1.0)
    """Return a percentage, 0-100% with resolution of 0.5%."""
    assert len(value) == 2, value
    if value in ("FE", "FF"):  # TODO: diff b/w FE (seen with 3150) & FF
        return
    assert int(value, 16) <= 200
    return int(value, 16) / 200


def _str(value: str) -> Optional[str]:  # printable ASCII characters
    """Return a string of printable ASCII characters."""
    _string = bytearray([x for x in bytearray.fromhex(value) if 31 < x < 127])
    return _string.decode("ascii").strip() if _string else None


def _temp(value: str) -> Union[float, bool, None]:
    """Return a two's complement Temperature/Setpoint."""
    assert len(value) == 4, value
    if value == "31FF":  # means: N/A (== 127.99, 2s complement)
        return
    if value == "7EFF":  # possibly only for setpoints?
        return False
    if value == "7FFF":  # also: FFFF?, means: N/A (== 327.67)
        return
    temp = int(value, 16)
    return (temp if temp < 2 ** 15 else temp - 2 ** 16) / 100


@parser_decorator  # rf_unknown
def parser_0001(payload, msg) -> Optional[dict]:
    # When in test mode, a 12: will send a W every 6 seconds, *on?* the second:
    # 12:39:56.099 061  W --- 12:010740 --:------ 12:010740 0001 005 0000000501
    # 12:40:02.098 061  W --- 12:010740 --:------ 12:010740 0001 005 0000000501
    # 12:40:08.099 058  W --- 12:010740 --:------ 12:010740 0001 005 0000000501

    # sent by a THM every 5s when is signal strength test mode (0505, except 1st pkt)
    # 13:48:38.518 080  W --- 12:010740 --:------ 12:010740 0001 005 0000000501
    # 13:48:45.518 074  W --- 12:010740 --:------ 12:010740 0001 005 0000000505
    # 13:48:50.518 077  W --- 12:010740 --:------ 12:010740 0001 005 0000000505

    # sent by a CTL before a rf_check
    # 15:12:47.769 053  W --- 01:145038 --:------ 01:145038 0001 005 FC00000505
    # 15:12:47.869 053 RQ --- 01:145038 13:237335 --:------ 0016 002 00FF
    # 15:12:47.880 053 RP --- 13:237335 01:145038 --:------ 0016 002 0017

    # 12:30:18.083 047  W --- 01:145038 --:------ 01:145038 0001 005 0800000505
    # 12:30:23.084 049  W --- 01:145038 --:------ 01:145038 0001 005 0800000505

    # 15:03:33.187 054  W --- 01:145038 --:------ 01:145038 0001 005 FC00000505
    # 15:03:38.188 063  W --- 01:145038 --:------ 01:145038 0001 005 FC00000505
    # 15:03:43.188 064  W --- 01:145038 --:------ 01:145038 0001 005 FC00000505
    # 15:13:19.757 053  W --- 01:145038 --:------ 01:145038 0001 005 FF00000505
    # 15:13:24.758 054  W --- 01:145038 --:------ 01:145038 0001 005 FF00000505
    # 15:13:29.758 068  W --- 01:145038 --:------ 01:145038 0001 005 FF00000505
    # 15:13:34.759 063  W --- 01:145038 --:------ 01:145038 0001 005 FF00000505

    # loopback (not Tx'd) by a HGI80 whenever its button is pressed
    # 00:22:41.540 ---  I --- --:------ --:------ --:------ 0001 005 00FFFF02FF
    # 00:22:41.757 ---  I --- --:------ --:------ --:------ 0001 005 00FFFF0200
    # 00:22:43.320 ---  I --- --:------ --:------ --:------ 0001 005 00FFFF02FF
    # 00:22:43.415 ---  I --- --:------ --:------ --:------ 0001 005 00FFFF0200

    # From a CM927:
    # W/--:/--:/12:/00-0000-0501 = Test transmit
    # W/--:/--:/12:/00-0000-0505 = Field strength

    assert msg.verb in (" I", " W"), msg.verb
    assert msg.len == 5, msg.len
    assert payload[:2] in ("FC", "FF") or (
        int(payload[:2], 16) < msg._gwy.config[MAX_ZONES]
    ), payload[:2]
    assert payload[2:6] in ("0000", "FFFF"), payload[2:6]
    assert payload[6:8] in ("02", "05"), payload[6:8]
    return {
        **_idx(payload[:2], msg),  # not fully understood
        "unknown_0": payload[2:6],
        "unknown_1": payload[6:8],
        "unknown_2": payload[8:],
    }


@parser_decorator  # sensor_weather
def parser_0002(payload, msg) -> Optional[dict]:
    # I --- 03:125829 --:------ 03:125829 0002 004 03020105  # seems to be faked

    assert msg.len == 4

    return {
        **_idx(payload[:2], msg),
        "temperature": _temp(payload[2:6]),
        "_light_level": payload[6:],  # light level
    }


@parser_decorator  # zone_name
def parser_0004(payload, msg) -> Optional[dict]:
    # RQ payload is zz00; limited to 12 chars in evohome UI? if "7F"*20: not a zone

    assert msg.len == 22, msg.len
    assert payload[2:4] == "00", payload[2:4]

    if payload[4:] == "7F" * 20:
        return {**_idx(payload[:2], msg)}

    return {
        **_idx(payload[:2], msg),
        "name": _str(payload[4:]),
    }


@parser_decorator  # system_zone (add/del a zone?)
def parser_0005(payload, msg) -> Optional[dict]:
    # 047  I --- 34:064023 --:------ 34:064023 0005 012 000A0000 000F0000 00100000
    # 045  I --- 01:145038 --:------ 01:145038 0005 004 00000100

    # RQ payload is xx00, controller wont respond to a xx
    def _parser(seqx) -> dict:
        def get_flag8(byte, *args) -> list:
            """Split a byte (as a str) into a list of 8 bits (1/0)."""
            ret = [0] * 8
            byte = bytes.fromhex(byte)[0]
            for i in range(0, 8):
                ret[i] = byte & 1
                byte = byte >> 1
            return ret

        assert len(seqx) == 8
        assert seqx[:2] == payload[:2]
        assert seqx[:2] == "00"  # done in _idx
        # assert payload[2:4] in CODE_0005_ZONE_TYPE, f"Unknown zone_type: {seqx[2:4]}"

        max_zones = msg._gwy.config[MAX_ZONES]
        return {
            "zone_mask": (get_flag8(seqx[4:6]) + get_flag8(seqx[6:8]))[:max_zones],
            "zone_type": CODE_0005_ZONE_TYPE.get(seqx[2:4], seqx[2:4]),
        }

    if msg.verb == "RQ":
        assert payload[:2] == "00", payload[:2]
        return {
            "zone_type": CODE_0005_ZONE_TYPE.get(payload[2:4], payload[2:4]),
        }

    assert msg.verb in (" I", "RP")
    if msg.src.type == "34":
        assert msg.len == 12, msg.len  # or % 4?
        return [_parser(payload[i : i + 8]) for i in range(0, len(payload), 8)]

    assert msg.src.type in ("01", "02")  # and "23"?
    return _parser(payload)


@parser_decorator  # schedule_sync (any changes?)
def parser_0006(payload, msg) -> Optional[dict]:
    """Return the total number of changes to the schedules, including the DHW schedule.

    An RQ is sent every ~60s by a RFG100, an increase will prompt it to send a run of
    RQ/0404s (it seems to assume only the zones may have changed?).
    """
    # 16:10:34.288 053 RQ --- 30:071715 01:145038 --:------ 0006 001 00
    # 16:10:34.291 053 RP --- 01:145038 30:071715 --:------ 0006 004 00050008

    if msg.verb == "RQ":
        assert payload == "00"  # implies msg.len == 1 byte
        return {}

    assert msg.verb == "RP"
    assert msg.len == 4  # should bs: 0005-nnnn
    assert payload[:2] == "00"  # otherwise: payload[2:] == "FFFFFF", invalid

    if payload[2:] == "FFFFFF":  # RP to an invalid RQ
        return {}

    assert payload[2:4] == "05"

    return {
        "change_counter": int(payload[4:], 16),
        "_header": payload[:4],
    }


@parser_decorator  # relay_demand (domain/zone/device)
def parser_0008(payload, msg) -> Optional[dict]:
    # https://www.domoticaforum.eu/viewtopic.php?f=7&t=5806&start=105#p73681
    # e.g. Electric Heat Zone

    if msg.src.type == "31":  # Honeywell Japser ?HVAC
        assert msg.len == 13, msg.len
        return {
            "ordinal": f"0x{payload[2:8]}",
            "blob": payload[8:],
        }

    assert msg.len == 2, msg.len

    if payload[:2] not in ("F9", "FA", "FC"):
        assert int(payload[:2], 16) < msg._gwy.config[MAX_ZONES], payload[:2]

    return {
        **_idx(payload[:2], msg),
        "relay_demand": _percent(payload[2:4]),
    }


@parser_decorator  # relay_failsafe
def parser_0009(payload, msg) -> Union[dict, list]:
    """The relay failsafe mode.

    The failsafe mode defines the relay behaviour if the RF communication is lost (e.g.
    when a room thermostat stops communicating due to discharged batteries):
        enabled  - if RF communication is lost, relay will be held in OFF position
        disabled - if RF communication is lost, relay will cycle at 20% ON, 80% OFF

    This setting may need to be enabled to ensure prost protect mode.
    """
    # TODO: can only be max one relay per domain/zone
    # can get: 003 or 006, e.g.: FC01FF-F901FF or FC00FF-F900FF
    # 095  I --- 23:100224 --:------ 23:100224 0009 003 0100FF  # 2-zone ST9520C

    def _parser(seqx) -> dict:
        assert (
            seqx[:2] in ("F9", "FC") or int(seqx[:2], 16) < msg._gwy.config[MAX_ZONES]
        )
        assert seqx[2:4] in ("00", "01"), seqx[2:4]
        assert seqx[4:] in ("00", "FF"), seqx[4:]

        return {
            **_idx(seqx[:2], msg),
            "failsafe_enabled": {"00": False, "01": True}.get(seqx[2:4]),
        }

    if msg.is_array:
        assert msg.len >= 3 and msg.len % 3 == 0, msg.len  # assuming not RQ
        return [_parser(payload[i : i + 6]) for i in range(0, len(payload), 6)]

    assert msg.len == 3, msg.len
    return _parser(payload)


@parser_decorator  # zone_config (zone/s)
def parser_000a(payload, msg) -> Union[dict, list, None]:
    # 11:21:10.674 063 RQ --- 34:044203 01:158182 --:------ 000A 001 08
    # 11:21:10.736 045 RP --- 01:158182 34:044203 --:------ 000A 006 081001F409C4
    # following for 12: too:
    # 13:13:08.273 045 RQ --- 22:017139 01:140959 --:------ 000A 006 080001F40DAC
    # 13:13:08.288 045 RP --- 01:140959 22:017139 --:------ 000A 006 081001F40DAC

    def _parser(seqx) -> dict:
        # if seqx[2:] == "007FFF7FFF":  # (e.g. RP) a null zone

        bitmap = int(seqx[2:4], 16)
        return {
            **_idx(seqx[:2], msg),
            "min_temp": _temp(seqx[4:8]),
            "max_temp": _temp(seqx[8:]),
            "local_override": not bool(bitmap & 1),
            "openwindow_function": not bool(bitmap & 2),
            "multiroom_mode": not bool(bitmap & 16),
            "_unknown_bitmap": f"0b{bitmap:08b}",
        }  # cannot determine zone_type from this information

    if msg.is_array:  # TODO: these msgs can require 2 pkts!
        assert msg.len >= 6 and msg.len % 6 == 0  # assuming not RQ
        return [_parser(payload[i : i + 12]) for i in range(0, len(payload), 12)]

    assert msg.len == 6
    return _parser(payload)


@parser_decorator  # zone_actuators (not sensors)
def parser_000c(payload, msg) -> Optional[dict]:
    # 045  I --- 34:092243 --:------ 34:092243 000C 018 000A7FFFFFFF 000F7FFFFFFF 00107FFFFFFF  # noqa: E501
    # 045 RP --- 01:145038 18:013393 --:------ 000C 006 00000010DAFD
    # 045 RP --- 01:145038 18:013393 --:------ 000C 012 01000010DAF5 01000010DAFB

    # RQ payload is zz00, NOTE: aggregation of parsing taken here
    def _parser(seqx) -> dict:
        assert len(seqx) == 12
        assert seqx[:2] == payload[:2]
        # assert seqx[2:4] in CODE_000C_DEVICE_TYPE, f"Unknown device_type: {seqx[2:4]}"
        assert seqx[4:6] == "7F" or int(seqx[4:6], 16) < msg._gwy.config[MAX_ZONES]

        return {dev_hex_to_id(seqx[6:12]): seqx[4:6]}

    if msg.verb == "RQ":
        assert msg.len == 2, msg.len
    else:
        assert msg.len >= 6 and msg.len % 6 == 0, msg.len  # assuming not RQ

    device_class = CODE_000C_DEVICE_TYPE.get(payload[2:4], f"unkown_{payload[2:4]}")
    if device_class == ATTR_DHW_VALVE and msg.raw_payload[:2] == "01":
        device_class = ATTR_DHW_VALVE_HTG

    if msg.verb == "RQ":
        return {**_idx(payload[:2], msg), "device_class": device_class}

    devices = [_parser(payload[i : i + 12]) for i in range(0, len(payload), 12)]

    return {
        # **_idx(payload[:2], msg),
        "device_class": device_class,
        "devices": [k for d in devices for k, v in d.items() if v != "7F"],
    }  # TODO: the assumption that all domain_id/zones_idx are the same is wrong


@parser_decorator  # unknown, from STA
def parser_000e(payload, msg) -> Optional[dict]:
    assert payload == "000014"  # rarely, from STA:xxxxxx
    return {
        "unknown_0": payload,
    }


@parser_decorator  # rf_check
def parser_0016(payload, msg) -> Optional[dict]:
    # TODO: does 0016 include parent_idx
    # 09:05:33.178 046 RQ --- 22:060293 01:078710 --:------ 0016 002 0200
    # 09:05:33.194 064 RP --- 01:078710 22:060293 --:------ 0016 002 021E
    # 12:47:25.080 048 RQ --- 12:010740 01:145038 --:------ 0016 002 0800
    # 12:47:25.094 045 RP --- 01:145038 12:010740 --:------ 0016 002 081E

    assert msg.verb in ("RQ", "RP"), msg.verb
    assert msg.len == 2, msg.len  # for both RQ/RP, but RQ/00 will work
    # assert payload[:2] == "00"  # e.g. RQ/22:/0z00 (parent_zone), but RQ/07:/0000?

    if msg.verb == "RQ":
        return {}  # {"rf_request": msg.dst.id}

    rf_value = int(payload[2:4], 16)
    return {
        #  "rf_source": msg.dst.id,
        "rf_strength": min(int(rf_value / 5) + 1, 5),
        "rf_value": rf_value,
    }


@parser_decorator  # language (of device/system)
def parser_0100(payload, msg) -> Optional[dict]:
    if msg.verb == "RQ" and payload == "00":  # HACK: should be "00ssssFFFF"
        return {}

    assert msg.len == 5, msg.len
    assert payload[:2] == "00", payload[:2]
    assert payload[6:] == "FFFF", payload[6:]
    return {
        "language": _str(payload[2:6]),
        "_unknown_0": payload[6:],
    }


@parser_decorator  # unknown, from a HR91 (when its buttons are pushed)
def parser_01d0(payload, msg) -> Optional[dict]:
    # 23:57:28.869 045  W --- 04:000722 01:158182 --:------ 01D0 002 0003
    # 23:57:28.931 045  I --- 01:158182 04:000722 --:------ 01D0 002 0003
    # 23:57:31.581 048  W --- 04:000722 01:158182 --:------ 01E9 002 0003
    # 23:57:31.643 045  I --- 01:158182 04:000722 --:------ 01E9 002 0000
    # 23:57:31.749 050  W --- 04:000722 01:158182 --:------ 01D0 002 0000
    # 23:57:31.811 045  I --- 01:158182 04:000722 --:------ 01D0 002 0000
    assert msg.len == 2, msg.len
    assert payload[2:] in ("00", "03"), payload[2:]
    return {
        "unknown_0": payload[2:],
    }


@parser_decorator  # unknown, from a HR91 (when its buttons are pushed)
def parser_01e9(payload, msg) -> Optional[dict]:
    # 23:57:31.581348 048  W --- 04:000722 01:158182 --:------ 01E9 002 0003
    # 23:57:31.643188 045  I --- 01:158182 04:000722 --:------ 01E9 002 0000
    assert msg.len == 2, msg.len
    assert payload[2:] in ("00", "03"), payload[2:]
    return {
        "unknown_0": payload[2:],
    }


@parser_decorator  # zone_schedule (fragment)
def parser_0404(payload, msg) -> Optional[dict]:
    # Retreival of Zone schedule
    # 18:02:53.700 057 RQ --- 30:185469 01:037519 --:------ 0404 007 00200008000100
    # 18:02:53.764 052 RP --- 01:037519 30:185469 --:------ 0404 048 002000082901036...
    # 18:02:55.606 054 RQ --- 30:185469 01:037519 --:------ 0404 007 00200008000203
    # 18:02:55.652 053 RP --- 01:037519 30:185469 --:------ 0404 048 002000082902034D...
    # 18:02:57.300 054 RQ --- 30:185469 01:037519 --:------ 0404 007 00200008000303
    # 18:02:57.338 052 RP --- 01:037519 30:185469 --:------ 0404 038 002000081F0303C1...

    # Retreival of DHW schedule
    # 18:04:26.097 055 RQ --- 30:185469 01:037519 --:------ 0404 007 00230008000100
    # 18:04:26.170 049 RP --- 01:037519 30:185469 --:------ 0404 048 0023000829010368...
    # 18:04:30.097 054 RQ --- 30:185469 01:037519 --:------ 0404 007 00230008000203
    # 18:04:30.144 047 RP --- 01:037519 30:185469 --:------ 0404 048 00230008290203ED...
    # 18:04:34.997 056 RQ --- 30:185469 01:037519 --:------ 0404 007 00230008000303
    # 18:04:35.019 047 RP --- 01:037519 30:185469 --:------ 0404 014 002300080703031F...

    def _header(seqx) -> dict:
        assert seqx[2:4] in ("20", "23"), seqx[2:4]  # Zones, DHW
        assert seqx[4:8] == "0008", seqx[4:8]

        return {
            # **_idx(payload[:2], msg),  # added by wrapper
            "frag_index": int(seqx[10:12], 16),
            "frag_total": int(seqx[12:], 16),
            "frag_length": int(seqx[8:10], 16),
        }

    if msg.verb == "RQ":
        assert msg.len == 7, msg.len
        return _header(payload[:14])

    assert msg.verb in ("RP", " I", " W"), msg.verb
    return {
        **_header(payload[:14]),
        "fragment": payload[14:],
    }


@parser_decorator  # system_fault
def parser_0418(payload, msg) -> Optional[dict]:
    """In testing: 10 * 6 log entries in the UI, but 63 via RQs."""

    # 045 RP --- 01:145038 18:013393 --:------ 0418 022 000000B00401010000008694A3CC7FFFFF70000ECC8A  # noqa
    # 045 RP --- 01:145038 18:013393 --:------ 0418 022 00C001B004010100000086949BCB7FFFFF70000ECC8A  # noqa
    # 045 RP --- 01:145038 18:013393 --:------ 0418 022 000000B0000000000000000000007FFFFF7000000000  # noqa
    # 000 RP --- 01:037519 18:140805 --:------ 0418 022 004024B0060006000000CB94A112FFFFFF70007AD47D  # noqa

    if payload[2:] == CODE_SCHEMA["0418"]["null_rp"][2:]:
        # a null log entry, or: is payload[38:] == "000000" sufficient?
        return {}
    #
    assert msg.verb in (" I", "RP"), msg.verb
    assert msg.len == 22, msg.len
    assert payload[:2] == "00", payload[:2]  # likely always 00
    assert payload[2:4] in CODE_0418_FAULT_STATE, payload[2:4]  # C0 don't appear in UI?
    assert int(payload[4:6], 16) <= 63, payload[4:6]  # TODO: upper limit is: 60? 63?
    assert payload[8:10] in CODE_0418_FAULT_TYPE, payload[8:10]

    assert int(payload[10:12], 16) < msg._gwy.config[MAX_ZONES] or (
        payload[10:12] in ("F9", "FA", "FC")  # "1C"?
    ), payload[10:12]
    assert payload[12:14] in CODE_0418_DEVICE_CLASS, payload[12:14]
    assert payload[28:30] in ("7F", "FF"), payload[28:30]

    result = {
        "log_idx": payload[4:6],
        "timestamp": dts_from_hex(payload[18:30]),
        "fault_state": CODE_0418_FAULT_STATE.get(payload[2:4], payload[2:4]),
        "fault_type": CODE_0418_FAULT_TYPE.get(payload[8:10], payload[8:10]),
        "device_class": CODE_0418_DEVICE_CLASS.get(payload[12:14], payload[12:14]),
    }  # TODO: stop using __idx()?

    if payload[10:12] == "FC" and result["device_class"] == "actuator":
        result["device_class"] = ATTR_HTG_CONTROL  # aka Boiler relay

    if payload[12:14] != "00":  # Controller
        key_name = (
            "zone_id"
            if int(payload[10:12], 16) < msg._gwy.config[MAX_ZONES]
            else "domain_id"
        )  # TODO: don't use zone_idx (for now)
        result.update({key_name: payload[10:12]})

    if payload[38:] == "000002":  # "00:000002 for Unknown?
        result.update({"device_id": None})
    elif payload[38:] not in ("000000", "000001"):  # "00:000001 for Controller?
        result.update({"device_id": dev_hex_to_id(payload[38:])})

    assert payload[6:8] == "B0", payload[6:8]  # unknown_1, ?priority
    assert payload[14:18] == "0000", payload[14:18]  # unknown_2
    assert payload[30:38] == "FFFF7000", payload[30:38]  # unknown_3
    result.update(
        {
            "_unknown_1": payload[6:8],
            "_unknown_2": payload[14:18],
            "_unknown_3": payload[30:38],
        }
    )

    # return {
    #     "log_idx": result["log_idx"],
    #     "log_entry": [v for k, v in result.items() if k != "log_idx"],
    # }
    return result


@parser_decorator  # unknown, from STA
def parser_042f(payload, msg) -> Optional[dict]:
    # 055  I --- 34:064023 --:------ 34:064023 042F 008 00000000230023F5
    # 063  I --- 34:064023 --:------ 34:064023 042F 008 00000000240024F5
    # 049  I --- 34:064023 --:------ 34:064023 042F 008 00000000250025F5
    # 045  I --- 34:064023 --:------ 34:064023 042F 008 00000000260026F5
    # 045  I --- 34:092243 --:------ 34:092243 042F 008 0000010021002201
    # 000  I     34:011469 --:------ 34:011469 042F 008 00000100030004BC

    assert msg.len in (8, 9), msg.len  # non-evohome are 9
    assert payload[:2] == "00", payload[:2]

    return {
        "counter_1": int(payload[2:6], 16),
        "counter_2": int(payload[6:10], 16),
        "counter_total": int(payload[10:14], 16),
        "unknown_0": payload[14:],
    }


@parser_decorator  # unknown, from THM
def parser_0b04(payload, msg) -> Optional[dict]:
    # 12:04:57.244 063  I --- --:------ --:------ 12:207082 0B04 002 00C8
    # 12:04:58.235 063  I --- --:------ --:------ 12:207082 0B04 002 00C8
    # 12:04:58.252 064  I --- --:------ --:------ 12:207082 0B04 002 00C8
    # above every 24h

    assert msg.len == 2, msg.len
    assert payload[:2] == "00", payload[:2]
    assert payload[2:] == "C8", payload[2:]

    return {
        "_unknown_0": payload[2:],
    }


@parser_decorator  # mixvalve_config (zone)
def parser_1030(payload, msg) -> Optional[dict]:
    def _parser(seqx) -> dict:
        assert seqx[2:4] == "01", seqx[2:4]

        param_name = {
            "C8": "max_flow_setpoint",  # 55 (0-99) C
            "C9": "min_flow_setpoint",  # 15 (0-50) C
            "CA": "valve_run_time",  # 150 (0-240) sec, aka actuator_run_time
            "CB": "pump_run_time",  # 15 (0-99) sec
            "CC": "_unknown_0",  # ?boolean?
        }[seqx[:2]]

        return {param_name: int(seqx[4:], 16)}

    assert msg.len == 1 + 5 * 3, msg.len
    assert payload[30:] in ("00", "01"), payload[30:]

    params = [_parser(payload[i : i + 6]) for i in range(2, len(payload), 6)]
    return {
        **_idx(payload[:2], msg),
        **{k: v for x in params for k, v in x.items()},
    }


@parser_decorator  # device_battery (battery_state)
def parser_1060(payload, msg) -> Optional[dict]:
    """Return the battery state.

    Some devices (04:) will also report battery level.
    """
    # 06:48:23.948 049  I --- 12:010740 --:------ 12:010740 1060 003 00FF01
    # 16:18:43.515 051  I --- 12:010740 --:------ 12:010740 1060 003 00FF00
    # 16:14:44.180 054  I --- 04:056057 --:------ 04:056057 1060 003 002800
    # 17:34:35.460 087  I --- 04:189076 --:------ 01:145038 1060 003 026401

    assert msg.len == 3, msg.len
    assert payload[4:6] in ("00", "01")

    return {
        "battery_low": payload[4:] == "00",
        "battery_level": _percent(payload[2:4]),
    }


@parser_decorator  # unknown (non-Evohome, e.g. ST9520C)
def parser_1090(payload, msg) -> dict:
    # 14:08:05.176 095 RP --- 23:100224 22:219457 --:------ 1090 005 007FFF01F4
    # 18:08:05.809 095 RP --- 23:100224 22:219457 --:------ 1090 005 007FFF01F4

    # this is an educated guess
    assert msg.len == 5, msg.len
    assert int(payload[:2], 16) < 2, payload[:2]

    return {
        **_idx(payload[:2], msg),
        "temp_0": _temp(payload[2:6]),
        "temp_1": _temp(payload[6:10]),
    }


@parser_decorator  # dhw_params
def parser_10a0(payload, msg) -> Optional[dict]:
    """Return the DHW parameters.

    DHW sends a RQ (not an I) with payload!
    """
    # RQ --- 01:136410 10:067219 --:------ 10A0 002 0000
    # RQ --- 07:017494 01:078710 --:------ 10A0 006 00-1566-00-03E4

    # RQ --- 07:045960 01:145038 --:------ 10A0 006 00-31FF-00-31FF (null)
    # RQ --- 07:045960 01:145038 --:------ 10A0 006 00-1770-00-03E8
    # RQ --- 07:045960 01:145038 --:------ 10A0 006 00-1374-00-03E4
    # RQ --- 07:030741 01:102458 --:------ 10A0 006 00-181F-00-03E4
    # RQ --- 07:036831 23:100224 --:------ 10A0 006 01-1566-00-03E4 (non-evohome)

    # RQ --- 30:185469 01:037519 --:------ 0005 002 000E
    # RP --- 01:037519 30:185469 --:------ 0005 004 000E0300  # two DHW valves
    # RQ --- 30:185469 01:037519 --:------ 10A0 001 01 (01 )

    assert msg.len in (1, 3, 6), msg.len  # OTB uses 3, evohome uses 6
    assert payload[:2] in ("00", "01"), payload[:2]  # can be two DHW valves/system

    result = {}
    if msg.len >= 2:
        setpoint = _temp(payload[2:6])  # 255 for OTB? iff no DHW?
        result = {"setpoint": None if setpoint == 255 else setpoint}  # 30.0-85.0 C
    if msg.len >= 4:
        result["overrun"] = int(payload[6:8], 16)  # 0-10 minutes
    if msg.len >= 6:
        result["differential"] = _temp(payload[8:12])  # 1.0-10.0 C

    return result


@parser_decorator  # device_info
def parser_10e0(payload, msg) -> Optional[dict]:
    assert msg.len in (30, 36, 38), msg.len  # a non-evohome seen with 30

    date = _date(payload[20:28])  # could be 'FFFFFFFF'

    return {  # TODO: add version?
        "_unknown": payload[:20],
        "date_1": _date(payload[28:36]),
        "date_2": date if date else '0000-00-00',
        "description": _str(payload[36:]),
    }


@parser_decorator  # tpi_params (domain/zone/device)
def parser_1100(payload, msg) -> Optional[dict]:

    if msg.src.type == "08":  # Honeywell Japser ?HVAC
        assert msg.len == 19, msg.len
        return {
            "ordinal": f"0x{payload[2:8]}",
            "blob": payload[8:],
        }

    assert msg.len in (5, 8), msg.len
    assert payload[:2] in ("00", "FC"), payload[:2]
    # 2020-09-23T19:25:04.767331 047  I --- 13:079800 --:------ 13:079800 1100 008 00170498007FFF01  # noqa
    assert int(payload[2:4], 16) / 4 in range(1, 13), payload[2:4]
    assert int(payload[4:6], 16) / 4 in range(1, 31), payload[4:6]
    assert int(payload[6:8], 16) / 4 in range(0, 16), payload[6:8]
    assert payload[8:10] in ("00", "FF"), payload[8:10]

    # for TPI
    #  - cycle_rate: 6, (3, 6, 9, 12)
    #  - min_on_time: 1 (1-5)
    #  - min_off_time: 1 (1-?)
    # for heatpump
    #  - cycle_rate: 1-9
    #  - min_on_time: 1, 5, 10,...30
    #  - min_off_time: 0, 5, 10, 15

    def _parser(seqx) -> dict:
        return {
            **_idx(seqx[:2], msg),
            "cycle_rate": int(payload[2:4], 16) / 4,  # cycles/hour
            "min_on_time": int(payload[4:6], 16) / 4,  # min
            "min_off_time": int(payload[6:8], 16) / 4,  # min
            "_unknown_0": payload[8:10],  # always 00, FF?
        }

    if msg.len == 5:
        return _parser(payload)

    assert payload[14:] == "01", payload[14:]
    return {
        **_parser(payload[:10]),
        "proportional_band_width": _temp(payload[10:14]),  # 1.5 (1.5-3.0) C
        "_unknown_1": payload[14:],  # always 01?
    }


@parser_decorator  # dhw_temp
def parser_1260(payload, msg) -> Optional[dict]:
    assert msg.len == 3, msg.len
    assert payload[:2] == "00", payload[:2]  # all DHW pkts have no domain

    return {
        "temperature": _temp(payload[2:]),
    }


@parser_decorator  # outdoor_temp
def parser_1290(payload, msg) -> Optional[dict]:
    # evohome responds to an RQ
    assert msg.len == 3, msg.len
    assert payload[:2] == "00", payload[:2]  # no domain

    return {
        "temperature": _temp(payload[2:]),
    }


@parser_decorator  # indoor_humidity (Nuaire RH sensor)
def parser_12a0(payload, msg) -> Optional[dict]:
    assert msg.len == 6, msg.len
    assert payload[:2] == "00", payload[:2]  # domain?

    return {
        "relative_humidity": int(payload[2:4], 16) / 100,  # is not /200
        "temperature": _temp(payload[4:8]),
        "dewpoint_temp": _temp(payload[8:12]),
    }


@parser_decorator  # window_state (of a device/zone)
def parser_12b0(payload, msg) -> Optional[dict]:
    assert payload[2:] in ("0000", "C800", "FFFF"), payload[2:]  # "FFFF" means N/A
    # assert msg.len == 3, msg.len  # implied

    # TODO: zone.open_window = any(TRV.open_windows)?
    return {
        **_idx(payload[:2], msg),
        "window_open": _bool(payload[2:4]),
    }


# 2020-09-20T14:24:32.072645 085  I --- 34:225071 --:------ 34:225071 12C0 003 002D01
# 2020-09-20T14:24:32.136582 091  I --- 34:225071 --:------ 34:225071 12C0 003 002D01
# 2020-09-20T14:24:32.216496 093  I --- 34:225071 --:------ 34:225071 12C0 003 002D01


@parser_decorator  # system_sync
def parser_1f09(payload, msg) -> Optional[dict]:
    # TODO: Try RQ/1F09/"F8-FF" (CTL will RP to a RQ/00)
    assert msg.len == 3, msg.len
    assert payload[:2] in ("00", "F8", "FF")  # W uses F8, non-Honeywell devices use 00

    seconds = int(payload[2:6], 16) / 10
    next_sync = msg.dtm + td(seconds=seconds)

    return {
        "remaining_seconds": seconds,
        "_next_sync": dt.strftime(next_sync, "%H:%M:%S"),
    }


@parser_decorator  # dhw_mode
def parser_1f41(payload, msg) -> Optional[dict]:
    assert msg.len in (6, 12), msg.len
    assert payload[:2] == "00", payload[:2]  # all DHW pkts have no domain

    # 053 RP --- 01:145038 18:013393 --:------ 1F41 006 00FF00FFFFFF  # no stored DHW
    assert payload[2:4] in ("00", "01", "FF"), payload[2:4]
    assert payload[4:6] in ZONE_MODE_MAP, payload[4:6]
    if payload[4:6] == "04":
        assert msg.len == 12, msg.len
        assert payload[6:12] == "FFFFFF", payload[6:12]

    return {
        "active": {"00": False, "01": True, "FF": None}[payload[2:4]],
        "dhw_mode": ZONE_MODE_MAP.get(payload[4:6]),
        "until": _dtm(payload[12:24]) if payload[4:6] == "04" else None,
    }


@parser_decorator  # rf_bind
def parser_1fc9(payload, msg) -> Optional[dict]:
    # 17:02:31.964172 064  I --- 07:045960 --:------ 07:045960 1FC9 012 0012601CB388001FC91CB388    # noqa: E501
    # 17:02:31.980015 065  W --- 01:145038 07:045960 --:------ 1FC9 006 0010A006368E                # noqa: E501
    # 17:02:32.004055 064  I --- 07:045960 01:145038 --:------ 1FC9 006 0012601CB388                # noqa: E501

    # 17:03:35.012706 053  I --- 01:145038 --:------ 01:145038 1FC9 018 FA000806368EFC3B0006368EFA1FC906368E  # noqa: E501
    # 17:03:35.658983 045  W --- 13:081807 01:145038 --:------ 1FC9 006 003EF0353F8F                # noqa: E501
    # 17:03:35.675856 053  I --- 01:145038 13:081807 --:------ 1FC9 006 00FFFF06368E                # noqa: E501

    # this is an array of codes
    # 049  I --- 01:145038 --:------ 01:145038 1FC9 018 07-0008-06368E FC-3B00-06368E                07-1FC9-06368E  # noqa: E501
    # 047  I --- 01:145038 --:------ 01:145038 1FC9 018 FA-0008-06368E FC-3B00-06368E                FA-1FC9-06368E  # noqa: E501
    # 065  I --- 01:145038 --:------ 01:145038 1FC9 024 FC-0008-06368E FC-3150-06368E FB-3150-06368E FC-1FC9-06368E  # noqa: E501

    # HW valve binding:
    # 063  I --- 01:145038 --:------ 01:145038 1FC9 018 FA-0008-06368E FC-3B00-06368E FA-1FC9-06368E  # noqa: E501
    # CH valve binding:
    # 071  I --- 01:145038 --:------ 01:145038 1FC9 018 F9-0008-06368E FC-3B00-06368E F9-1FC9-06368E  # noqa: E501
    # ZoneValve zone binding
    # 045  W --- 13:106039 01:145038 --:------ 1FC9 012 00-3EF0-359E37 00-3B00-359E37
    # DHW binding..
    # 045  W --- 13:163733 01:145038 --:------ 1FC9 012 00-3EF0-367F95 00-3B00-367F95

    # 049  I --- 01:145038 --:------ 01:145038 1FC9 018 F9-0008-06368E FC-3B00-06368E F9-1FC9-06368E  # noqa

    # the new (heatpump-aware) BDR91:
    # 045 RP --- 13:035462 18:013393 --:------ 1FC9 018 00-3EF0-348A86 00-11F0-348A86 90-7FE1-DD6ABD # noqa

    def _parser(seqx) -> dict:
        # print(dev_hex_to_id(seqx[6:]))
        assert seqx[6:] == payload[6:12]  # all with same controller
        if seqx[:2] not in ("F9", "FA", "FB", "FC"):  # or: not in DOMAIN_TYPE_MAP: ??
            assert int(seqx[:2], 16) < msg._gwy.config[MAX_ZONES]
        return [seqx[:2], seqx[2:6], dev_hex_to_id(seqx[6:])]

    assert msg.len >= 6 and msg.len % 6 == 0, msg.len  # assuming not RQ
    assert msg.verb in (" I", " W", "RP"), msg.verb  # devices will respond to a RQ!
    assert msg.src.id == dev_hex_to_id(payload[6:12]), payload[6:12]
    return [
        _parser(payload[i : i + 12])
        for i in range(0, len(payload), 12)
        if payload[i : i + 2] != "90"  # TODO: WIP
    ]


@parser_decorator  # opentherm_sync, otb_sync
def parser_1fd4(payload, msg) -> Optional[dict]:
    assert msg.verb == " I", msg.verb
    assert msg.len == 3, msg.len
    assert payload[:2] == "00", payload[:2]

    return {
        "ticker": int(payload[2:], 16),
    }


@parser_decorator  # now_next_setpoint (non-Evohome, e.g. Sundial programmer)
def parser_2249(payload, msg) -> Optional[dict]:
    # see: https://github.com/jrosser/honeymon/blob/master/decoder.cpp#L357-L370
    # 095  I --- 23:100224 --:------ 23:100224 2249 007 00-7EFF-7EFF-FFFF
    # 095  I --- 23:100224 --:------ 23:100224 2249 007 00-7EFF-7EFF-FFFF

    def _parser(seqx) -> dict:
        minutes = int(seqx[10:], 16)
        next_setpoint = msg.dtm + td(minutes=minutes)
        return {
            **_idx(seqx[:2], msg),
            "setpoint_now": _temp(seqx[2:6]),
            "setpoint_next": _temp(seqx[6:10]),
            "minutes_remaining": minutes,
            "_next_setpoint": dt.strftime(next_setpoint, "%H:%M:%S"),
        }

    # the ST9520C can support two heating zones, so: msg.len in (7, 14)?
    if msg.is_array:  # TODO: can these msgs require >1 pkts? - seems unlikely
        assert msg.len >= 7 and msg.len % 7 == 0, msg.len
        return [_parser(payload[i : i + 14]) for i in range(0, len(payload), 14)]

    assert msg.len == 7, msg.len
    return _parser(payload)


@parser_decorator  # ufh_setpoint, TODO: max length = 24?
def parser_22c9(payload, msg) -> Optional[dict]:
    def _parser(seqx) -> dict:
        assert seqx[10:], seqx[10:]

        return {
            **_idx(seqx[:2], msg),
            "temp_low": _temp(seqx[2:6]),
            "temp_high": _temp(seqx[6:10]),
            "_unknown_0": seqx[10:],
        }

    assert msg.len >= 6 and msg.len % 6 == 0, msg.len
    return [_parser(payload[i : i + 12]) for i in range(0, len(payload), 12)]


@parser_decorator  # message_22d0 - system switch?
def parser_22d0(payload, msg) -> Optional[dict]:
    assert payload[:2] == "00", payload[:2]  # has no domain?
    assert payload[2:] == "000002", payload[2:]

    return {
        "unknown": payload[2:],
    }


@parser_decorator  # boiler_setpoint
def parser_22d9(payload, msg) -> Optional[dict]:
    assert msg.len == 3, msg.len
    assert payload[:2] == "00", payload[:2]

    return {
        "boiler_setpoint": _temp(payload[2:6]),
    }


@parser_decorator  # ???? (Nuaire 2 x 2-way switch)
def parser_22f1(payload, msg) -> Optional[dict]:
    # 11:42:43.149 081  I 051 --:------ --:------ 49:086353 22F1 003 000304
    # 11:42:49.587 071  I 052 --:------ --:------ 49:086353 22F1 003 000404
    # 11:42:49.685 072  I 052 --:------ --:------ 49:086353 22F1 003 000404
    # 11:42:49.784 072  I 052 --:------ --:------ 49:086353 22F1 003 000404
    assert msg.len == 3, msg.len
    assert payload[:2] == "00", payload[:2]  # has no domain
    assert payload[4:] in ("04", "0A"), payload[4:]

    bitmap = int(payload[2:4], 16)

    _bitmap = {"_bitmap": bitmap}

    if bitmap in (2, 3):
        _action = {"fan_mode": "normal" if bitmap == 2 else "boost"}
    elif bitmap in (9, 10):
        _action = {"heater_mode": "auto" if bitmap == 10 else "off"}
    else:
        _action = {}

    return {
        **_action,
        **_bitmap,
        "unknown_0": payload[4:],
    }


@parser_decorator  # similar to 22F1? switch?
def parser_22f3(payload, msg) -> Optional[dict]:
    assert msg.len == 3, msg.len
    assert payload[:2] == "00", payload[:2]  # has no domain
    assert payload[4:6] == "0A", payload[4:6]

    return {
        "_bitmap": int(payload[2:4], 16),
    }


@parser_decorator  # setpoint (of device/zones)
def parser_2309(payload, msg) -> Union[dict, list, None]:
    def _parser(seqx) -> dict:
        return {**_idx(seqx[:2], msg), "setpoint": _temp(seqx[2:])}

    # 055 RQ --- 12:010740 13:163733 --:------ 2309 003 0007D0
    # 046 RQ --- 12:010740 01:145038 --:------ 2309 003 03073A

    assert msg.verb in (" I", "RP", " W"), msg.verb

    if msg.is_array:
        assert msg.len >= 3 and msg.len % 3 == 0, msg.len  # assuming not RQ
        return [_parser(payload[i : i + 6]) for i in range(0, len(payload), 6)]

    assert msg.len == 3, msg.len
    return _parser(payload)


@parser_decorator  # zone_mode
def parser_2349(payload, msg) -> Optional[dict]:
    # RQ --- 34:225071 30:258557 --:------ 2349 001 00
    # RP --- 30:258557 34:225071 --:------ 2349 013 007FFF00FFFFFFFFFFFFFFFFFF
    #  I --- 10:067219 --:------ 10:067219 2349 004 00000001
    assert msg.verb in (" I", "RP", " W"), msg.verb
    assert msg.len in (4, 7, 13), msg.len  # has a dtm if mode == "04", OTB has 4

    assert payload[6:8] in ZONE_MODE_MAP, payload[6:8]
    result = {"mode": ZONE_MODE_MAP.get(payload[6:8]), "setpoint": _temp(payload[2:6])}

    if msg.len >= 7:
        assert payload[8:14] == "FFFFFF", payload[8:14]

    if msg.len >= 13:
        assert payload[6:8] in ("00", "04"), payload[6:8]
        if payload[14:] == "FF" * 6:
            result["until"] = None
        else:
            result["until"] = _dtm(payload[14:26])

    return {
        **_idx(payload[:2], msg),
        **result,
    }


@parser_decorator  # hometronics _state (of unknwon)
def parser_2d49(payload, msg) -> dict:
    assert (
        payload[:2] in ("88", "FD") or int(payload[:2], 16) < msg._gwy.config[MAX_ZONES]
    ), payload[:2]
    assert payload[2:] in ("0000", "C800"), payload[2:]  # would "FFFF" mean N/A?
    # assert msg.len == 3, msg.len  # implied

    return {
        **_idx(payload[:2], msg),
        "_state": _bool(payload[2:4]),
    }


@parser_decorator  # system_mode
def parser_2e04(payload, msg) -> Optional[dict]:
    # if msg.verb == " W":
    # RQ/2E04/FF

    #  I --— 01:020766 --:------ 01:020766 2E04 016 FFFFFFFFFFFFFF0007FFFFFFFFFFFF04  # Manual          # noqa: E501
    #  I --— 01:020766 --:------ 01:020766 2E04 016 FFFFFFFFFFFFFF0000FFFFFFFFFFFF04  # Automatic/times # noqa: E501

    if msg.len == 8:  # evohome
        assert payload[:2] in SYSTEM_MODE_MAP, payload[:2]  # TODO: check AutoWithReset

    elif msg.len == 16:  # hometronics, lifestyle ID:
        assert 0 <= int(payload[:2], 16) <= 15 or payload[:2] == "FF", payload[:2]
        assert payload[16:18] in ("00", "07"), payload[16:18]
        assert payload[30:32] == "04", payload[30:32]
        # assert False

    else:
        assert False, msg.len  # msg.len in (8, 16)  # evohome 8, hometronics 16

    return {
        "system_mode": SYSTEM_MODE_MAP.get(payload[:2], payload[:2]),
        "until": _dtm(payload[2:14]) if payload[14:16] != "00" else None,
    }  # TODO: double-check the final "00"


@parser_decorator  # temperature (of device, zone/s)
def parser_30c9(payload, msg) -> Optional[dict]:
    def _parser(seqx) -> dict:
        return {**_idx(seqx[:2], msg), "temperature": _temp(seqx[2:])}

    if msg.is_array:
        assert msg.len >= 3 and msg.len % 3 == 0  # assuming not RQ
        return [_parser(payload[i : i + 6]) for i in range(0, len(payload), 6)]

    assert msg.len == 3, msg.len
    return _parser(payload)


@parser_decorator  # unknown, from STA
def parser_3120(payload, msg) -> Optional[dict]:
    # sent by STAs every ~3:45:00, why?
    assert msg.src.type == "34", msg.src.type
    assert payload == "0070B0000000FF", payload
    return {
        "unknown_0": payload,
    }


@parser_decorator  # datetime_sync
def parser_313f(payload, msg) -> Optional[dict]:
    # 2020-03-28T03:59:21.315178 045 RP --- 01:158182 04:136513 --:------ 313F 009 00FC3500A41C0307E4  # noqa: E501
    # 2020-03-29T04:58:30.486343 045 RP --- 01:158182 04:136485 --:------ 313F 009 00FC8400C51D0307E4  # noqa: E501
    # 2020-05-31T11:37:50.351511 056  I --- --:------ --:------ 12:207082 313F 009 0038021ECB1F0507E4  # noqa: E501

    # https://www.automatedhome.co.uk/vbulletin/showthread.php?5085-My-HGI80-equivalent-Domoticz-setup-without-HGI80&p=36422&viewfull=1#post36422
    # every day at ~4am TRV/RQ->CTL/RP, approx 5-10secs apart (CTL respond at any time)
    if msg.verb == "RQ":
        assert payload == "00", payload  # implies msg.len == 1 byte
        return {}

    assert msg.len == 9
    assert payload[:2] == "00"  # evohome is always "00FC"? OTB is always 00xx
    return {
        "datetime": _dtm(payload[4:18]),
        "is_dst": True if bool(int(payload[4:6], 16) & 0x80) else None,
        "_unknown_0": payload[2:4],
    }


@parser_decorator  # heat_demand (of device, FC domain)
def parser_3150(payload, msg) -> Optional[dict]:
    # event-driven, and periodically; FC domain is highest of all zones
    # TODO: all have a valid domain will UFC/CTL respond to an RQ, for FC, for a zone?

    def _parser(seqx) -> dict:
        # assert seqx[:2] == "FC" or (int(seqx[:2], 16) < MAX_ZONES)  # <5, 8 for UFC
        return {**_idx(seqx[:2], msg), "heat_demand": _percent(seqx[2:])}

    if msg.src.type == "02" and msg.is_array:  # TODO: hometronics only?
        return [_parser(payload[i : i + 4]) for i in range(0, len(payload), 4)]

    assert msg.len == 2, msg.len  # msg.src.type in ("01","02","10","04")
    return _parser(payload)  # TODO: check UFC/FC is == CTL/FC


@parser_decorator  # ???
def parser_31d9(payload, msg) -> Optional[dict]:
    assert payload[2:4] in ("00", "06"), payload[2:4]
    assert payload[4:6] == "FF" or int(payload[4:6], 16) <= 200, payload[4:6]

    if msg.len == 3:  # usu: I -->20: (no seq#)
        return {
            **_idx(payload[:2], msg),
            "percent_1": _percent(payload[4:6]),
            "unknown_0": payload[2:4],
        }

    assert msg.len == 17, msg.len  # usu: I 30:-->30:, (or 20:) with a seq#!
    assert payload[6:8] == "00", payload[6:8]
    assert payload[8:32] in ("00" * 12, "20" * 12), payload[8:32]

    return {
        **_idx(payload[:2], msg),
        "percent_1": _percent(payload[4:6]),
        "unknown_0": payload[2:4],
        "unknown_2": payload[6:8],
        "unknown_3": payload[8:32],
        "unknown_4": payload[32:],
    }


@parser_decorator  # UFC HCE80 (Nuaire humidity)
def parser_31da(payload, msg) -> Optional[dict]:
    assert msg.len == 29, msg.len  # usu: I CTL-->CTL

    assert payload[2:10] == "EF007FFF", payload[2:10]
    assert payload[12:30] == "EF7FFF7FFF7FFF7FFF", payload[12:30]
    assert payload[34:36] == "EF", payload[34:36]
    assert payload[42:44] == "00", payload[42:44]
    assert payload[46:48] in ("00", "EF"), payload[46:48]
    assert payload[48:] in ("EF7FFF7FFF", "EF7FFFFFFF"), payload[48:]

    rh = int(payload[10:12], 16) / 100 if payload[10:12] != "EF" else None  # not /200!

    return {
        **_idx(payload[:2], msg),
        "relative_humidity": rh,
        "unknown_1": payload[30:32],
        "unknown_2": payload[32:34],
        "unknown_3": payload[36:38],
        "unknown_4": payload[38:40],
        "unknown_5": payload[44:46],
    }


@parser_decorator  # ???? (Nuaire on/off)
def parser_31e0(payload, msg) -> Optional[dict]:
    # cat pkts.log | grep 31DA | grep -v ' I ' (event-driven ex 168090, humidity sensor)
    # 11:09:49.973 045  I --- VNT:168090 GWY:082155  --:------ 31E0 004 00 00 00 00
    # 11:14:46.168 045  I --- VNT:168090 GWY:082155  --:------ 31E0 004 00 00 C8 00
    # TODO: track humidity against 00/C8, OR HEATER?

    assert msg.len == 4, msg.len  # usu: I VNT->GWY
    assert payload[:4] == "0000", payload[:4]  # domain?
    assert payload[4:] in ("0000", "C800"), payload[4:]

    return {
        "state_31e0": _bool(payload[4:6]),
        "unknown_0": payload[:4],
        "unknown_1": payload[6:],
    }


@parser_decorator  # opentherm_msg
def parser_3220(payload, msg) -> Optional[dict]:
    assert msg.len == 5 and payload[:2] == "00", "Invalid OpenTherm payload"

    # these are OpenTherm-specific assertions
    if msg.src.type != "18":  # TODO: remove this workaround
        assert int(payload[2:4], 16) // 0x80 == parity(
            int(payload[2:], 16) & 0x7FFFFFFF
        ), "Invalid OpenTherm check bit"

    ot_msg_type = int(payload[2:4], 16) & 0x70
    assert (
        ot_msg_type in OPENTHERM_MSG_TYPE
    ), f"Unknown OpenTherm msg type: {ot_msg_type:02X}"

    assert int(payload[2:4], 16) & 0x0F == 0

    ot_msg_id = int(payload[4:6], 16)
    assert (
        str(ot_msg_id) in OPENTHERM_MESSAGES["messages"]
    ), f"Unknown OpenTherm msg id: {ot_msg_id} (0x{ot_msg_id:02X})"

    message = OPENTHERM_MESSAGES["messages"].get(str(ot_msg_id))

    result = {
        "id": payload[4:6],  # ot_msg_id,
        "msg_name": message["en"],
        "msg_type": OPENTHERM_MSG_TYPE[ot_msg_type],
    }

    if not message:
        return {**result, "value_raw": payload[6:]}

    if msg.verb == "RQ":
        assert ot_msg_type < 48, f"Invalid OpenTherm msg type: {ot_msg_type:02X}"
        assert payload[6:10] == "0000", payload[6:10]
        return {
            **result,
            # "description": message["en"]
        }

    assert ot_msg_type > 48, f"Invalid OpenTherm msg type: {ot_msg_type:02X}"

    if isinstance(message["var"], dict):
        if isinstance(message["val"], dict):
            result["value_hb"] = ot_msg_value(
                payload[6:8], message["val"].get("hb", message["val"])
            )
            result["value_lb"] = ot_msg_value(
                payload[8:10], message["val"].get("lb", message["val"])
            )
        else:
            result["value_hb"] = ot_msg_value(payload[6:8], message["val"])
            result["value_lb"] = ot_msg_value(payload[8:10], message["val"])

    else:
        if message["val"] in ("flag8", "u8", "s8"):
            result["value"] = ot_msg_value(payload[6:8], message["val"])
        else:
            result["value"] = ot_msg_value(payload[6:10], message["val"])

    return {
        **result,
        # "description": message["en"],
    }


@parser_decorator  # actuator_sync (aka sync_tpi: TPI cycle sync)
def parser_3b00(payload, msg) -> Optional[dict]:
    # system timing master: the device that sends I/FCC8 pkt controls the heater relay
    """Decode a 3B00 packet (actuator_sync).

    The heat relay regularly broadcasts a 3B00 at the end(?) of every TPI cycle, the
    frequency of which is determined by the (TPI) cycle rate in 1100.

    The CTL subsequently broadcasts a 3B00 (i.e. at the start of every TPI cycle).

    The OTB does not send these packets, but the CTL sends a regular broadcast anyway
    for the benefit of any zone actuators (e.g. zone valve zones).
    """

    # 053  I --- 13:209679 --:------ 13:209679 3B00 002 00C8
    # 045  I --- 01:158182 --:------ 01:158182 3B00 002 FCC8
    # 052  I --- 13:209679 --:------ 13:209679 3B00 002 00C8
    # 045  I --- 01:158182 --:------ 01:158182 3B00 002 FCC8

    # 063  I --- 01:078710 --:------ 01:078710 3B00 002 FCC8
    # 064  I --- 01:078710 --:------ 01:078710 3B00 002 FCC8

    assert msg.len == 2, msg.len
    assert payload[:2] in {"01": "FC", "13": "00", "23": "FC"}.get(msg.src.type, "00")
    assert payload[2:] == "C8", payload[2:]  # Could it be a percentage?

    return {
        **_idx(payload[:2], msg),
        "actuator_sync": _bool(payload[2:]),
    }


@parser_decorator  # actuator_state
def parser_3ef0(payload, msg) -> dict:
    # 045 RP --- 10:067219 01:078710 --:------ 3EF0 006 00 3C 10 0000FF
    # 074 RP --- 10:067219 01:078710 --:------ 3EF0 006 00 3C 10 0000FF

    # --- RP --- 10:138822 01:187666 --:------ 3EF0 006 00 00 10 0200FF
    # 063 RP --- 10:138822 01:187666 --:------ 3EF0 006 00 01 10 0200FF

    # 066 RP --- 10:067219 01:078710 --:------ 3EF0 006 00 00 10 0A00FF
    # 068 RP --- 10:067219 01:078710 --:------ 3EF0 006 00 2F 10 0A00FF
    # 066 RP --- 10:067219 01:078710 --:------ 3EF0 006 00 2F 10 0A00FF
    # 066 RP --- 10:067219 01:078710 --:------ 3EF0 006 00 2F 10 0A00FF
    # 069 RP --- 10:067219 01:078710 --:------ 3EF0 006 00 1D 10 0A00FF
    # 070 RP --- 10:067219 01:078710 --:------ 3EF0 006 00 12 10 0A00FF
    # 071 RP --- 10:067219 01:078710 --:------ 3EF0 006 00 11 10 0000FF

    # 072 RP --- 10:067219 01:078710 --:------ 3EF0 006 00 00 10 0000FF
    # 072 RP --- 10:067219 01:078710 --:------ 3EF0 006 00 00 10 0A00FF
    # 074 RP --- 10:067219 01:078710 --:------ 3EF0 006 00 00 10 0000FF

    # 095 RP --- 10:139656 34:212252 --:------ 3EF0 006 00 00 11 0000FF
    # 095 RP --- 10:114131 34:254475 --:------ 3EF0 006 00 00 10 000000

    # 060 RP --- 10:138822 01:187666 --:------ 3EF0 006 00 64 10 0C00FF
    # 058 RP --- 10:138822 01:187666 --:------ 3EF0 006 00 00 10 0400FF
    # 061 RP --- 10:138822 01:187666 --:------ 3EF0 006 00 64 10 0800FF

    # 063 RP --- 10:138822 01:187666 --:------ 3EF0 006 00 01 11 0100FF
    # 058 RP --- 10:138822 01:187666 --:------ 3EF0 006 00 00 11 0100FF
    # 057 RP --- 10:138822 01:187666 --:------ 3EF0 006 00 01 10 FA00FF
    # 062 RP --- 10:138822 01:187666 --:------ 3EF0 006 00 00 11 0100FF
    # 065 RP --- 10:138822 01:187666 --:------ 3EF0 006 00 FF 10 0200FF
    # 060 RP --- 10:138822 01:187666 --:------ 3EF0 006 00 00 11 0100FF
    # 062 RP --- 10:067219 01:078710 --:------ 3EF0 006 00 11 10 0AFFFF

    # 051  I --- 13:049225 --:------ 13:049225 3EF0 003 00 00 FF
    # 054  I --- 13:209679 --:------ 13:209679 3EF0 003 00 C8 FF

    if msg.src.type in "08":  # Honeywell Japser ?HVAC
        assert msg.len == 20, msg.len
        return {
            "ordinal": f"0x{payload[2:8]}",
            "blob": payload[8:],
        }

    assert payload[:2] == "00", f"domain_id is not 00: {payload[:2]}"
    if msg.len == 3:
        assert payload[2:4] in ("00", "C8", "FF"), payload[2:4]
        assert payload[4:6] == "FF", payload[4:6]

    if msg.len >= 6:  # for OTB, TODO: why 100 & not 200
        assert payload[2:4] == "FF" or int(payload[2:4], 16) <= 100, payload[2:4]
        assert payload[4:6] in ("10", "11"), payload[4:6]

    result = {
        # **_idx(payload[:2], msg),
        "actuator_enabled": bool(_percent(payload[2:4])),
        "modulation_level": _percent(payload[2:4]),
        "_unknown_0": payload[4:6],
    }

    if msg.len >= 6:  # for OTB (there's no reliable) modulation_level <-> flame_state)
        # assert payload[6:8] in (
        #     "00",
        #     "01",
        #     "02",
        #     "04",
        #     "08",
        #     "0A",
        #     "0C",
        #     "42",
        # ), payload[6:8]
        # assert payload[8:12] in ("0000", "00FF")  # and "FFFF"?

        result.update(
            {
                "flame_active": {"0A": True}.get(payload[6:8], False),
                "flame_state": payload[6:8],
                "_unknown_1": payload[8:],
            }
        )

    return result


@parser_decorator  # actuator_cycle
def parser_3ef1(payload, msg) -> dict:
    # RP --- 10:067219 18:200202 --:------ 3EF1 007 00-7FFF-003C-0010

    if msg.src.type == "08":  # Honeywell Japser ?HVAC
        assert msg.len == 18, msg.len
        return {
            "ordinal": f"0x{payload[2:8]}",
            "blob": payload[8:],
        }

    if msg.src.type == "31":  # or (12, 20) Honeywell Japser ?HVAC
        assert msg.len == 12, msg.len
        return {
            "ordinal": f"0x{payload[2:8]}",
            "blob": payload[8:],
        }

    if msg.verb == "RQ":
        assert msg.len == 1, msg.len
        return {}

    assert msg.verb == "RP", msg.verb
    assert msg.len == 7, msg.len
    assert payload[:2] == "00", payload[:2]
    assert _percent(payload[10:12]) <= 1, payload[10:12]
    # assert payload[12:] == "FF"

    cycle_countdown = None if payload[2:6] == "7FFF" else int(payload[2:6], 16)

    return {
        **_idx(payload[:2], msg),
        "actuator_enabled": bool(_percent(payload[10:12])),
        "modulation_level": _percent(payload[10:12]),
        "actuator_countdown": int(payload[6:10], 16),
        "cycle_countdown": cycle_countdown,  # not for OTB, == "7FFF"
        "_unknown_0": payload[12:],  # for OTB != "FF"
    }


# def create_7fff(counter, length=48) -> Command:
#     payload = f"7F{dts_to_hex(dt.now())}7F{counter % 0x10000:04X}7F{interval:04X}7F"
#     payload = payload.ljust(length * 2, "F")
#     return Command(" I", "63:262142", "7FFF", payload, qos={"retries": 0})

# @parser_decorator  # faked puzzle pkt shouldn't be decorated
def parser_7fff(payload, msg) -> Optional[dict]:
    return {
        "counter": int(payload[16:20], 16),
        "datetime": dts_from_hex(payload[2:14]),
        "interval": int(payload[22:26], 16) / 100,
    }


@parser_decorator
def parser_unknown(payload, msg) -> Optional[dict]:
    # TODO: it may be useful to search payloads for hex_ids, commands, etc.
    raise NotImplementedError

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - payload processors."""

# Many thanks to:
# - Evsdd: 0404
# - Ierlandfan: 3150, 31D9, 31DA, others
# - ReneKlootwijk: 3EF0
# - brucemiranda: 3EF0, others

import logging
from datetime import datetime as dt
from datetime import timedelta as td
from typing import Any, Optional, Union

from .const import (
    _000C_DEVICE,
    _000C_DEVICE_TYPE,
    _0005_ZONE_TYPE,
    _0418_DEVICE_CLASS,
    _0418_FAULT_STATE,
    _0418_FAULT_TYPE,
    ATTR_DHW_VALVE,
    ATTR_DHW_VALVE_HTG,
    ATTR_HTG_CONTROL,
    BOOST_TIMER,
    FAN_MODE,
    FAN_MODES,
    HEATER_MODE,
    HEATER_MODES,
    SYSTEM_MODE,
    ZONE_MODE,
)
from .exceptions import InvalidPayloadError
from .helpers import (
    bool_from_hex,
    date_from_hex,
    double,
    dtm_from_hex,
    dts_from_hex,
    flag8,
    hex_id_to_dec,
    percent,
    str_from_hex,
    temp_from_hex,
    valve_demand,
)
from .opentherm import EN, MSG_DESC, MSG_ID, MSG_NAME, MSG_TYPE, decode_frame
from .version import VERSION

from .const import I_, RP, RQ, W_, __dev_mode__  # noqa: F401, isort: skip
from .const import (  # noqa: F401, isort: skip
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

LOOKUP_PUZZ = {
    "10": "engine",  # .    # version str, e.g. v0.14.0
    "11": "impersonating",  # pkt header, e.g. 30C9| I|03:123001 (15 characters, packed)
    "12": "message",  # .   # message only, max len is 16 ascii characters
    "13": "message",  # .   # message only, but without a timestamp, max len 22 chars
}  # "00" is reserved

DEV_MODE = __dev_mode__ and False
TEST_MODE = False  # enable to test constructors (usu. W)

_LOGGER = _PKT_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


def parser_decorator(fnc):  # TODO: remove
    def wrapper(*args, **kwargs) -> Optional[Any]:
        return fnc(*args, **kwargs)

    return wrapper


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

    return {
        "payload": "-".join((payload[:2], payload[2:6], payload[6:8], payload[8:])),
    }


@parser_decorator  # sensor_weather
def parser_0002(payload, msg) -> Optional[dict]:
    # seen with: 03:125829, 03:196221, 03:196196, 03:052382, 03:201498, 03:201565:
    #  I 000 03:201565 --:------ 03:201565 0002 004 03020105  # no zone_idx, domain_id

    # is it CODE_IDX_COMPLEX:
    #  - 02...... for outside temp?
    #  - 03...... for other stuff?

    if msg.src.type == "03":  # payload[2:] == "03", DEX
        assert payload == "03020105"
        return {"_unknown": payload}

    # if payload[6:] == "02":  # msg.src.type == "17":
    return {
        "temperature": temp_from_hex(payload[2:6]),
        "_unknown": payload[6:],
    }


@parser_decorator  # zone_name
def parser_0004(payload, msg) -> Optional[dict]:
    # RQ payload is zz00; limited to 12 chars in evohome UI? if "7F"*20: not a zone

    result = {} if payload[4:] == "7F" * 20 else {"name": str_from_hex(payload[4:])}

    # TODO: remove me...
    if TEST_MODE and msg.verb == W_:
        from .command import Command

        cmd = Command.set_zone_name(msg.dst.id, payload[:2], result["name"])
        assert cmd.payload == payload, str_from_hex(payload)
    # TODO: remove me...

    return result


@parser_decorator  # system_zone (add/del a zone?)
def parser_0005(payload, msg) -> Optional[dict]:  # TODO: needs a cleanup
    #  I --- 01:145038 --:------ 01:145038 0005 004 00000100
    # RP --- 02:017205 18:073736 --:------ 0005 004 0009001F
    #  I --- 34:064023 --:------ 34:064023 0005 012 000A0000-000F0000-00100000

    def _parser(seqx) -> dict:
        if msg.src.type == "02":  # DEX, or use: seqx[2:4] == _0005_ZONE.UFH:
            zone_mask = flag8(seqx[6:8], lsb=True)
        elif msg.len == 3:  # ATC928G1000 - 1st gen monochrome model, max 8 zones
            zone_mask = flag8(seqx[4:6], lsb=True)
        else:
            zone_mask = flag8(seqx[4:6], lsb=True) + flag8(seqx[6:8], lsb=True)
        return {
            "_device_class": seqx[2:4],
            "zone_mask": zone_mask,
            "zone_type": _0005_ZONE_TYPE.get(seqx[2:4], f"unknown_{seqx[2:4]}"),
        }

    if msg._has_array:
        assert (
            msg.verb == I_ and msg.src.type == "34"
        ), f"{msg._pkt} # expecting I/34:"  # DEX
        return [_parser(payload[i : i + 8]) for i in range(0, len(payload), 8)]

    if msg.verb == RQ:  # RQs have a context: zone_type
        return {
            "_device_class": payload[2:4],
            "zone_type": _0005_ZONE_TYPE.get(payload[2:4], f"unknown_{payload[2:4]}"),
        }

    return _parser(payload)


@parser_decorator  # schedule_sync (any changes?)
def parser_0006(payload, msg) -> Optional[dict]:
    """Return the total number of changes to the schedules, including the DHW schedule.

    An RQ is sent every ~60s by a RFG100, an increase will prompt it to send a run of
    RQ/0404s (it seems to assume only the zones may have changed?).
    """
    # 16:10:34.288 053 RQ --- 30:071715 01:145038 --:------ 0006 001 00
    # 16:10:34.291 053 RP --- 01:145038 30:071715 --:------ 0006 004 00050008

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

    if msg.src.type == "31" and msg.len == 13:  # Honeywell Japser ?HVAC, DEX
        assert msg.len == 13, "expecting length 13"
        return {
            "ordinal": f"0x{payload[2:8]}",
            "blob": payload[8:],
        }

    return {"relay_demand": percent(payload[2:4])}


@parser_decorator  # relay_failsafe
def parser_0009(payload, msg) -> Union[dict, list]:
    """The relay failsafe mode.

    The failsafe mode defines the relay behaviour if the RF communication is lost (e.g.
    when a room thermostat stops communicating due to discharged batteries):
        False (disabled) - if RF comms are lost, relay will be held in OFF position
        True  (enabled)  - if RF comms are lost, relay will cycle at 20% ON, 80% OFF

    This setting may need to be enabled to ensure prost protect mode.
    """
    # can get: 003 or 006, e.g.: FC01FF-F901FF or FC00FF-F900FF
    #  I --- 23:100224 --:------ 23:100224 0009 003 0100FF  # 2-zone ST9520C
    #  I --- 10:040239 01:223036 --:------ 0009 003 000000

    def _parser(seqx) -> dict:
        assert seqx[:2] in ("F9", "FC") or int(seqx[:2], 16) < msg._gwy.config.max_zones
        return {
            "domain_id" if seqx[:1] == "F" else "zone_idx": seqx[:2],
            "failsafe_enabled": {"00": False, "01": True}.get(seqx[2:4]),
            "unknown_0": seqx[4:],
        }

    if msg._has_array:
        return [_parser(payload[i : i + 6]) for i in range(0, len(payload), 6)]

    return {
        "failsafe_enabled": {"00": False, "01": True}.get(payload[2:4]),
        "unknown_0": payload[4:],
    }


@parser_decorator  # zone_config (zone/s)
def parser_000a(payload, msg) -> Union[dict, list, None]:
    # RQ --- 34:044203 01:158182 --:------ 000A 001 08
    # RP --- 01:158182 34:044203 --:------ 000A 006 081001F409C4
    # RQ --- 22:017139 01:140959 --:------ 000A 006 080001F40DAC
    # RP --- 01:140959 22:017139 --:------ 000A 006 081001F40DAC

    def _parser(seqx) -> dict:  # null_rp: "007FFF7FFF"
        bitmap = int(seqx[2:4], 16)
        return {
            "min_temp": temp_from_hex(seqx[4:8]),
            "max_temp": temp_from_hex(seqx[8:]),
            "local_override": not bool(bitmap & 1),
            "openwindow_function": not bool(bitmap & 2),
            "multiroom_mode": not bool(bitmap & 16),
            "_unknown_bitmap": f"0b{bitmap:08b}",  # TODO: try W with this
        }  # cannot determine zone_type from this information

    if msg._has_array:  # NOTE: these arrays can span 2 pkts!
        return [
            {
                "zone_idx": payload[i : i + 2],
                **_parser(payload[i : i + 12]),
            }
            for i in range(0, len(payload), 12)
        ]

    if msg.verb == RQ and msg.len <= 2:  # some RQs have a payload (why?)
        return {}

    assert msg.len == 6, f"{msg._pkt} # expecting length 006"
    result = _parser(payload)

    # TODO: remove me...
    if TEST_MODE and msg.verb == W_:
        from .command import Command

        kwargs = {k: v for k, v in result.items() if k[:1] != "_"}
        cmd = Command.set_zone_config(msg.dst.id, payload[:2], **kwargs)
        assert cmd.payload == payload, cmd.payload
    # TODO: remove me...

    return result


@parser_decorator  # zone_devices
def parser_000c(payload, msg) -> Optional[dict]:
    #  I --- 34:092243 --:------ 34:092243 000C 018 00-0A-7F-FFFFFF 00-0F-7F-FFFFFF 00-10-7F-FFFFFF  # noqa: E501
    # RP --- 01:145038 18:013393 --:------ 000C 006 00-00-00-10DAFD
    # RP --- 01:145038 18:013393 --:------ 000C 012 01-00-00-10DAF5 01-00-00-10DAFB

    # RQ payload is zz00, NOTE: aggregation of parsing taken here

    def complex_index(seqx, msg) -> dict:  # complex index
        # TODO: 000C to a UFC should be ufh_ifx, not zone_idx
        if msg.src.type == "02":  # DEX
            assert int(seqx, 16) < 8, f"invalid ufh_idx: '{seqx}' (0x00)"
            return {
                "ufh_idx": seqx,
                "zone_id": None if payload[4:6] == "7F" else payload[4:6],
            }

        if payload[2:4] in (_000C_DEVICE.DHW_SENSOR, _000C_DEVICE.DHW):
            assert (
                int(seqx, 16) < 1 if payload[2:4] == "0D" else 2
            ), f"invalid _idx: '{seqx}' (0x01)"
            return {"domain_id": "FA"}

        if payload[2:4] == _000C_DEVICE.HTG:
            assert int(seqx, 16) < 1, f"invalid _idx: '{seqx}' (0x02)"
            return {"domain_id": "FC"}

        assert (
            int(seqx, 16) < msg._gwy.config.max_zones
        ), f"invalid zone_idx: '{seqx}' (0x03)"
        return {"zone_idx": seqx}

    def _parser(seqx) -> dict:
        # TODO: this assumption that all domain_id/zones_idx are the same is wrong...
        assert seqx[:2] == payload[:2], f"{msg._pkt} # {seqx[:2]} != idx"
        assert seqx[4:6] == "7F" or int(seqx[4:6], 16) < msg._gwy.config.max_zones
        return {hex_id_to_dec(seqx[6:12]): seqx[4:6]}

    device_class = _000C_DEVICE_TYPE.get(payload[2:4], f"unknown_{payload[2:4]}")
    if device_class == ATTR_DHW_VALVE and payload[:2] == "01":
        device_class = ATTR_DHW_VALVE_HTG

    result = {
        **complex_index(payload[:2], msg),
        "_device_class": payload[2:4],
        "device_class": device_class,
    }
    if msg.verb == RQ:  # RQs have a context: index, zone_type
        return result

    devices = [_parser(payload[i : i + 12]) for i in range(0, len(payload), 12)]
    return {
        **result,
        "devices": [k for d in devices for k, v in d.items() if v != "7F"],
    }


@parser_decorator  # unknown, from STA
def parser_000e(payload, msg) -> Optional[dict]:
    assert payload in ("000000", "000014")  # rarely, from STA:xxxxxx
    return {"unknown_0": payload}


@parser_decorator  # rf_check
def parser_0016(payload, msg) -> Optional[dict]:
    # TODO: does 0016 include parent_idx?, but RQ/07:/0000?
    # RQ --- 22:060293 01:078710 --:------ 0016 002 0200
    # RP --- 01:078710 22:060293 --:------ 0016 002 021E
    # RQ --- 12:010740 01:145038 --:------ 0016 002 0800
    # RP --- 01:145038 12:010740 --:------ 0016 002 081E
    # RQ --- 07:031785 01:063844 --:------ 0016 002 0000
    # RP --- 01:063844 07:031785 --:------ 0016 002 002A

    if msg.verb == RQ:  # and msg.len == 1:  # TODO: some RQs have a payload
        return {}

    rf_value = int(payload[2:4], 16)
    return {
        "rf_strength": min(int(rf_value / 5) + 1, 5),
        "rf_value": rf_value,
    }


@parser_decorator  # language (of device/system)
def parser_0100(payload, msg) -> Optional[dict]:

    if msg.verb == RQ and msg.len == 1:  # some RQs have a payload
        return {}

    return {
        "language": str_from_hex(payload[2:6]),
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
    # assert msg.len == 2, msg.len
    # assert payload[2:] in ("00", "03"), payload[2:]
    return {"unknown_0": payload[2:]}


@parser_decorator  # unknown, from a HR91 (when its buttons are pushed)
def parser_01e9(payload, msg) -> Optional[dict]:
    # 23:57:31.581348 048  W --- 04:000722 01:158182 --:------ 01E9 002 0003
    # 23:57:31.643188 045  I --- 01:158182 04:000722 --:------ 01E9 002 0000
    assert msg.len == 2, msg.len
    assert payload[2:] in ("00", "03"), payload[2:]
    return {"unknown_0": payload[2:]}


@parser_decorator  # zone_schedule (fragment)
def parser_0404(payload, msg) -> Optional[dict]:
    # Retreival of Zone schedule
    # RQ --- 30:185469 01:037519 --:------ 0404 007 00200008000100
    # RP --- 01:037519 30:185469 --:------ 0404 048 002000082901036...
    # RQ --- 30:185469 01:037519 --:------ 0404 007 00200008000203
    # RP --- 01:037519 30:185469 --:------ 0404 048 002000082902034D...
    # RQ --- 30:185469 01:037519 --:------ 0404 007 00200008000303
    # RP --- 01:037519 30:185469 --:------ 0404 038 002000081F0303C1...

    # Retreival of DHW schedule
    # RQ --- 30:185469 01:037519 --:------ 0404 007 00230008000100
    # RP --- 01:037519 30:185469 --:------ 0404 048 0023000829010368...
    # RQ --- 30:185469 01:037519 --:------ 0404 007 00230008000203
    # RP --- 01:037519 30:185469 --:------ 0404 048 00230008290203ED...
    # RQ --- 30:185469 01:037519 --:------ 0404 007 00230008000303
    # RP --- 01:037519 30:185469 --:------ 0404 014 002300080703031F...

    def _header(seqx) -> dict:
        return {
            "frag_index": int(seqx[10:12], 16),
            "frag_total": int(seqx[12:], 16),
            "frag_length": int(seqx[8:10], 16),
        }

    if msg.verb == RQ:  # RQs have a context: index, fragment_idx
        return _header(payload[:14])

    return {
        **_header(payload[:14]),
        "fragment": payload[14:],
    }


@parser_decorator  # system_fault
def parser_0418(payload, msg) -> Optional[dict]:
    # RP --- 01:145038 18:013393 --:------ 0418 022 000000B0000000000000000000007FFFFF7000000000  # noqa
    # RP --- 01:145038 18:013393 --:------ 0418 022 000036B0010000000000108000007FFFFF7000000000  # noqa
    # RP --- 01:145038 18:013393 --:------ 0418 022 000000B00401010000008694A3CC7FFFFF70000ECC8A  # noqa
    #  I --- 01:037519 --:------ 01:037519 0418 022 000000B0050000000000239581877FFFFF7000000001  # Evotouch Battery Error  # noqa
    # RP --- 01:037519 18:140805 --:------ 0418 022 004024B0060006000000CB94A112FFFFFF70007AD47D  # noqa
    #                                                 0     0   1     1            3        3
    #                                                 2     8   2     8            0        8

    # assert int(payload[4:6], 16) < 64, f"Unexpected log_idx: 0x{payload[4:6]}"

    if dts_from_hex(payload[18:30]) is None:  # a null log entry
        return {}

    assert payload[2:4] in _0418_FAULT_STATE, payload[2:4]  # C0 don't appear in UI?
    assert payload[8:10] in _0418_FAULT_TYPE, payload[8:10]
    assert payload[12:14] in _0418_DEVICE_CLASS, payload[12:14]

    result = {
        "timestamp": dts_from_hex(payload[18:30]),
        "fault_state": _0418_FAULT_STATE.get(payload[2:4], payload[2:4]),
        "fault_type": _0418_FAULT_TYPE.get(payload[8:10], payload[8:10]),
        "device_class": _0418_DEVICE_CLASS.get(payload[12:14], payload[12:14]),
    }

    if payload[10:12] == "FC" and result["device_class"] == "actuator":
        result["device_class"] = ATTR_HTG_CONTROL  # aka Boiler relay

    assert int(payload[10:12], 16) < msg._gwy.config.max_zones or (
        payload[10:12] in ("F9", "FA", "FC")  # "1C"?
    ), f"unexpected domain_id: {payload[10:12]}"

    if payload[12:14] != "00":  # TODO: Controller
        key_name = (
            "zone_id"
            if int(payload[10:12], 16) < msg._gwy.config.max_zones
            else "domain_id"
        )  # TODO: don't use zone_idx (for now)
        result.update({key_name: payload[10:12]})

    if payload[38:] == "000002":  # "00:000002 for Unknown?
        result.update({"device_id": None})
    elif payload[38:] not in ("000000", "000001"):  # "00:000001 for Controller?
        result.update({"device_id": hex_id_to_dec(payload[38:])})

    result.update(
        {
            "_unknown_1": payload[6:8],  # B0 ?priority
            "_unknown_2": payload[14:18],  # 0000
            "_unknown_3": payload[30:38],  # FFFF7000
        }
    )

    return {"log_entry": [v for k, v in result.items() if k != "log_idx"]}


@parser_decorator  # unknown, from STA, VMS
def parser_042f(payload, msg) -> Optional[dict]:
    #  I --- 34:064023 --:------ 34:064023 042F 008 00-0000-0023-0023-F5
    #  I --- 34:064023 --:------ 34:064023 042F 008 00-0000-0024-0024-F5
    #  I --- 34:064023 --:------ 34:064023 042F 008 00-0000-0025-0025-F5
    #  I --- 34:064023 --:------ 34:064023 042F 008 00-0000-0026-0026-F5
    #  I --- 34:092243 --:------ 34:092243 042F 008 00-0001-0021-0022-01
    #  I     34:011469 --:------ 34:011469 042F 008 00-0001-0003-0004-BC

    #  I --- 32:168090 --:------ 32:168090 042F 009 00-0000100F00105050
    #  I --- 32:166025 --:------ 32:166025 042F 009 00-050E0B0C00111470

    if msg.len != 8:
        return {"unknown": payload[2:]}

    return {
        "counter_1": int(payload[2:6], 16),
        "counter_2": int(payload[6:10], 16),
        "counter_total": int(payload[10:14], 16),
        "unknown_0": payload[14:],
    }


@parser_decorator  # TODO: unknown, from THM (only when its a CTL?)
def parser_0b04(payload, msg) -> Optional[dict]:
    #  I --- --:------ --:------ 12:207082 0B04 002 00C8  # batch of 3, every 24h

    return {"_unknown_0": payload[2:]}


@parser_decorator  # mixvalve_config (zone), NB: mixvalves are listen-only
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
    result = {k: v for x in params for k, v in x.items()}

    # TODO: remove me...
    if TEST_MODE and msg.verb == W_:
        from .command import Command

        KEYS = (
            "max_flow_setpoint",
            "min_flow_setpoint",
            "valve_run_time",
            "pump_run_time",
        )
        cmd = Command.get_mix_valve_params(
            msg.dst.id, payload[:2], **{k: v for k, v in result.items() if k in KEYS}
        )
        assert cmd.payload == payload, cmd.payload
    # TODO: remove me...

    return result


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
        "battery_level": percent(payload[2:4]),
    }


@parser_decorator  # max_ch_setpoint (supply high limit)
def parser_1081(payload, msg) -> Optional[dict]:
    return {"setpoint": temp_from_hex(payload[2:])}


@parser_decorator  # unknown (non-Evohome, e.g. ST9520C)
def parser_1090(payload, msg) -> dict:
    # 14:08:05.176 095 RP --- 23:100224 22:219457 --:------ 1090 005 007FFF01F4
    # 18:08:05.809 095 RP --- 23:100224 22:219457 --:------ 1090 005 007FFF01F4

    # this is an educated guess
    assert msg.len == 5, msg.len
    assert int(payload[:2], 16) < 2, payload[:2]

    return {
        "temp_0": temp_from_hex(payload[2:6]),
        "temp_1": temp_from_hex(payload[6:10]),
    }


@parser_decorator  # dhw (cylinder) params  # FIXME: a bit messy
def parser_10a0(payload, msg) -> Optional[dict]:
    # RQ --- 07:045960 01:145038 --:------ 10A0 006 00-1087-00-03E4  # RQ/RP, every 24h
    # RP --- 01:145038 07:045960 --:------ 10A0 006 00-109A-00-03E8
    # RP --- 10:048122 18:006402 --:------ 10A0 003 00-1B58

    # these may not be reliable...
    # RQ --- 01:136410 10:067219 --:------ 10A0 002 0000
    # RQ --- 07:017494 01:078710 --:------ 10A0 006 00-1566-00-03E4

    # RQ --- 07:045960 01:145038 --:------ 10A0 006 00-31FF-00-31FF  # null
    # RQ --- 07:045960 01:145038 --:------ 10A0 006 00-1770-00-03E8
    # RQ --- 07:045960 01:145038 --:------ 10A0 006 00-1374-00-03E4
    # RQ --- 07:030741 01:102458 --:------ 10A0 006 00-181F-00-03E4
    # RQ --- 07:036831 23:100224 --:------ 10A0 006 01-1566-00-03E4  # non-evohome

    # these from a RFG...
    # RQ --- 30:185469 01:037519 --:------ 0005 002 000E
    # RP --- 01:037519 30:185469 --:------ 0005 004 000E0300  # two DHW valves
    # RQ --- 30:185469 01:037519 --:------ 10A0 001 01 (01 )

    if msg.verb == RQ and msg.len == 1:  # some RQs have a payload (why?)
        # 045 RQ --- 07:045960 01:145038 --:------ 10A0 006 0013740003E4
        # 037 RQ --- 18:013393 01:145038 --:------ 10A0 001 00
        # 054 RP --- 01:145038 18:013393 --:------ 10A0 006 0013880003E8
        return {}

    assert msg.len in (1, 3, 6), msg.len  # OTB uses 3, evohome uses 6
    assert payload[:2] in ("00", "01"), payload[:2]  # can be two DHW valves/system

    result = {}
    if msg.len >= 2:
        setpoint = temp_from_hex(payload[2:6])  # 255 for OTB? iff no DHW?
        result = {"setpoint": None if setpoint == 255 else setpoint}  # 30.0-85.0 C
    if msg.len >= 4:
        result["overrun"] = int(payload[6:8], 16)  # 0-10 minutes
    if msg.len >= 6:
        result["differential"] = temp_from_hex(payload[8:12])  # 1.0-10.0 C

    # TODO: remove me...
    if TEST_MODE and msg.verb == W_:
        from .command import Command

        KEYS = ("setpoint", "overrun", "differential")
        cmd = Command.set_dhw_params(
            msg.dst.id, **{k: v for k, v in result.items() if k in KEYS}
        )
        assert cmd.payload == payload, cmd.payload
    # TODO: remove me...

    return result


@parser_decorator  # device_info
def parser_10e0(payload, msg) -> Optional[dict]:
    assert msg.len >= 19, msg.len  # in (19, 28, 30, 36, 38), msg.len

    # if DEV_MODE:
    try:
        if msg.src.type == "01":  # DEX
            assert payload[2:20] in (
                "0002FF0119FFFFFFFF",  # ATC928-G3-0xx Evo Mk3 - EvoTouch Colour (WiFi, 12 zones)
                "0002FF0163FFFFFFFF",  # ATP928-G2-080 Evo Mk2 - Color (no WiFi)
                "0002FFFF17FFFFFFFF",  # ATC928-G1-000 Evo Mk1 - Monochrone (?prototype, 8 zones)
            ), payload[2:20]
        elif msg.src.type == "02":  # DEX
            assert payload[2:20] in (
                "0003FF0203FFFF0001",  # HCE80 V3.10 061117
            ), payload[2:20]
        elif msg.src.type == "04":  # DEX
            assert payload[2:20] in (
                "0002FF0412FFFFFFFF",  # HR92 Radiator Ctrl.
                "0002FF050BFFFFFFFF",  # HR91 Radiator Ctrl.
            ), payload[2:20]
        elif msg.src.type == "08":  # DEX
            assert payload[2:20] in (
                "0002FF0802FFFFFFFE",  # Jasper EIM (non-evohome)
            ), payload[2:20]
        elif msg.src.type == "10":  # DEX
            assert payload[2:20] in (
                "0001C8810B0700FEFF",  # R8820A
                "0002FF0A0CFFFFFFFF",  # R8810A
            ), payload[2:20]
        elif msg.src.type == "18":  # DEX
            assert payload[2:20] in (
                "0001C8820C006AFEFF",  # HRA82 (Orcon MVHR?)
            ), payload[2:20]
        elif msg.src.type == "20":  # DEX
            assert payload[2:20] in (
                "000100140C06010000",  # n/a
                "0001001B190B010000",  # n/a
                "0001001B221201FEFF",  # CVE-RF
                "0001001B271501FEFF",  # CVE-RF
                "0001001B281501FEFF",  # CVE-RF
            ), payload[2:20]
        elif msg.src.type == "29":  # DEX
            assert payload[2:20] in (
                "0001C825050266FFFF",  # VMS-17HB01
                "0001C8260D0467FFFF",  # VMC-15RP01
                "0001C827070167FFFF",  # VMN-15LF01
            ), payload[2:20]
        elif msg.src.type == "30":  # DEX
            assert payload[2:20] in (
                "0001C90011006CFEFF",  # BRDG-02JAS01 (fan, PIV)
                "0002FF1E01FFFFFFFF",  # Internet Gateway
                "0002FF1E03FFFFFFFF",  # Internet Gateway
            ), payload[2:20]
        elif msg.src.type == "31":  # DEX
            assert payload[2:20] in (
                "0002FF1F02FFFFFFFF",  # Jasper Stat TXXX
            ), payload[2:20]
        elif msg.src.type == "32":  # DEX
            # VMN-23LMH23 (switch, 4-button)
            assert payload[2:20] in (
                "0001C83A0F0866FFFF",  # VMD-17RPS01
                "0001C85701016CFFFF",  # VMS-23C33   (sensor, CO2)
                "0001C85802016CFFFF",  # VMS-23HB33  (sensor, RH/temp)
                "0001C85803016CFFFF",  # VMS-23HB33  (sensor, RH/temp)
                "0001C8950B0A67FEFF",  # VMD-15RMS86 (fan, Orcon HRC 500)
            ), payload[2:20]
        elif msg.src.type == "34":  # DEX
            assert payload[2:20] in (
                "0001C8380A0100F1FF",  # T87RF2025
                "0001C8380F0100F1FF",  # T87RF2025
            ), payload[2:20]
        elif msg.src.type == "37":  # DEX
            assert payload[2:20] in (
                "0001001B2E1901FEFF",  # CVE-RF
                "0001001B311901FEFF",  # CVE-RF
                "0001001B361B01FEFF",  # CVE-RF
                "0001001B381B01FEFF",  # CVE-RF
                "00010028080101FEFF",  # VMS-12C39
            ), payload[2:20]
        else:
            assert False, payload[2:20]

    except AssertionError:
        _LOGGER.warning(
            f"{msg._pkt} < Support development by reporting this pkt, "
            "please include a description/the make & model of this device"
        )

    date_2 = date_from_hex(payload[20:28])  # could be 'FFFFFFFF'
    date_1 = date_from_hex(payload[28:36])  # could be 'FFFFFFFF'
    description = bytearray.fromhex(payload[36:]).split(b"\x00")[0].decode()

    return {  # TODO: add version?
        "unknown_0": payload[2:20],
        "date_2": date_2 or "0000-00-00",
        "date_1": date_1 or "0000-00-00",
        "description": description,
        "_unknown_1": payload[38 + len(description) * 2 :],
    }


@parser_decorator  # device_id
def parser_10e1(payload, msg) -> Optional[dict]:
    return {"device_id": hex_id_to_dec(payload[2:])}


@parser_decorator  # tpi_params (domain/zone/device)  # FIXME: a bit messy
def parser_1100(payload, msg) -> Optional[dict]:
    def complex_index(seqx) -> dict:
        return {"domain_id": seqx} if seqx[:1] == "F" else {}  # only FC

    if msg.src.type == "08":  # Honeywell Japser ?HVAC, DEX
        assert msg.len == 19, msg.len
        return {
            "ordinal": f"0x{payload[2:8]}",
            "blob": payload[8:],
        }

    if msg.verb == RQ and msg.len == 1:  # some RQs have a payload (why?)
        return complex_index(payload[:2])

    assert int(payload[2:4], 16) / 4 in range(1, 13), payload[2:4]
    assert int(payload[4:6], 16) / 4 in range(1, 31), payload[4:6]
    assert int(payload[6:8], 16) / 4 in range(0, 16), payload[6:8]

    # for:             TPI              // heatpump
    #  - cycle_rate:   6 (3, 6, 9, 12)  // ?? (1-9)
    #  - min_on_time:  1 (1-5)          // ?? (1, 5, 10,...30)
    #  - min_off_time: 1 (1-?)          // ?? (0, 5, 10, 15)

    def _parser(seqx) -> dict:
        return {
            "cycle_rate": int(int(payload[2:4], 16) / 4),  # cycles/hour
            "min_on_time": int(payload[4:6], 16) / 4,  # min
            "min_off_time": int(payload[6:8], 16) / 4,  # min
            "_unknown_0": payload[8:10],  # always 00, FF?
        }

    result = _parser(payload)

    if msg.len > 5:
        assert (
            payload[10:14] == "7FFF" or 1.5 <= temp_from_hex(payload[10:14]) <= 3.0
        ), f"unexpected value for PBW: {payload[10:14]}"

        result.update(
            {
                "proportional_band_width": temp_from_hex(payload[10:14]),
                "_unknown_1": payload[14:],  # always 01?
            }
        )

    # TODO: remove me...
    if TEST_MODE and msg.verb == W_:
        from .command import Command

        KEYS = ("cycle_rate", "min_on_time", "min_off_time", "proportional_band_width")
        cmd = Command.set_tpi_params(
            msg.dst.id, payload[:2], **{k: v for k, v in result.items() if k in KEYS}
        )
        assert cmd.payload == payload, cmd.payload
    # TODO: remove me...

    return {
        **complex_index(payload[:2]),
        **result,
    }


@parser_decorator  # dhw cylinder temperature
def parser_1260(payload, msg) -> Optional[dict]:
    return {"temperature": temp_from_hex(payload[2:])}


@parser_decorator  # outdoor humidity
def parser_1280(payload, msg) -> Optional[dict]:
    # this packet never seen in the wild
    # assert msg.len == 6 if type == ?? else 2, msg.len
    assert payload[:2] == "00", payload[:2]  # domain?

    rh = int(payload[2:4], 16) / 100 if payload[2:4] != "EF" else None
    if msg.len == 2:
        return {"relative_humidity": rh}

    assert msg.len == 6, f"pkt length is {msg.len}, expected 6"
    return {
        "relative_humidity": rh,
        "temperature": temp_from_hex(payload[4:8]),
        "dewpoint_temp": temp_from_hex(payload[8:12]),
    }


@parser_decorator  # outdoor temperature
def parser_1290(payload, msg) -> Optional[dict]:
    # evohome responds to an RQ
    return {"temperature": temp_from_hex(payload[2:])}


@parser_decorator  # co2_level
def parser_1298(payload, msg) -> Optional[dict]:
    #  I --- 37:258565 --:------ 37:258565 1298 003 0007D0
    FAULT_CODES = {
        "80": "sensor short circuit",
        "81": "sensor open",
        "83": "sensor value too high",
        "84": "sensor value too low",
        "85": "sensor unreliable",
    }
    if fault := FAULT_CODES.get(payload[:2]):
        return {"sensor_fault": fault}

    return {"co2_level": double(payload[2:])}


@parser_decorator  # indoor_humidity (Nuaire RH sensor)
def parser_12a0(payload, msg) -> Optional[dict]:
    # assert msg.len == 6 if type == ?? else 2, msg.len
    assert payload[:2] == "00", payload[:2]  # domain?

    FAULT_CODES_RHUM = {
        "EF": "RH sensor not available ",
        "F0": "RH sensor short circuit ",
        "F1": "RH sensor open ",
        "F2": "RH sensor not available",
        "F3": "RH sensor value too high ",
        "F4": "RH sensor value too low ",
        "F5": "RH sensor unreliable ",
    }  # relative humidity sensor

    assert payload[2:4] in FAULT_CODES_RHUM or int(payload[2:4], 16) <= 100
    if fault := FAULT_CODES_RHUM.get(payload[2:4]):
        return {"sensor_fault": fault}

    # FAULT_CODES_TEMP = {
    #     "7F": "sensor not available",
    #     "80": "sensor short circuit",
    #     "81": "sensor open",
    #     "82": "sensor not available",
    #     "83": "sensor value too high",
    #     "84": "sensor value too low",
    #     "85": "sensor unreliable",
    # }
    # assert payload[4:6] in FAULT_CODES_TEMP or ...
    # if (fault := FAULT_CODES_TEMP.get(payload[2:4])):
    #     return {"sensor_fault": fault}

    rh = int(payload[2:4], 16) / 100 if payload[2:4] != "EF" else None
    if msg.len == 2:
        return {"relative_humidity": rh}

    assert msg.len == 6, f"pkt length is {msg.len}, expected 6"
    return {
        "relative_humidity": rh,
        "temperature": temp_from_hex(payload[4:8]),
        "dewpoint_temp": temp_from_hex(payload[8:12]),
    }


@parser_decorator  # window_state (of a device/zone)
def parser_12b0(payload, msg) -> Optional[dict]:
    assert payload[2:] in ("0000", "C800", "FFFF"), payload[2:]  # "FFFF" means N/A

    return {
        "window_open": bool_from_hex(payload[2:4]),
    }


@parser_decorator  # displayed temperature (on a TR87RF bound to a RFG100)
def parser_12c0(payload, msg) -> Optional[dict]:

    if payload[2:4] == "80":
        temp = None
    elif payload[4:] == "00":  # units are 1.0 F
        temp = int(payload[2:4], 16)
    else:  # if payload[4:] == "01":  # units are 0.5 C
        temp = int(payload[2:4], 16) / 2

    return {
        "temperature": temp,
        "units": {"00": "Fahrenheit", "01": "Celsius"}[payload[4:]],
    }


@parser_decorator  # hvac_12C8
def parser_12c8(payload, msg) -> Optional[dict]:
    #  I --- 37:261128 --:------ 37:261128 12C8 003 000040
    assert payload[2:4] == "00"
    return {"unknown": percent(payload[4:])}


@parser_decorator  # ch_pressure
def parser_1300(payload, msg) -> Optional[dict]:
    return {"pressure": temp_from_hex(payload[2:])}  # is 2's complement still


@parser_decorator  # system_sync
def parser_1f09(payload, msg) -> Optional[dict]:
    # 22:51:19.287 067  I --- --:------ --:------ 12:193204 1F09 003 010A69
    # 22:51:19.318 068  I --- --:------ --:------ 12:193204 2309 003 010866
    # 22:51:19.321 067  I --- --:------ --:------ 12:193204 30C9 003 0108C3

    assert msg.len == 3, f"length is {msg.len}, expecting 3"
    assert payload[:2] in ("00", "01", "F8", "FF")  # W/F8

    seconds = int(payload[2:6], 16) / 10
    next_sync = msg.dtm + td(seconds=seconds)

    return {
        "remaining_seconds": seconds,
        "_next_sync": dt.strftime(next_sync, "%H:%M:%S"),
    }


@parser_decorator  # dhw_mode
def parser_1f41(payload, msg) -> Optional[dict]:
    # 053 RP --- 01:145038 18:013393 --:------ 1F41 006 00FF00FFFFFF  # no stored DHW
    assert payload[4:6] in ZONE_MODE, f"{payload[4:6]} (0xjj)"
    assert payload[4:6] == "04" or msg.len == 6, f"{msg._pkt}: expected length 6"
    assert payload[4:6] != "04" or msg.len == 12, f"{msg._pkt}: expected length 12"
    assert (
        payload[6:12] == "FFFFFF"
    ), f"{msg._pkt}: expected FFFFFF instead of '{payload[6:12]}'"

    result = {
        "active": {"00": False, "01": True, "FF": None}[payload[2:4]],
        "mode": ZONE_MODE.get(payload[4:6]),
    }
    if payload[4:6] == "04":  # temporary_override
        result["until"] = dtm_from_hex(payload[12:24])

    # TODO: remove me...
    if TEST_MODE and msg.verb == W_:
        from .command import Command

        KEYS = ("active", "mode", "until")
        cmd = Command.set_dhw_mode(
            msg.dst.id, **{k: v for k, v in result.items() if k in KEYS}
        )
        assert cmd.payload == payload, cmd.payload
    # TODO: remove me...

    return result


@parser_decorator  # rf_bind
def parser_1fc9(payload, msg) -> list:
    #  I is missing?
    #  W --- 10:048122 01:145038 --:------ 1FC9 006 003EF028BBFA
    #  I --- 01:145038 10:048122 --:------ 1FC9 006 00FFFF06368E

    #  I --- 07:045960 --:------ 07:045960 1FC9 012 0012601CB388001FC91CB388
    #  W --- 01:145038 07:045960 --:------ 1FC9 006 0010A006368E
    #  I --- 07:045960 01:145038 --:------ 1FC9 006 0012601CB388

    #  I --- 01:145038 --:------ 01:145038 1FC9 018 FA000806368EFC3B0006368EFA1FC906368E
    #  W --- 13:081807 01:145038 --:------ 1FC9 006 003EF0353F8F
    #  I --- 01:145038 13:081807 --:------ 1FC9 006 00FFFF06368E

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
        if seqx[:2] != "90":
            assert seqx[6:] == payload[6:12]  # all with same controller
        if seqx[:2] not in (
            "90",
            "F9",
            "FA",
            "FB",
            "FC",
            "FF",
        ):  # or: not in DOMAIN_TYPE_MAP: ??
            assert int(seqx[:2], 16) < msg._gwy.config.max_zones
        return [seqx[:2], seqx[2:6], hex_id_to_dec(seqx[6:])]

    assert msg.len >= 6 and msg.len % 6 == 0, msg.len  # assuming not RQ
    assert msg.verb in (I_, W_, RP), msg.verb  # devices will respond to a RQ!
    assert msg.src.id == hex_id_to_dec(payload[6:12]), payload[6:12]
    return [
        _parser(payload[i : i + 12])
        for i in range(0, len(payload), 12)
        # if payload[i : i + 2] != "90"  # TODO: WIP, what is 90?
    ]


@parser_decorator  # unknown
def parser_1fca(payload, msg) -> list:
    #  W --- 30:248208 34:021943 --:------ 1FCA 009 00-01FF-7BC990-FFFFFF  # sent x2

    return {
        "_unknown_0": payload[:2],
        "_unknown_1": payload[2:6],
        "device_id0": hex_id_to_dec(payload[6:12]),
        "device_id1": hex_id_to_dec(payload[12:]),
    }


@parser_decorator  # opentherm_sync, otb_sync
def parser_1fd4(payload, msg) -> Optional[dict]:
    return {"ticker": int(payload[2:], 16)}


@parser_decorator  # now_next_setpoint - Programmer/Hometronics
def parser_2249(payload, msg) -> Optional[dict]:
    # see: https://github.com/jrosser/honeymon/blob/master/decoder.cpp#L357-L370
    #  I --- 23:100224 --:------ 23:100224 2249 007 00-7EFF-7EFF-FFFF

    def _parser(seqx) -> dict:
        minutes = int(seqx[10:], 16)
        next_setpoint = msg.dtm + td(minutes=minutes)
        return {
            "setpoint_now": temp_from_hex(seqx[2:6]),
            "setpoint_next": temp_from_hex(seqx[6:10]),
            "minutes_remaining": minutes,
            "_next_setpoint": dt.strftime(next_setpoint, "%H:%M:%S"),
        }

    # the ST9520C can support two heating zones, so: msg.len in (7, 14)?
    if msg._has_array:
        return [
            {
                "zone_idx": payload[i : i + 2],
                **_parser(payload[i + 2 : i + 14]),
            }
            for i in range(0, len(payload), 14)
        ]

    return _parser(payload)


@parser_decorator  # ufh_setpoint, TODO: max length = 24?
def parser_22c9(payload, msg) -> list:
    def _parser(seqx) -> dict:
        assert seqx[10:] == "01", f"is {seqx[10:]}, expecting 01"

        return {
            "temp_low": temp_from_hex(seqx[2:6]),
            "temp_high": temp_from_hex(seqx[6:10]),
            "_unknown_0": seqx[10:],
        }

    if msg._has_array:
        return [
            {
                "ufh_idx": payload[i : i + 2],
                **_parser(payload[i : i + 12]),
            }
            for i in range(0, len(payload), 12)
        ]

    return _parser(payload)


@parser_decorator  # message_22d0 - system switch?
def parser_22d0(payload, msg) -> Optional[dict]:
    assert payload[:2] == "00", payload[:2]  # has no domain?
    assert payload[2:] == "000002", payload[2:]

    return {"unknown": payload[2:]}


@parser_decorator  # desired boiler setpoint
def parser_22d9(payload, msg) -> Optional[dict]:
    return {"setpoint": temp_from_hex(payload[2:6])}


@parser_decorator  # switch_mode
def parser_22f1(payload, msg) -> Optional[dict]:  # FIXME
    # 11:42:43.149 081  I 051 --:------ --:------ 49:086353 22F1 003 000304
    # 11:42:49.587 071  I 052 --:------ --:------ 49:086353 22F1 003 000404
    # 11:42:49.685 072  I 052 --:------ --:------ 49:086353 22F1 003 000404
    # 11:42:49.784 072  I 052 --:------ --:------ 49:086353 22F1 003 000404

    # assert payload[:2] == "00", payload[:2]  # has no domain
    assert int(payload[2:4], 16) <= int(payload[4:], 16), "step_idx not <= step_max"
    # assert payload[4:] in ("04", "0A"), payload[4:]

    bitmap = int(payload[2:4], 16)

    if bitmap in FAN_MODES:
        _action = {FAN_MODE: FAN_MODES[bitmap]}
    elif bitmap in {9, 10}:  # 00010001, 00010010
        _action = {HEATER_MODE: HEATER_MODES[bitmap]}
    else:
        _action = {}

    return {
        **_action,
        "step_idx": int(payload[2:4], 16),
        "step_max": int(payload[4:6], 16),
    }


@parser_decorator  # switch_boost
def parser_22f3(payload, msg) -> Optional[dict]:
    # NOTE: for boost timer for high
    assert payload[:2] == "00", payload[:2]  # has no domain
    assert payload[2:4] == "00", payload[2:4]
    assert payload[4:6] in ("0A", "14", "1E"), payload[4:6]  # 10, 20, 30

    if msg.len >= 3:
        result = {
            "mode": BOOST_TIMER,  # payload[2:4]
            "minutes": int(payload[4:6], 16),
        }

    if msg.len >= 5:
        result.update(parser_22f1(f"00{payload[6:10]}"))  # NOTE: a guess

    if msg.len >= 7:
        result.update({"_unknown": payload[10:]})

    return result


@parser_decorator  # setpoint (of device/zones)
def parser_2309(payload, msg) -> Union[dict, list, None]:

    if msg._has_array:
        return [
            {
                "zone_idx": payload[i : i + 2],
                "setpoint": temp_from_hex(payload[i + 2 : i + 6]),
            }
            for i in range(0, len(payload), 6)
        ]

    # RQ --- 22:131874 01:063844 --:------ 2309 003 020708
    if msg.verb == RQ and msg.len == 1:  # some RQs have a payload (why?)
        return {}

    result = {"setpoint": temp_from_hex(payload[2:])}

    # TODO: remove me...
    if TEST_MODE and msg.verb == W_:
        from .command import Command

        cmd = Command.set_zone_setpoint(msg.dst.id, payload[:2], result["setpoint"])
        assert cmd.payload == payload, cmd.payload
    # TODO: remove me...

    return result


@parser_decorator  # zone_mode  # TODO: messy
def parser_2349(payload, msg) -> Optional[dict]:
    # RQ --- 34:225071 30:258557 --:------ 2349 001 00
    # RP --- 30:258557 34:225071 --:------ 2349 013 007FFF00FFFFFFFFFFFFFFFFFF
    # RP --- 30:253184 34:010943 --:------ 2349 013 00064000FFFFFF00110E0507E5
    #  I --- 10:067219 --:------ 10:067219 2349 004 00000001

    if msg.verb == RQ and msg.len <= 2:  # some RQs have a payload (why?)
        return {}

    assert msg.len in (4, 7, 13), f"expected len 4,7,13, got {msg.len}"  # OTB has 4

    assert payload[6:8] in ZONE_MODE, f"unknown zone_mode: {payload[6:8]}"
    result = {
        "mode": ZONE_MODE.get(payload[6:8]),
        "setpoint": temp_from_hex(payload[2:6]),
    }

    if msg.len >= 7:  # has a dtm if mode == "04"
        if payload[8:14] == "FF" * 3:  # 03/FFFFFF OK if W?
            assert payload[6:8] != "03", f"{payload[6:8]} (0x00)"
        else:
            assert payload[6:8] == "03", f"{payload[6:8]} (0x01)"
            result["duration"] = int(payload[8:14], 16)

    if msg.len >= 13:
        if payload[14:] == "FF" * 6:
            assert payload[6:8] in ("00", "02"), f"{payload[6:8]} (0x02)"
            result["until"] = None  # TODO: remove?
        else:
            assert payload[6:8] != "02", f"{payload[6:8]} (0x03)"
            result["until"] = dtm_from_hex(payload[14:26])

    # TODO: remove me...
    if TEST_MODE and msg.verb == W_:
        from .command import Command

        KEYS = ("mode", "setpoint", "until", "duration")
        cmd = Command.set_zone_mode(
            msg.dst.id, payload[:2], **{k: v for k, v in result.items() if k in KEYS}
        )
        assert cmd.payload == payload, f"{cmd.payload}, not {payload}"
    # TODO: remove me...

    return result


@parser_decorator  # unknown
def parser_2389(payload, msg) -> Optional[dict]:
    return {"_unknown": temp_from_hex(payload[2:6])}


@parser_decorator  # hometronics _state (of unknwon)
def parser_2d49(payload, msg) -> dict:
    assert payload[2:] in ("0000", "C800"), payload[2:]  # would "FFFF" mean N/A?

    return {
        "_state": bool_from_hex(payload[2:4]),
    }


@parser_decorator  # system_mode
def parser_2e04(payload, msg) -> Optional[dict]:
    # if msg.verb == W_:

    #  I --— 01:020766 --:------ 01:020766 2E04 016 FFFFFFFFFFFFFF0007FFFFFFFFFFFF04  # Manual          # noqa: E501
    #  I --— 01:020766 --:------ 01:020766 2E04 016 FFFFFFFFFFFFFF0000FFFFFFFFFFFF04  # Automatic/times # noqa: E501

    if msg.len == 8:  # evohome
        assert payload[:2] in SYSTEM_MODE, payload[:2]  # TODO: check AutoWithReset

    elif msg.len == 16:  # hometronics, lifestyle ID:
        assert 0 <= int(payload[:2], 16) <= 15 or payload[:2] == "FF", payload[:2]
        assert payload[16:18] in ("00", "07"), payload[16:18]
        assert payload[30:32] == "04", payload[30:32]
        # assert False

    else:
        # msg.len in (8, 16)  # evohome 8, hometronics 16
        assert False, f"Packet length is {msg.len} (expecting 8, 16)"

    result = {
        "system_mode": SYSTEM_MODE.get(payload[:2], payload[:2]),
        "until": dtm_from_hex(payload[2:14]) if payload[14:16] != "00" else None,
    }  # TODO: double-check the final "00"

    # TODO: remove me...
    if TEST_MODE and msg.verb == W_:
        from .command import Command

        KEYS = ("system_mode", "until")
        cmd = Command.set_system_mode(
            msg.dst.id, **{k: v for k, v in result.items() if k in KEYS}
        )
        assert cmd.payload == payload, cmd.payload
    # TODO: remove me...

    return result


@parser_decorator  # current temperature (of device, zone/s)
def parser_30c9(payload, msg) -> Optional[dict]:

    if msg._has_array:
        return [
            {
                "zone_idx": payload[i : i + 2],
                "temperature": temp_from_hex(payload[i + 2 : i + 6]),
            }
            for i in range(0, len(payload), 6)
        ]

    # TODO: remove me...
    if TEST_MODE and msg.verb == RQ:
        from .command import Command

        cmd = Command.get_zone_temp(msg.dst.id, payload[:2])
        assert cmd.payload == payload, cmd.payload
    # TODO: remove me...

    return {"temperature": temp_from_hex(payload[2:])}


@parser_decorator  # unknown, from STA, VCE
def parser_3120(payload, msg) -> Optional[dict]:
    #  I --- 34:136285 --:------ 34:136285 3120 007 0070B0000000FF  # every ~3:45:00!
    # RP --- 20:008749 18:142609 --:------ 3120 007 0070B000009CFF
    #  I --- 37:258565 --:------ 37:258565 3120 007 0080B0010003FF

    assert payload[:2] == "00", f"byte 0: {payload[:2]}"
    assert payload[2:4] in ("00", "70", "80"), f"byte 1: {payload[2:4]}"
    assert payload[4:6] == "B0", f"byte 2: {payload[4:6]}"
    assert payload[6:8] in ("00", "01"), f"byte 3: {payload[6:8]}"
    assert payload[8:10] == "00", f"byte 4: {payload[8:10]}"
    assert payload[10:12] in ("00", "03", "9C"), f"byte 5: {payload[10:12]}"
    assert payload[12:] == "FF", f"byte 6: {payload[12:]}"
    return {
        "unknown_0": payload[2:10],
        "unknown_1": payload[10:12],
        "unknown_2": payload[12:],
    }


@parser_decorator  # datetime
def parser_313f(payload, msg) -> Optional[dict]:
    # 2020-03-28T03:59:21.315178 045 RP --- 01:158182 04:136513 --:------ 313F 009 00FC3500A41C0307E4  # noqa: E501
    # 2020-03-29T04:58:30.486343 045 RP --- 01:158182 04:136485 --:------ 313F 009 00FC8400C51D0307E4  # noqa: E501
    # 2020-05-31T11:37:50.351511 056  I --- --:------ --:------ 12:207082 313F 009 0038021ECB1F0507E4  # noqa: E501

    # https://www.automatedhome.co.uk/vbulletin/showthread.php?5085-My-HGI80-equivalent-Domoticz-setup-without-HGI80&p=36422&viewfull=1#post36422
    # every day at ~4am TRV/RQ->CTL/RP, approx 5-10secs apart (CTL respond at any time)

    assert msg.src.type != "01" or payload[2:4] in ("F0", "FC"), payload[2:4]  # DEX
    assert msg.src.type not in ("12", "22") or payload[2:4] == "38", payload[2:4]  # DEX
    assert msg.src.type != "30" or payload[2:4] == "60", payload[2:4]  # DEX

    result = {
        "datetime": dtm_from_hex(payload[4:18]),
        "is_dst": True if bool(int(payload[4:6], 16) & 0x80) else None,
        "_unknown_0": payload[2:4],
    }

    # TODO: remove me...
    if TEST_MODE and msg.verb == W_:
        from .command import Command

        cmd = Command.set_system_time(msg.dst.id, result["datetime"])
        payload = payload[:4] + "00" + payload[6:]  # 00, 01, 02, 03?
        assert cmd.payload == payload, cmd.payload
    # TODO: remove me...

    return result


@parser_decorator  # heat_demand (of device, FC domain) - valve status (%open)
def parser_3150(payload, msg) -> Union[list, dict, None]:
    # event-driven, and periodically; FC domain is maximum of all zones
    # TODO: all have a valid domain will UFC/CTL respond to an RQ, for FC, for a zone?

    #  I --- 04:136513 --:------ 01:158182 3150 002 01CA < often seen CA, artefact?

    def complex_index(seqx, msg) -> dict:
        # assert seqx[:2] == "FC" or (int(seqx[:2], 16) < MAX_ZONES)  # <5, 8 for UFC
        idx_name = "ufx_idx" if msg.src.type == "02" else "zone_idx"  # DEX
        return {"domain_id" if seqx[:1] == "F" else idx_name: seqx[:2]}

    if msg._has_array:
        return [
            {
                **complex_index(payload[i : i + 2], msg),
                **valve_demand(payload[i + 2 : i + 4]),
            }
            for i in range(0, len(payload), 4)
        ]

    return valve_demand(payload[2:])  # TODO: check UFC/FC is == CTL/FC


@parser_decorator  # ventilation state
def parser_31d9(payload, msg) -> Optional[dict]:
    # NOTE: I have a suspicion that Itho use 0x00-C8 for %, whilst Nuaire use 0x00-64
    assert payload[:2] in ("00", "01", "21"), payload[2:4]
    assert payload[2:4] in ("00", "06", "80"), payload[2:4]
    assert payload[4:6] == "FF" or int(payload[4:6], 16) <= 200, payload[4:6]

    bitmap = int(payload[2:4], 16)

    result = {
        "exhaust_fan_speed": percent(
            payload[4:6], high_res=True
        ),  # NOTE: is 31DA/payload[38:40]
        "passive": bool(bitmap & 0x02),
        "damper_only": bool(bitmap & 0x04),
        "filter_dirty": bool(bitmap & 0x20),
        "frost_cycle": bool(bitmap & 0x40),
        "has_fault": bool(bitmap & 0x80),
        "_bitmap_0": payload[2:4],
    }

    if msg.len == 3:  # usu: I -->20: (no seq#)
        return result

    assert msg.len == 17, msg.len  # usu: I 30:-->30:, (or 20:) with a seq#!
    assert payload[6:8] == "00", payload[6:8]
    assert payload[8:32] in ("00" * 12, "20" * 12), payload[8:32]
    assert payload[32:] == "00", payload[32:]

    return {
        **result,
        "_unknown_2": payload[6:8],
        "_unknown_3": payload[8:32],
        "_unknown_4": payload[32:],
    }


@parser_decorator  # ventilation state extended
def parser_31da(payload, msg) -> Optional[dict]:

    CODE_31DA_FAN_INFO = {
        0x00: "off",
        0x01: "speed 1",
        0x02: "speed 2",
        0x03: "speed 3",
        0x04: "speed 4",
        0x05: "speed 5",
        0x06: "speed 6",
        0x07: "speed 7",
        0x08: "speed 8",
        0x09: "speed 9",
        0x0A: "speed 10",
        0x0B: "speed 1 temporary override",
        0x0C: "speed 2 temporary override",
        0x0D: "speed 3 temporary override",
        0x0E: "speed 4 temporary override",
        0x0F: "speed 5 temporary override",
        0x10: "speed 6 temporary override",
        0x11: "speed 7 temporary override",
        0x12: "speed 8 temporary override",
        0x13: "speed 9 temporary override",
        0x14: "speed 10 temporary override",
        0x15: "away",
        0x16: "absolute minimum",
        0x17: "absolute maximum",
        0x18: "auto",
    }

    # I --- 37:261128 --:------ 37:261128 31DA 029 00004007D045EF7FFF7FFF7FFF7FFFF808EF03C8000000EFEF7FFF7FFF
    # I --- 37:053679 --:------ 37:053679 31DA 030 00EF007FFF41EF7FFF7FFF7FFF7FFFF800EF0134000000EFEF7FFF7FFF00

    assert payload[2:4] in ("00", "EF"), payload[2:4]
    assert payload[4:6] in ("00", "40"), payload[4:6]
    # assert payload[6:10] in ("07D0", "7FFF"), payload[6:10]
    assert payload[10:12] == "EF" or int(payload[10:12], 16) <= 100, payload[10:12]
    assert payload[12:14] == "EF", payload[12:14]
    assert payload[14:18] == "7FFF", payload[14:18]
    assert payload[18:22] == "7FFF", payload[18:22]
    assert payload[22:26] == "7FFF", payload[22:26]
    assert payload[26:30] == "7FFF", payload[26:30]
    assert payload[30:34] in ("0002", "F000", "F800", "F808", "7FFF"), payload[30:34]
    assert payload[34:36] == "EF", payload[34:36]
    assert payload[36:38] == "EF" or int(payload[36:38], 16) & 0x1F <= 0x18, payload[
        36:38
    ]
    assert payload[38:40] in ("EF", "FF") or int(payload[38:40], 16) <= 200, payload[
        38:40
    ]
    assert payload[40:42] in ("00", "EF", "FF"), payload[40:42]
    # assert payload[42:46] == "0000", payload[42:46]
    assert payload[46:48] in ("00", "EF"), payload[46:48]
    assert payload[48:50] == "EF", payload[48:50]
    assert payload[50:54] == "7FFF", payload[50:54]
    assert payload[54:58] == "7FFF", payload[54:58]  # or: FFFF?

    return {
        "air_quality": percent(payload[2:4]),
        "air_quality_base": int(payload[4:6], 16),  # NOTE: 12C8/payload[4:6]
        "co2_level": double(payload[6:10]),  # ppm NOTE: 1298/payload[2:6]
        "indoor_humidity": percent(payload[10:12], high_res=False),  # TODO: 12A0?
        "outdoor_humidity": percent(payload[12:14], high_res=False),
        "exhaust_temperature": double(payload[14:18], factor=100),
        "supply_temperature": double(payload[18:22], factor=100),
        "indoor_temperature": double(payload[22:26], factor=100),
        "outdoor_temperature": double(payload[26:30], factor=100),  # TODO: 1290?
        "speed_cap": int(payload[30:34], 16),
        "bypass_pos": percent(payload[34:36]),
        "fan_info": CODE_31DA_FAN_INFO[int(payload[36:38], 16) & 0x1F],
        "exhaust_fan_speed": percent(
            payload[38:40], high_res=True
        ),  # NOTE: 31D9/payload[4:6]
        "supply_fan_speed": percent(payload[40:42], high_res=True),
        "remaining_time": double(payload[42:46]),  # mins NOTE: 22F3/payload[2:6]
        "post_heat": percent(payload[46:48], high_res=False),
        "pre_heat": percent(payload[48:50], high_res=False),
        "supply_flow": double(payload[50:54], factor=100),  # L/sec
        "exhaust_flow": double(payload[54:58], factor=100),  # L/sec
    }


@parser_decorator  # ventilation heater?
def parser_31e0(payload, msg) -> dict:
    """Notes are.

    van means “of”.
    - 0 = min. van min. potm would be:
    - 0 = minimum of minimum potentiometer

    See: https://www.industrialcontrolsonline.com/honeywell-t991a
    - modulates air temperatures in ducts

    case 0x31E0:  ' 12768:
    {
        string str4;
        unchecked
        {
            result.Fan = Conversions.ToString((double)(int)data[checked(start + 1)] / 2.0);
            str4 = "";
        }
        str4 = (data[start + 2] & 0xF) switch
        {
            0 => str4 + "0 = min. potm. ",
            1 => str4 + "0 = min. van min. potm ",
            2 => str4 + "0 = min. fan ",
            _ => "",
        };
        switch (data[start + 2] & 0xF0)
        {
        case 16:
            str4 += "100 = max. potm";
            break;
        case 32:
            str4 += "100 = max. van max. potm ";
            break;
        case 48:
            str4 += "100 = max. fan ";
            break;
        }
        result.Data = str4;
        break;
    }
    """
    #  I --- 32:168240 30:079129 --:------ 31E0 004 00-00-00-FF
    #  I --- 32:166025 --:------ 30:079129 31E0 004 00-00-00-00
    #  I --- 32:168240 30:079129 --:------ 31E0 004 00-00-00-FF
    #  I --- 32:168090 30:082155 --:------ 31E0 004 00-00-C8-00

    return {
        "active": bool_from_hex(payload[4:6]),
        "_unknown_0": payload[:4],
        "unknown_2": payload[6:],
    }


@parser_decorator  # supplied boiler water (flow) temp
def parser_3200(payload, msg) -> Optional[dict]:
    return {"temperature": temp_from_hex(payload[2:])}


@parser_decorator  # return (boiler) water temp
def parser_3210(payload, msg) -> Optional[dict]:
    return {"temperature": temp_from_hex(payload[2:])}


@parser_decorator  # opentherm_msg
def parser_3220(payload, msg) -> Optional[dict]:

    try:
        ot_type, ot_id, ot_value, ot_schema = decode_frame(payload[2:10])
    except AssertionError as e:
        raise AssertionError(f"OpenTherm: {e}")
    except ValueError as e:
        raise InvalidPayloadError(f"OpenTherm: {e}")

    # NOTE: Unknown-DataId isn't an invalid payload & is useful to train the OTB device
    if ot_schema is None and ot_type != "Unknown-DataId":
        raise InvalidPayloadError(f"OpenTherm: Unknown data-id: {ot_id}")

    result = {
        MSG_ID: ot_id,
        MSG_TYPE: ot_type,
        MSG_NAME: ot_value.pop(MSG_NAME, None),
    }

    if msg.verb == RQ:  # RQs have a context: msg_id (and a payload)
        assert (
            ot_type != "Read-Data" or payload[6:10] == "0000"  # likely true for RAMSES
        ), f"OpenTherm: Invalid msg-type|data-value: {ot_type}|{payload[6:10]}"

        if ot_type != "Read-Data":
            assert ot_type in (
                "Write-Data",
                "Invalid-Data",
            ), f"OpenTherm: Invalid msg-type for RQ: {ot_type}"

            result.update(ot_value)  # TODO: find some of these packets to review

    else:  # if msg.verb == RP:
        _LIST = ("Data-Invalid", "Unknown-DataId", "-reserved-")
        assert ot_type not in _LIST or payload[6:10] in (
            "0000",
            "FFFF",
        ), f"OpenTherm: Invalid msg-type|data-value: {ot_type}|{payload[6:10]}"

        if ot_type not in _LIST:
            assert ot_type in (
                "Read-Ack",
                "Write-Ack",
            ), f"OpenTherm: Invalid msg-type for RP: {ot_type}"

            result.update(ot_value)

    result[MSG_DESC] = ot_schema.get(EN)
    return result


# @parser_decorator  # R8810A/20A
# def parser_3221(payload, msg) -> Optional[dict]:

#     # 2021-11-03T09:55:43.112792 071 RP --- 10:052644 18:198151 --:------ 3221 002 000F
#     # 2021-11-02T05:15:55.767108 046 RP --- 10:048122 18:006402 --:------ 3221 002 0000


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

    def complex_index(payload, msg) -> dict:  # has complex idx
        if (
            msg.verb == I_ and msg.src.type in ("01", "23") and msg.src is msg.dst
        ):  # DEX
            assert payload[:2] == "FC"
            return {"domain_id": "FC"}
        assert payload[:2] == "00"
        return {}

    assert msg.len == 2, msg.len
    assert payload[:2] == {"01": "FC", "13": "00", "23": "FC"}.get(
        msg.src.type, "00"
    )  # DEX
    assert payload[2:] == "C8", payload[2:]  # Could it be a percentage?

    return {
        **complex_index(payload[:2], msg),
        "actuator_sync": bool_from_hex(payload[2:]),
    }


@parser_decorator  # actuator_state
def parser_3ef0(payload, msg) -> dict:

    if msg.src.type in "08":  # Honeywell Jasper ?HVAC, DEX
        assert msg.len == 20, f"expecting len 20, got: {msg.len}"
        return {
            "ordinal": f"0x{payload[2:8]}",
            "blob": payload[8:],
        }

    assert msg.len in (3, 6, 9)
    assert payload[:2] == "00", f"byte 1: {payload[:2]}"

    if msg.len == 3:  # I|BDR|003
        # .I --- 13:042805 --:------ 13:042805 3EF0 003 0000FF
        # .I --- 13:023770 --:------ 13:023770 3EF0 003 00C8FF
        assert payload[2:4] in ("00", "C8"), f"byte 1: {payload[2:4]}"
        assert payload[4:6] == "FF", f"byte 2: {payload[4:6]}"
        mod_level = percent(payload[2:4])

    if msg.len >= 6:  # RP|OTB|006 (to RQ|CTL/HGI/RFG)
        # RP --- 10:105624 01:133689 --:------ 3EF0 006 0000100000FF
        # RP --- 10:105624 01:133689 --:------ 3EF0 006 003B100C00FF
        assert payload[4:6] in ("10", "11"), f"byte 2: {payload[4:6]}"
        mod_level = percent(payload[2:4], high_res=False)

    result = {
        "modulation_level": mod_level,
        "_flags_0": payload[4:6],
    }

    if msg.len >= 6:  # RP|OTB|006 (to RQ|CTL/HGI/RFG)
        # RP --- 10:138822 01:187666 --:------ 3EF0 006 000110FA00FF  # ?corrupt

        # for OTB (there's no reliable) modulation_level <-> flame_state)
        assert int(payload[6:8], 16) & 0b11110000 == 0, f"byte 3: {payload[6:8]}"
        assert int(payload[8:10], 16) & 0b11110000 == 0, f"byte 4: {payload[8:10]}"
        assert payload[10:12] in ("00", "1C", "FF"), f"byte 5: {payload[10:12]}"

        result.update(
            {
                "_flags_3": flag8(payload[6:8]),
                "ch_enabled": bool(int(payload[6:8], 0x10) & 1 << 1),
                "dhw_active": bool(int(payload[6:8], 0x10) & 1 << 2),
                "flame_active": bool(int(payload[6:8], 0x10) & 1 << 3),
                "_unknown_4": payload[8:10],
                "_unknown_5": payload[10:12],  # rel_modulation?
            }
        )

    if msg.len >= 9:  # I/RP|OTB|009 (R8820A only?)
        assert int(payload[12:14], 16) & 0b11111100 == 0, f"byte 6: {payload[12:14]}"
        assert int(payload[12:14], 16) & 0b00000010 == 2, f"byte 6: {payload[12:14]}"
        assert 10 <= int(payload[14:16], 16) <= 90, f"byte 7: {payload[14:16]}"
        assert int(payload[16:18], 16) in (0, 100), f"byte 8: {payload[18:]}"

        result.update(
            {
                "_flags_6": flag8(payload[12:14]),
                "ch_active": bool(int(payload[12:14], 0x10) & 1 << 0),
                "ch_setpoint": int(payload[14:16], 0x10),
                "max_rel_modulation": percent(payload[16:18], high_res=False),
            }
        )

    return result


@parser_decorator  # actuator_cycle
def parser_3ef1(payload, msg) -> dict:

    if msg.src.type == "08":  # Honeywell Jasper ?HVAC, DEX
        assert msg.len == 18, f"expecting len 18, got: {msg.len}"
        return {
            "ordinal": f"0x{payload[2:8]}",
            "blob": payload[8:],
        }

    if msg.src.type == "31":  # and msg.len == 12:  # or (12, 20) Japser ?HVAC, DEX
        assert msg.len == 12, f"expecting len 12, got: {msg.len}"
        return {
            "ordinal": f"0x{payload[2:8]}",
            "blob": payload[8:],
        }

    if payload[12:] == "FF":  # is BDR
        # assert (
        #     re.compile(r"^00[0-9A-F]{10}FF").match(payload)
        # ), "doesn't match: " + r"^00[0-9A-F]{10}FF"
        assert int(payload[2:6], 16) <= 7200, payload[2:6]
        # assert payload[6:10] in ("87B3", "9DFA", "DCE1", "E638", "F8F7") or (
        #     int(payload[6:10], 16) <= 7200
        # ), payload[6:10]
        assert percent(payload[10:12]) in (0, 1), payload[10:12]

    else:  # is OTB?
        # assert (
        #     re.compile(r"^00[0-9A-F]{10}10").match(payload)
        # ), "doesn't match: " + r"^00[0-9A-F]{10}10"
        assert payload[2:6] == "7FFF", payload[2:6]
        assert payload[6:10] == "003C", payload[6:10]  # 1 minute
        assert percent(payload[10:12]) <= 1, payload[10:12]

    cycle_countdown = None if payload[2:6] == "7FFF" else int(payload[2:6], 16)

    return {
        "modulation_level": percent(payload[10:12]),
        "actuator_countdown": int(payload[6:10], 16),
        "cycle_countdown": cycle_countdown,
        "_unknown_0": payload[12:],
    }


# @parser_decorator  # faked puzzle pkt shouldn't be decorated
def parser_7fff(payload, msg) -> Optional[dict]:

    if payload[:2] != "00":
        _LOGGER.debug("Invalid/deprecated Puzzle packet")
        return {
            "msg_type": payload[:2],
            "payload": str_from_hex(payload[2:]),
        }

    if payload[2:4] not in LOOKUP_PUZZ:
        _LOGGER.debug("Invalid/deprecated Puzzle packet")
        return {
            "msg_type": payload[2:4],
            "message": str_from_hex(payload[4:]),
        }

    result = {}
    if payload[2:4] != "13":
        dtm = dt.fromtimestamp(int(payload[4:16], 16) / 1000)
        result["datetime"] = dtm.isoformat(timespec="milliseconds")

    msg_type = LOOKUP_PUZZ.get(payload[2:4], "message")

    if payload[2:4] == "11":
        msg = str_from_hex(payload[16:])
        result[msg_type] = f"{msg[:4]}|{msg[4:6]}|{msg[6:]}"

    elif payload[2:4] == "13":
        result[msg_type] = str_from_hex(payload[4:])

    else:
        result[msg_type] = str_from_hex(payload[16:])

    return {**result, "parser": f"v{VERSION}"}


@parser_decorator
def parser_unknown(payload, msg) -> Optional[dict]:
    # TODO: it may be useful to generically search payloads for hex_ids, commands, etc.

    if msg.len == 2 and payload[:2] == "00":
        return {
            "_value": {"00": False, "C8": True}.get(payload[2:], int(payload[2:], 16))
        }

    if msg.len == 3 and payload[:2] == "00":
        return {
            "_value": temp_from_hex(payload[2:]),
        }

    raise NotImplementedError


PAYLOAD_PARSERS = {
    k[7:].upper(): v
    for k, v in locals().items()
    if callable(v) and k.startswith("parser_") and k != "parser_unknown"
}

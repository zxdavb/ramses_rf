#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - payload processors."""

# Kudos & many thanks to:
# - Evsdd: 0404
# - Ierlandfan: 3150, 31D9, 31DA, others
# - ReneKlootwijk: 3EF0
# - brucemiranda: 3EF0, others

import logging
import re
from datetime import datetime as dt
from datetime import timedelta as td
from typing import Optional, Union

from .address import hex_id_to_dev_id
from .const import (
    DEV_ROLE,
    DEV_ROLE_MAP,
    DEV_TYPE_MAP,
    FAN_MODE,
    FAN_MODES,
    FAULT_DEVICE_CLASS,
    FAULT_STATE,
    FAULT_TYPE,
    HEATER_MODE,
    HEATER_MODES,
    SYS_MODE_MAP,
    SZ_ACTUATOR,
    SZ_AIR_QUALITY,
    SZ_AIR_QUALITY_BASE,
    SZ_BYPASS_POSITION,
    SZ_CHANGE_COUNTER,
    SZ_CO2_LEVEL,
    SZ_DATETIME,
    SZ_DEVICE_CLASS,
    SZ_DEVICE_ID,
    SZ_DEVICE_ROLE,
    SZ_DEVICES,
    SZ_DOMAIN_ID,
    SZ_DURATION,
    SZ_EXHAUST_FAN_SPEED,
    SZ_EXHAUST_FLOW,
    SZ_EXHAUST_TEMPERATURE,
    SZ_FAN_INFO,
    SZ_FRAG_LENGTH,
    SZ_FRAG_NUMBER,
    SZ_FRAGMENT,
    SZ_INDOOR_HUMIDITY,
    SZ_INDOOR_TEMPERATURE,
    SZ_IS_DST,
    SZ_LANGUAGE,
    SZ_MODE,
    SZ_NAME,
    SZ_OUTDOOR_HUMIDITY,
    SZ_OUTDOOR_TEMPERATURE,
    SZ_PAYLOAD,
    SZ_POST_HEAT,
    SZ_PRE_HEAT,
    SZ_PRESSURE,
    SZ_RELAY_DEMAND,
    SZ_REMAINING_TIME,
    SZ_SETPOINT,
    SZ_SPEED_CAP,
    SZ_SUPPLY_FAN_SPEED,
    SZ_SUPPLY_FLOW,
    SZ_SUPPLY_TEMPERATURE,
    SZ_SYSTEM_MODE,
    SZ_TEMPERATURE,
    SZ_TOTAL_FRAGS,
    SZ_UFH_IDX,
    SZ_UNKNOWN,
    SZ_UNTIL,
    SZ_VALUE,
    SZ_WINDOW_OPEN,
    SZ_ZONE_CLASS,
    SZ_ZONE_IDX,
    SZ_ZONE_MASK,
    SZ_ZONE_TYPE,
    ZON_MODE_MAP,
    ZON_ROLE_MAP,
    __dev_mode__,
)
from .exceptions import InvalidPayloadError
from .fingerprint import check_signature
from .helpers import (
    bool_from_hex,
    date_from_hex,
    double,
    dtm_from_hex,
    dts_from_hex,
    flag8,
    percent,
    str_from_hex,
    temp_from_hex,
    valve_demand,
)
from .opentherm import EN, MSG_DESC, MSG_ID, MSG_NAME, MSG_TYPE, OtMsgType, decode_frame
from .version import VERSION

# skipcq: PY-W2000
from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    F8,
    F9,
    FA,
    FB,
    FC,
    FF,
)

_INFORM_DEV_MSG = "Support the development of ramses_rf by reporting this packet"

LOOKUP_PUZZ = {
    "10": "engine",  # .    # version str, e.g. v0.14.0
    "11": "impersonating",  # pkt header, e.g. 30C9| I|03:123001 (15 characters, packed)
    "12": "message",  # .   # message only, max len is 16 ascii characters
    "13": "message",  # .   # message only, but without a timestamp, max len 22 chars
    "7F": "null",  # .      # packet is null / was nullified: payload to be ignored
}  # "00" is reserved

DEV_MODE = __dev_mode__ and False
TEST_MODE = False  # enable to test constructors (usu. W)

_LOGGER = _PKT_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


def parser_decorator(fnc):
    def wrapper(payload, msg, **kwargs):
        result = fnc(payload, msg, **kwargs)
        if isinstance(result, dict) and msg.seqn.isnumeric():  # 22F1/3
            result["seqx_num"] = msg.seqn
        return result

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
        SZ_PAYLOAD: "-".join((payload[:2], payload[2:6], payload[6:8], payload[8:])),
    }


@parser_decorator  # outdoor_sensor (outdoor_weather / outdoor_temperature)
def parser_0002(payload, msg) -> Optional[dict]:
    # seen with: 03:125829, 03:196221, 03:196196, 03:052382, 03:201498, 03:201565:
    #  I 000 03:201565 --:------ 03:201565 0002 004 03020105  # no zone_idx, domain_id

    # is it CODE_IDX_COMPLEX:
    #  - 02...... for outside temp?
    #  - 03...... for other stuff?

    if msg.src.type == DEV_TYPE_MAP.HCW:  # payload[2:] == DEV_TYPE_MAP.HCW, DEX
        assert payload == "03020105"
        return {f"_{SZ_UNKNOWN}": payload}

    # if payload[6:] == "02":  # msg.src.type == DEV_TYPE_MAP.OUT:
    return {
        SZ_TEMPERATURE: temp_from_hex(payload[2:6]),
        f"_{SZ_UNKNOWN}": payload[6:],
    }


@parser_decorator  # zone_name
def parser_0004(payload, msg) -> Optional[dict]:
    # RQ payload is zz00; limited to 12 chars in evohome UI? if "7F"*20: not a zone

    return {} if payload[4:] == "7F" * 20 else {SZ_NAME: str_from_hex(payload[4:])}


@parser_decorator  # system_zones (add/del a zone?)
def parser_0005(payload, msg) -> Union[dict, list[dict]]:  # TODO: needs a cleanup
    #  I --- 01:145038 --:------ 01:145038 0005 004 00000100
    # RP --- 02:017205 18:073736 --:------ 0005 004 0009001F
    #  I --- 34:064023 --:------ 34:064023 0005 012 000A0000-000F0000-00100000

    def _parser(seqx) -> dict:
        if msg.src.type == DEV_TYPE_MAP.UFC:  # DEX, or use: seqx[2:4] == ...
            zone_mask = flag8(seqx[6:8], lsb=True)
        elif msg.len == 3:  # ATC928G1000 - 1st gen monochrome model, max 8 zones
            zone_mask = flag8(seqx[4:6], lsb=True)
        else:
            zone_mask = flag8(seqx[4:6], lsb=True) + flag8(seqx[6:8], lsb=True)
        zone_class = ZON_ROLE_MAP.get(seqx[2:4], DEV_ROLE_MAP[seqx[2:4]])
        return {
            SZ_ZONE_TYPE: seqx[2:4],
            SZ_ZONE_MASK: zone_mask,
            SZ_ZONE_CLASS: zone_class,
        }

    if msg.verb == RQ:  # RQs have a context: zone_type
        return {SZ_ZONE_TYPE: payload[2:4], SZ_ZONE_CLASS: DEV_ROLE_MAP[payload[2:4]]}

    if msg._has_array:
        assert (
            msg.verb == I_ and msg.src.type == DEV_TYPE_MAP.RND
        ), f"{msg!r} # expecting I/{DEV_TYPE_MAP.RND}:"  # DEX
        return [_parser(payload[i : i + 8]) for i in range(0, len(payload), 8)]

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
        SZ_CHANGE_COUNTER: int(payload[4:], 16),
        "_header": payload[:4],
    }


@parser_decorator  # relay_demand (domain/zone/device)
def parser_0008(payload, msg) -> Optional[dict]:
    # https://www.domoticaforum.eu/viewtopic.php?f=7&t=5806&start=105#p73681
    # e.g. Electric Heat Zone

    if msg.src.type == DEV_TYPE_MAP.JST and msg.len == 13:  # Honeywell Japser, DEX
        assert msg.len == 13, "expecting length 13"
        return {
            "ordinal": f"0x{payload[2:8]}",
            "blob": payload[8:],
        }

    return {SZ_RELAY_DEMAND: percent(payload[2:4])}


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
        assert seqx[:2] in (F9, FC) or int(seqx[:2], 16) < msg._gwy.config.max_zones
        return {
            SZ_DOMAIN_ID if seqx[:1] == "F" else SZ_ZONE_IDX: seqx[:2],
            "failsafe_enabled": {"00": False, "01": True}.get(seqx[2:4]),
            f"{SZ_UNKNOWN}_0": seqx[4:],
        }

    if msg._has_array:
        return [_parser(payload[i : i + 6]) for i in range(0, len(payload), 6)]

    return {
        "failsafe_enabled": {"00": False, "01": True}.get(payload[2:4]),
        f"{SZ_UNKNOWN}_0": payload[4:],
    }


@parser_decorator  # zone_params (zone_config)
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
            f"_{SZ_UNKNOWN}_bitmap": f"0b{bitmap:08b}",  # TODO: try W with this
        }  # cannot determine zone_type from this information

    if msg._has_array:  # NOTE: these arrays can span 2 pkts!
        return [
            {
                SZ_ZONE_IDX: payload[i : i + 2],
                **_parser(payload[i : i + 12]),
            }
            for i in range(0, len(payload), 12)
        ]

    if msg.verb == RQ and msg.len <= 2:  # some RQs have a payload (why?)
        return {}

    assert msg.len == 6, f"{msg!r} # expecting length 006"
    return _parser(payload)


@parser_decorator  # zone_devices
def parser_000c(payload, msg) -> Optional[dict]:
    #  I --- 34:092243 --:------ 34:092243 000C 018 00-0A-7F-FFFFFF 00-0F-7F-FFFFFF 00-10-7F-FFFFFF  # noqa: E501
    # RP --- 01:145038 18:013393 --:------ 000C 006 00-00-00-10DAFD
    # RP --- 01:145038 18:013393 --:------ 000C 012 01-00-00-10DAF5 01-00-00-10DAFB

    def complex_idx(seqx, msg) -> dict:  # complex index
        """domain_id, zone_idx, or ufx_idx|zone_idx."""

        # TODO: 000C to a UFC should be ufh_ifx, not zone_idx
        if msg.src.type == DEV_TYPE_MAP.UFC:  # DEX
            assert int(seqx, 16) < 8, f"invalid ufh_idx: '{seqx}' (0x00)"
            return {
                SZ_UFH_IDX: seqx,
                SZ_ZONE_IDX: None if payload[4:6] == "7F" else payload[4:6],
            }

        if payload[2:4] in (DEV_ROLE_MAP.DHW, DEV_ROLE_MAP.HTG):
            assert (
                int(seqx, 16) < 1 if payload[2:4] == DEV_ROLE_MAP.DHW else 2
            ), f"invalid _idx: '{seqx}' (0x01)"
            return {SZ_DOMAIN_ID: FA if payload[:2] == "00" else F9}

        if payload[2:4] == DEV_ROLE_MAP.APP:
            assert int(seqx, 16) < 1, f"invalid _idx: '{seqx}' (0x02)"
            return {SZ_DOMAIN_ID: FC}

        assert (
            int(seqx, 16) < msg._gwy.config.max_zones
        ), f"invalid zone_idx: '{seqx}' (0x03)"
        return {SZ_ZONE_IDX: seqx}

    def _parser(seqx) -> dict:  # TODO: assumption that all id/idx are same is wrong!
        assert (
            seqx[:2] == payload[:2]
        ), f"idx != {payload[:2]} (seqx = {seqx}), short={is_short_000C(payload)}"
        assert int(seqx[:2], 16) < msg._gwy.config.max_zones
        assert seqx[4:6] == "7F" or seqx[6:] != "F" * 6
        return {hex_id_to_dev_id(seqx[6:12]): seqx[4:6]}

    def is_short_000C(payload) -> bool:
        """Return True if it is a short 000C (element length is 5, not 6)."""

        if (pkt_len := len(payload)) != 72:
            return pkt_len % 12 != 0

        # 0608-001099C3 0608-001099C5 0608-001099BF 0608-001099BE 0608-001099BD 0608-001099BC  # len(element) = 6
        # 0508-00109901 0800-10990208 0010-99030800 1099-04080010 9905-08001099 0608-00109907  # len(element) = 5
        elif all(payload[i : i + 4] == payload[:4] for i in range(12, pkt_len, 12)):
            return False  # len(element) = 6 (12)

        # 06 08-001099C3 06-08001099 C5-06080010 99-BF060800 10-99BE0608 00-1099BD06 08-001099BC  # len(element) = 6
        # 05 08-00109901 08-00109902 08-00109903 08-00109904 08-00109905 08-00109906 08-00109907  # len(element) = 5
        elif all(payload[i : i + 2] == payload[2:4] for i in range(12, pkt_len, 10)):
            return True  # len(element) = 5 (10)

        raise InvalidPayloadError("Unable to determine element length")  # return None

    if payload[2:4] == DEV_ROLE_MAP.HTG and payload[:2] == "01":
        dev_role = DEV_ROLE_MAP[DEV_ROLE.HT1]
    else:
        dev_role = DEV_ROLE_MAP[payload[2:4]]

    result = {
        SZ_ZONE_TYPE: payload[2:4],
        **complex_idx(payload[:2], msg),
        SZ_DEVICE_ROLE: dev_role,
    }
    if msg.verb == RQ:  # RQs have a context: index, zone_type, payload is iitt
        return result

    # NOTE: Both these are valid! So collision when len = 036!
    # RP --- 01:239474 18:198929 --:------ 000C 012 06-00-00119A99 06-00-00119B21
    # RP --- 01:069616 18:205592 --:------ 000C 011 01-00-00121B54    00-00121B52
    # RP --- 01:239700 18:009874 --:------ 000C 018 07-08-001099C3 07-08-001099C5 07-08-001099BF
    # RP --- 01:059885 18:010642 --:------ 000C 016 00-00-0011EDAA    00-0011ED92    00-0011EDA0

    devs = (
        [_parser(payload[:2] + payload[i : i + 10]) for i in range(2, len(payload), 10)]
        if is_short_000C(payload)
        else [_parser(payload[i : i + 12]) for i in range(0, len(payload), 12)]
    )

    return {
        **result,
        SZ_DEVICES: [k for d in devs for k, v in d.items() if v != "7F"],
    }


@parser_decorator  # unknown_000e, from STA
def parser_000e(payload, msg) -> Optional[dict]:

    assert payload in ("000000", "000014"), _INFORM_DEV_MSG

    return {
        SZ_PAYLOAD: payload,
    }


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
        SZ_LANGUAGE: str_from_hex(payload[2:6]),
        f"_{SZ_UNKNOWN}_0": payload[6:],
    }


@parser_decorator  # unknown_0150, from OTB
def parser_0150(payload, msg) -> Optional[dict]:

    assert payload == "000000", _INFORM_DEV_MSG

    return {
        SZ_PAYLOAD: payload,
    }


@parser_decorator  # unknown_01d0, from a HR91 (when its buttons are pushed)
def parser_01d0(payload, msg) -> Optional[dict]:
    # 23:57:28.869 045  W --- 04:000722 01:158182 --:------ 01D0 002 0003
    # 23:57:28.931 045  I --- 01:158182 04:000722 --:------ 01D0 002 0003
    # 23:57:31.581 048  W --- 04:000722 01:158182 --:------ 01E9 002 0003
    # 23:57:31.643 045  I --- 01:158182 04:000722 --:------ 01E9 002 0000
    # 23:57:31.749 050  W --- 04:000722 01:158182 --:------ 01D0 002 0000
    # 23:57:31.811 045  I --- 01:158182 04:000722 --:------ 01D0 002 0000

    assert payload[2:] in ("00", "03"), _INFORM_DEV_MSG
    return {
        f"{SZ_UNKNOWN}_0": payload[2:],
    }


@parser_decorator  # unknown_01e9, from a HR91 (when its buttons are pushed)
def parser_01e9(payload, msg) -> Optional[dict]:
    # 23:57:31.581348 048  W --- 04:000722 01:158182 --:------ 01E9 002 0003
    # 23:57:31.643188 045  I --- 01:158182 04:000722 --:------ 01E9 002 0000

    assert payload[2:] in ("00", "03"), _INFORM_DEV_MSG
    return {
        f"{SZ_UNKNOWN}_0": payload[2:],
    }


@parser_decorator  # zone_schedule (fragment)
def parser_0404(payload, msg) -> Optional[dict]:
    # Retreival of Zone schedule (NB: 20)
    # RQ --- 30:185469 01:037519 --:------ 0404 007 00-20-0008-00-0100
    # RP --- 01:037519 30:185469 --:------ 0404 048 00-20-0008-29-0103-62...
    # RQ --- 30:185469 01:037519 --:------ 0404 007 00-20-0008-00-0203
    # RP --- 01:037519 30:185469 --:------ 0404 048 00-20-0008-29-0203-4D...
    # RQ --- 30:185469 01:037519 --:------ 0404 007 00-20-0008-00-0303
    # RP --- 01:037519 30:185469 --:------ 0404 038 00-20-0008-1F-0303-C1...

    # Retreival of DHW schedule (NB: 23)
    # RQ --- 30:185469 01:037519 --:------ 0404 007 00-23-0008-00-0100
    # RP --- 01:037519 30:185469 --:------ 0404 048 00-23-0008-29-0103-68...
    # RQ --- 30:185469 01:037519 --:------ 0404 007 00-23-0008-00-0203
    # RP --- 01:037519 30:185469 --:------ 0404 048 00-23-0008-29-0203-ED...
    # RQ --- 30:185469 01:037519 --:------ 0404 007 00-23-0008-00-0303
    # RP --- 01:037519 30:185469 --:------ 0404 014 00-23-0008-07-0303-1F...

    def _context(seqx) -> dict:
        return {
            SZ_FRAG_NUMBER: int(seqx[10:12], 16),
            SZ_TOTAL_FRAGS: int(seqx[12:], 16),
            SZ_FRAG_LENGTH: int(seqx[8:10], 16),
        }

    if msg.verb == RQ:  # RQs have a context: index|fragment_idx
        return _context(payload)

    return {
        **_context(payload[:14]),
        SZ_FRAGMENT: payload[14:],
    }


@parser_decorator  # system_fault
def parser_0418(payload, msg) -> Optional[dict]:
    # RP --- 01:145038 18:013393 --:------ 0418 022 000000B0000000000000000000007FFFFF7000000000  # noqa: E501
    # RP --- 01:145038 18:013393 --:------ 0418 022 000036B0010000000000108000007FFFFF7000000000  # noqa: E501
    # RP --- 01:145038 18:013393 --:------ 0418 022 000000B00401010000008694A3CC7FFFFF70000ECC8A  # noqa: E501
    #  I --- 01:037519 --:------ 01:037519 0418 022 000000B0050000000000239581877FFFFF7000000001  # Evotouch Battery Error  # noqa: E501
    # RP --- 01:037519 18:140805 --:------ 0418 022 004024B0060006000000CB94A112FFFFFF70007AD47D  # noqa: E501
    #                                                 0     0   1     1            3        3
    #                                                 2     8   2     8            0        8

    # assert int(payload[4:6], 16) < 64, f"Unexpected log_idx: 0x{payload[4:6]}"

    if dts_from_hex(payload[18:30]) is None:  # a null log entry
        return {"log_entry": None}

    try:
        assert payload[2:4] in FAULT_STATE, f"fault state: {payload[2:4]}"
        assert payload[8:10] in FAULT_TYPE, f"fault type: {payload[8:10]}"
        assert payload[12:14] in FAULT_DEVICE_CLASS, f"device class: {payload[12:14]}"
        # 1C: 'Comms fault, Actuator': seen with boiler relays
        assert int(payload[10:12], 16) < msg._gwy.config.max_zones or (
            payload[10:12] in ("1C", F9, FA, FC)
        ), f"domain id: {payload[10:12]}"
    except AssertionError as exc:
        _LOGGER.warning(
            f"{msg!r} < {_INFORM_DEV_MSG} ({exc}), with a photo of your fault log"
        )

    result = {
        "timestamp": dts_from_hex(payload[18:30]),
        "state": FAULT_STATE.get(payload[2:4], payload[2:4]),
        "type": FAULT_TYPE.get(payload[8:10], payload[8:10]),
        SZ_DEVICE_CLASS: FAULT_DEVICE_CLASS.get(payload[12:14], payload[12:14]),
    }

    if payload[10:12] == FC and result[SZ_DEVICE_CLASS] == SZ_ACTUATOR:
        result[SZ_DEVICE_CLASS] = DEV_ROLE_MAP[DEV_ROLE.APP]  # actual evohome UI
    elif payload[10:12] == FA and result[SZ_DEVICE_CLASS] == SZ_ACTUATOR:
        result[SZ_DEVICE_CLASS] = DEV_ROLE_MAP[DEV_ROLE.HTG]  # speculative
    elif payload[10:12] == F9 and result[SZ_DEVICE_CLASS] == SZ_ACTUATOR:
        result[SZ_DEVICE_CLASS] = DEV_ROLE_MAP[DEV_ROLE.HT1]  # speculative

    if payload[12:14] != "00":  # TODO: Controller
        key_name = (
            SZ_ZONE_IDX
            if int(payload[10:12], 16) < msg._gwy.config.max_zones
            else SZ_DOMAIN_ID
        )
        result.update({key_name: payload[10:12]})

    if payload[38:] == "000002":  # "00:000002 for Unknown?
        result.update({SZ_DEVICE_ID: None})
    elif payload[38:] not in ("000000", "000001"):  # "00:000001 for Controller?
        result.update({SZ_DEVICE_ID: hex_id_to_dev_id(payload[38:])})

    result.update(
        {
            f"_{SZ_UNKNOWN}_3": payload[6:8],  # B0 ?priority
            f"_{SZ_UNKNOWN}_7": payload[14:18],  # 0000
            f"_{SZ_UNKNOWN}_15": payload[30:38],  # FFFF7000/1/2
        }
    )

    return {"log_entry": [v for k, v in result.items() if k != "log_idx"]}


@parser_decorator  # unknown_042f, from STA, VMS
def parser_042f(payload, msg) -> Optional[dict]:
    #  I --- 34:064023 --:------ 34:064023 042F 008 00-0000-0023-0023-F5
    #  I --- 34:064023 --:------ 34:064023 042F 008 00-0000-0024-0024-F5
    #  I --- 34:064023 --:------ 34:064023 042F 008 00-0000-0025-0025-F5
    #  I --- 34:064023 --:------ 34:064023 042F 008 00-0000-0026-0026-F5
    #  I --- 34:092243 --:------ 34:092243 042F 008 00-0001-0021-0022-01
    #  I     34:011469 --:------ 34:011469 042F 008 00-0001-0003-0004-BC

    #  I --- 32:168090 --:------ 32:168090 042F 009 00-0000100F00105050
    #  I --- 32:166025 --:------ 32:166025 042F 009 00-050E0B0C00111470

    return {
        "counter_1": f"0x{payload[2:6]}",
        "counter_3": f"0x{payload[6:10]}",
        "counter_5": f"0x{payload[10:14]}",
        f"{SZ_UNKNOWN}_7": f"0x{payload[14:]}",
    }


@parser_decorator  # TODO: unknown_0b04, from THM (only when its a CTL?)
def parser_0b04(payload, msg) -> Optional[dict]:
    #  I --- --:------ --:------ 12:207082 0B04 002 00C8  # batch of 3, every 24h

    return {
        f"{SZ_UNKNOWN}_1": payload[2:],
    }


@parser_decorator  # mixvalve_config (zone), NB: mixvalves are listen-only
def parser_1030(payload, msg) -> Optional[dict]:
    def _parser(seqx) -> dict:
        assert seqx[2:4] == "01", seqx[2:4]

        param_name = {
            "C8": "max_flow_setpoint",  # 55 (0-99) C
            "C9": "min_flow_setpoint",  # 15 (0-50) C
            "CA": "valve_run_time",  # 150 (0-240) sec, aka actuator_run_time
            "CB": "pump_run_time",  # 15 (0-99) sec
            "CC": f"_{SZ_UNKNOWN}_0",  # ?boolean?
        }[seqx[:2]]

        return {param_name: int(seqx[4:], 16)}

    assert msg.len == 1 + 5 * 3, msg.len
    assert payload[30:] in ("00", "01"), payload[30:]

    params = [_parser(payload[i : i + 6]) for i in range(2, len(payload), 6)]
    return {k: v for x in params for k, v in x.items()}


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
    return {SZ_SETPOINT: temp_from_hex(payload[2:])}


@parser_decorator  # unknown_1090 (non-Evohome, e.g. ST9520C)
def parser_1090(payload, msg) -> dict:
    # 14:08:05.176 095 RP --- 23:100224 22:219457 --:------ 1090 005 007FFF01F4
    # 18:08:05.809 095 RP --- 23:100224 22:219457 --:------ 1090 005 007FFF01F4

    # this is an educated guess
    assert msg.len == 5, _INFORM_DEV_MSG
    assert int(payload[:2], 16) < 2, _INFORM_DEV_MSG

    return {
        f"{SZ_TEMPERATURE}_0": temp_from_hex(payload[2:6]),
        f"{SZ_TEMPERATURE}_1": temp_from_hex(payload[6:10]),
    }


@parser_decorator  # unknown_1098, from OTB
def parser_1098(payload, msg) -> Optional[dict]:

    assert payload == "00C8", _INFORM_DEV_MSG

    return {
        f"_{SZ_PAYLOAD}": payload,
        f"_{SZ_VALUE}": {"00": False, "C8": True}.get(
            payload[2:], percent(payload[2:])
        ),
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
        result = {SZ_SETPOINT: None if setpoint == 255 else setpoint}  # 30.0-85.0 C
    if msg.len >= 4:
        result["overrun"] = int(payload[6:8], 16)  # 0-10 minutes
    if msg.len >= 6:
        result["differential"] = temp_from_hex(payload[8:12])  # 1.0-10.0 C

    return result


@parser_decorator  # unknown_10b0, from OTB
def parser_10b0(payload, msg) -> Optional[dict]:

    assert payload == "0000", _INFORM_DEV_MSG

    return {
        f"_{SZ_PAYLOAD}": payload,
        f"_{SZ_VALUE}": {"00": False, "C8": True}.get(
            payload[2:], percent(payload[2:])
        ),
    }


@parser_decorator  # device_info
def parser_10e0(payload, msg) -> Optional[dict]:
    assert msg.len in (19, 28, 29, 30, 36, 38), msg.len  # >= 19, msg.len

    payload = re.sub("(00)*$", "", payload)  # remove trailing 00s
    assert len(payload) >= 18 * 2

    # if DEV_MODE:  # TODO
    try:  # DEX
        check_signature(msg.src.type, payload[2:20])
    except ValueError as exc:
        _LOGGER.warning(
            f"{msg!r} < {_INFORM_DEV_MSG}, with the make/model of device: {msg.src} ({exc})"
        )

    description, _, unknown = payload[36:].partition("00")
    assert msg.verb == RP or not unknown, f"{unknown}"

    result = {
        "date_2": date_from_hex(payload[20:28]) or "0000-00-00",  # manufactured?
        "date_1": date_from_hex(payload[28:36]) or "0000-00-00",  # firmware?
        # # "manufacturer_group": payload[2:6],  # default is: 0001
        # "manufacturer_sub_id": payload[6:8],
        "product_id": payload[8:10],  # if CH/DHW: matches device_type (sometimes)
        # "software_ver_id": payload[10:12],
        # "list_ver_id": payload[12:14],  # if FF/01 is CH/DHW, then 01/FF
        "oem_code": payload[14:16],  # 00/FF is CH/DHW, 01/6x is HVAC
        # # "additional_ver_a": payload[16:18],
        # # "additional_ver_b": payload[18:20],
        "description": bytearray.fromhex(description).decode(),
    }
    if msg.verb == RP and unknown:  # TODO: why only OTBs do this?
        result[f"_{SZ_UNKNOWN}"] = unknown
    return result


@parser_decorator  # device_id
def parser_10e1(payload, msg) -> Optional[dict]:
    return {SZ_DEVICE_ID: hex_id_to_dev_id(payload[2:])}


@parser_decorator  # unknown_10e2 - HVAC
def parser_10e2(payload, msg) -> Optional[dict]:
    # .I --- --:------ --:------ 20:231151 10E2 003 00AD74  # every 2 minutes

    assert payload[:2] == "00", _INFORM_DEV_MSG
    assert len(payload) == 6, _INFORM_DEV_MSG

    return {
        "counter": int(payload[2:], 16),
    }


@parser_decorator  # tpi_params (domain/zone/device)  # FIXME: a bit messy
def parser_1100(payload, msg) -> Optional[dict]:
    def complex_idx(seqx) -> dict:
        return {SZ_DOMAIN_ID: seqx} if seqx[:1] == "F" else {}  # only FC

    if msg.src.type == DEV_TYPE_MAP.JIM:  # Honeywell Japser, DEX
        assert msg.len == 19, msg.len
        return {
            "ordinal": f"0x{payload[2:8]}",
            "blob": payload[8:],
        }

    if msg.verb == RQ and msg.len == 1:  # some RQs have a payload (why?)
        return complex_idx(payload[:2])

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
            f"_{SZ_UNKNOWN}_0": payload[8:10],  # always 00, FF?
        }

    result = _parser(payload)

    if msg.len > 5:
        assert (
            payload[10:14] == "7FFF" or 1.5 <= temp_from_hex(payload[10:14]) <= 3.0
        ), f"unexpected value for PBW: {payload[10:14]}"

        result.update(
            {
                "proportional_band_width": temp_from_hex(payload[10:14]),
                f"_{SZ_UNKNOWN}_1": payload[14:],  # always 01?
            }
        )

    return {
        **complex_idx(payload[:2]),
        **result,
    }


@parser_decorator  # unknown_11f0, from heatpump relay
def parser_11f0(payload, msg) -> Optional[dict]:

    assert payload == "000009000000000000", _INFORM_DEV_MSG

    return {
        SZ_PAYLOAD: payload,
    }


@parser_decorator  # dhw cylinder temperature
def parser_1260(payload, msg) -> Optional[dict]:
    return {SZ_TEMPERATURE: temp_from_hex(payload[2:])}


@parser_decorator  # outdoor humidity
def parser_1280(payload, msg) -> Optional[dict]:
    # educated guess - this packet never seen in the wild

    rh = percent(payload[2:4], high_res=False)
    if msg.len == 2:
        return {SZ_OUTDOOR_HUMIDITY: rh}

    return {
        SZ_OUTDOOR_HUMIDITY: rh,
        SZ_TEMPERATURE: temp_from_hex(payload[4:8]),
        "dewpoint_temp": temp_from_hex(payload[8:12]),
    }


@parser_decorator  # outdoor temperature
def parser_1290(payload, msg) -> Optional[dict]:
    # evohome responds to an RQ
    return {SZ_TEMPERATURE: temp_from_hex(payload[2:])}


@parser_decorator  # co2_level
def parser_1298(payload, msg) -> Optional[dict]:
    #  I --- 37:258565 --:------ 37:258565 1298 003 0007D0
    FAULT_CODES_CO2 = {
        "80": "sensor short circuit",
        "81": "sensor open",
        "83": "sensor value too high",
        "84": "sensor value too low",
        "85": "sensor unreliable",
    }
    if fault := FAULT_CODES_CO2.get(payload[:2]):
        return {"sensor_fault": fault}

    return {SZ_CO2_LEVEL: double(payload[2:])}


@parser_decorator  # indoor_humidity
def parser_12a0(payload, msg) -> Optional[dict]:

    FAULT_CODES_RHUM = {
        "EF": "sensor not available",
        "F0": "sensor short circuit",
        "F1": "sensor open",
        "F2": "sensor not available",
        "F3": "sensor value too high",
        "F4": "sensor value too low",
        "F5": "sensor unreliable",
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

    rh = percent(payload[2:4], high_res=False)
    if msg.len == 2:
        return {SZ_INDOOR_HUMIDITY: rh}

    return {
        SZ_INDOOR_HUMIDITY: rh,
        SZ_TEMPERATURE: temp_from_hex(payload[4:8]),
        "dewpoint_temp": temp_from_hex(payload[8:12]),
    }


@parser_decorator  # window_state (of a device/zone)
def parser_12b0(payload, msg) -> Optional[dict]:
    assert payload[2:] in ("0000", "C800", "FFFF"), payload[2:]  # "FFFF" means N/A

    return {
        SZ_WINDOW_OPEN: bool_from_hex(payload[2:4]),
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
        SZ_TEMPERATURE: temp,
        "units": {"00": "Fahrenheit", "01": "Celsius"}[payload[4:6]],
        f"_{SZ_UNKNOWN}_6": payload[6:],
    }


@parser_decorator  # air_quality, HVAC
def parser_12c8(payload, msg) -> Optional[dict]:
    # 04:50:01.616 080  I --- 37:261128 --:------ 37:261128 31DA 029 00A740-05133AEF7FFF7FFF7FFF7FFFF808EF1805000000EFEF7FFF7FFF  # noqa: E501
    # 04:50:01.717 078  I --- 37:261128 --:------ 37:261128 12C8 003 00A740
    # 04:50:31.443 078  I --- 37:261128 --:------ 37:261128 31DA 029 007A40-05993AEF7FFF7FFF7FFF7FFFF808EF1807000000EFEF7FFF7FFF  # noqa: E501
    # 04:50:31.544 078  I --- 37:261128 --:------ 37:261128 12C8 003 007A40
    # 04:51:40.262 079  I --- 37:261128 --:------ 37:261128 31DA 029 009540-054B3AEF7FFF7FFF7FFF7FFFF808EF180E000000EFEF7FFF7FFF  # noqa: E501
    # 04:51:41.192 078  I --- 37:261128 --:------ 37:261128 12C8 003 009540

    return {
        SZ_AIR_QUALITY: percent(payload[2:4]),  # 31DA[2:4]
        SZ_AIR_QUALITY_BASE: int(payload[4:6], 16),  # 31DA[4:6]
    }


@parser_decorator  # dhw_flow_rate
def parser_12f0(payload, msg) -> Optional[dict]:
    return {"dhw_flow_rate": temp_from_hex(payload[2:])}


@parser_decorator  # ch_pressure
def parser_1300(payload, msg) -> Optional[dict]:
    return {SZ_PRESSURE: temp_from_hex(payload[2:])}  # is 2's complement still


@parser_decorator  # message_1470 (HVAC)
def parser_1470(payload, msg) -> Optional[dict]:
    assert payload[2:] == "B30E60802A0108", _INFORM_DEV_MSG
    return {SZ_VALUE: payload[2:]}


@parser_decorator  # system_sync
def parser_1f09(payload, msg) -> Optional[dict]:
    # 22:51:19.287 067  I --- --:------ --:------ 12:193204 1F09 003 010A69
    # 22:51:19.318 068  I --- --:------ --:------ 12:193204 2309 003 010866
    # 22:51:19.321 067  I --- --:------ --:------ 12:193204 30C9 003 0108C3

    assert msg.len == 3, f"length is {msg.len}, expecting 3"
    assert payload[:2] in ("00", "01", F8, FF)  # W/F8

    seconds = int(payload[2:6], 16) / 10
    next_sync = msg.dtm + td(seconds=seconds)

    return {
        "remaining_seconds": seconds,
        "_next_sync": dt.strftime(next_sync, "%H:%M:%S"),
    }


@parser_decorator  # dhw_mode
def parser_1f41(payload, msg) -> Optional[dict]:
    # 053 RP --- 01:145038 18:013393 --:------ 1F41 006 00FF00FFFFFF  # no stored DHW
    assert payload[4:6] in ZON_MODE_MAP, f"{payload[4:6]} (0xjj)"
    assert (
        payload[4:6] == ZON_MODE_MAP.TEMPORARY or msg.len == 6
    ), f"{msg!r}: expected length 6"
    assert (
        payload[4:6] != ZON_MODE_MAP.TEMPORARY or msg.len == 12
    ), f"{msg!r}: expected length 12"
    assert (
        payload[6:12] == "FFFFFF"
    ), f"{msg!r}: expected FFFFFF instead of '{payload[6:12]}'"

    result = {
        "active": {"00": False, "01": True, "FF": None}[payload[2:4]],
        SZ_MODE: ZON_MODE_MAP.get(payload[4:6]),
    }
    if payload[4:6] == ZON_MODE_MAP.TEMPORARY:  # temporary_override
        result[SZ_UNTIL] = dtm_from_hex(payload[12:24])

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

    # 049  I --- 01:145038 --:------ 01:145038 1FC9 018 F9-0008-06368E FC-3B00-06368E F9-1FC9-06368E  # noqa: E501

    # the new (heatpump-aware) BDR91:
    # 045 RP --- 13:035462 18:013393 --:------ 1FC9 018 00-3EF0-348A86 00-11F0-348A86 90-7FE1-DD6ABD  # noqa: E501

    def _parser(seqx) -> dict:
        if seqx[:2] not in ("90",):
            assert seqx[6:] == payload[6:12]  # all with same controller
        if seqx[:2] not in (
            "63",
            "67",
            "6C",
            "90",
            F9,
            FA,
            FB,
            FC,
            FF,
        ):  # or: not in DOMAIN_TYPE_MAP: ??
            assert int(seqx[:2], 16) < msg._gwy.config.max_zones
        return [seqx[:2], seqx[2:6], hex_id_to_dev_id(seqx[6:])]

    if payload == "00":
        return []

    assert msg.len >= 6 and msg.len % 6 == 0, msg.len  # assuming not RQ
    assert msg.verb in (I_, W_, RP), msg.verb  # devices will respond to a RQ!
    # assert (
    #     msg.src.id == hex_id_to_dev_id(payload[6:12])
    # ), f"{payload[6:12]} ({hex_id_to_dev_id(payload[6:12])})"  # NOTE: use_regex
    return [
        _parser(payload[i : i + 12])
        for i in range(0, len(payload), 12)
        # if payload[i : i + 2] != "90"  # TODO: WIP, what is 90?
    ]


@parser_decorator  # unknown_1fca, HVAC?
def parser_1fca(payload, msg) -> list:
    #  W --- 30:248208 34:021943 --:------ 1FCA 009 00-01FF-7BC990-FFFFFF  # sent x2

    return {
        f"_{SZ_UNKNOWN}_0": payload[:2],
        f"_{SZ_UNKNOWN}_1": payload[2:6],
        "device_id_0": hex_id_to_dev_id(payload[6:12]),
        "device_id_1": hex_id_to_dev_id(payload[12:]),
    }


@parser_decorator  # unknown_1fd0, from OTB
def parser_1fd0(payload, msg) -> Optional[dict]:

    assert payload == "0000000000000000", _INFORM_DEV_MSG

    return {
        SZ_PAYLOAD: payload,
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
                SZ_ZONE_IDX: payload[i : i + 2],
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
            f"_{SZ_UNKNOWN}_0": seqx[10:],
        }

    if msg._has_array:
        return [
            {
                SZ_UFH_IDX: payload[i : i + 2],
                **_parser(payload[i : i + 12]),
            }
            for i in range(0, len(payload), 12)
        ]

    return _parser(payload)


@parser_decorator  # unknown_22d0, HVAC system switch?
def parser_22d0(payload, msg) -> Optional[dict]:

    assert payload == "00000002", _INFORM_DEV_MSG

    return {
        SZ_PAYLOAD: payload[2:],
    }


@parser_decorator  # desired boiler setpoint
def parser_22d9(payload, msg) -> Optional[dict]:
    return {SZ_SETPOINT: temp_from_hex(payload[2:6])}


@parser_decorator  # fan_speed (switch_mode), HVAC
def parser_22f1(payload, msg) -> Optional[dict]:
    # Orcon wireless remote 15RF
    # I --- 37:171871 32:155617 --:------ 22F1 003 000307  # Mode 3: High // Stand 3 (position high)
    # I --- 37:171871 32:155617 --:------ 22F1 003 000207  # Mode 2: Med  // Stand 2 (position med)
    # I --- 37:171871 32:155617 --:------ 22F1 003 000107  # Mode 1: Low  // Stand 1 (position low)
    # I --- 37:171871 32:155617 --:------ 22F1 003 000007  # Absent mode  // Afwezig (absence mode, aka: weg/away) - low & doesn't respond to sensors
    # I --- 37:171871 32:155617 --:------ 22F1 003 000607  # Party/boost
    # I --- 37:171871 32:155617 --:------ 22F3 007 00023C03070000  # Timer (boost) mode // TIJDELIJKE stand (temporary) 60 min - high, then return to what was

    #  I 018 --:------ --:------ 39:159057 22F1 003 000204 # low
    #  I 016 --:------ --:------ 39:159057 22F1 003 000304 # medium
    #  I 017 --:------ --:------ 39:159057 22F1 003 000404 # high

    # Scheme x: 0|x standby/off, 1|x min, 2+|x rate as % of max (Itho?)
    # Scheme 4: 0|4 standby/off, 1|4 auto, 2|4 low, 3|4 med, 4|4 high/boost
    # Scheme 7: only seen 000[2345]07 -- ? off, auto, rate x/4, +3 others?
    # Scheme A: only seen 000[239A]0A -- ? off, auto, rate x/x, and?

    try:
        assert int(payload[2:4], 16) <= int(payload[4:], 16), "byte 1: idx > max"
        assert payload[4:] in ("04", "07", "0A"), f"byte 2: {payload[4:]}"
    except AssertionError as exc:
        _LOGGER.warning(f"{msg!r} < {_INFORM_DEV_MSG} ({exc})")

    bitmap = int(payload[2:4], 16)  # & 0b11110000

    if bitmap in FAN_MODES:
        _action = {FAN_MODE: FAN_MODES[bitmap]}
    elif bitmap in {9, 10}:  # 0b00010001, 0b00010010
        _action = {HEATER_MODE: HEATER_MODES[bitmap]}
    else:
        _action = {}

    step_idx = int(payload[2:4], 16)  # & 0x07
    step_max = int(payload[4:6], 16)  # & 0x07

    return {
        "rate": step_idx / step_max,
        "_step_idx": step_idx,
        "_step_max": step_max,
        **_action,
    }


@parser_decorator  # switch_boost, HVAC
def parser_22f3(payload, msg) -> Optional[dict]:
    #  I 019 --:------ --:------ 39:159057 22F3 003 00000A  # 10 mins
    #  I 022 --:------ --:------ 39:159057 22F3 003 000014  # 20 mins
    #  I 026 --:------ --:------ 39:159057 22F3 003 00001E  # 30 mins
    #  I --- 29:151550 29:237552 --:------ 22F3 007 00023C-0304-0000  # 60 mins
    #  I --- 29:162374 29:237552 --:------ 22F3 007 00020F-0304-0000  # 15 mins
    #  I --- 29:162374 29:237552 --:------ 22F3 007 00020F-0304-0000  # 15 mins

    # NOTE: for boost timer for high
    try:
        assert payload[2:4] in ("00", "02"), f"byte 1: {flag8(payload[2:4])}"
        assert msg.len <= 7 or payload[14:] == "0000", f"byte 7: {payload[14:]}"
    except AssertionError as exc:
        _LOGGER.warning(f"{msg!r} < {_INFORM_DEV_MSG} ({exc})")

    new_speed = {  # from now, until timer expiry
        0x00: "fan_boost",  # #    set fan off, or 'boost' mode?
        0x01: "per_request",  # #  set fan as per payload[6:10]?
        0x02: "per_vent_speed",  # set fan as per current fan mode/speed?
    }.get(int(payload[2:4], 0x10) & 0x07)

    fallback_speed = {  # after timer expiry
        0x08: "fan_off",  # #      set fan off?
        0x10: "per_request",  # #  set fan as per payload[6:10], or payload[10:]?
        0x18: "per_vent_speed",  # set fan as per current fan mode/speed?
    }.get(int(payload[2:4], 0x10) & 0x38)

    units = {
        0x00: "minutes",
        0x40: "hours",
        0x80: "index",  # TODO: days, day-of-week, day-of-month?
    }.get(int(payload[2:4], 0x10) & 0xC0)

    duration = int(payload[4:6], 16) * 60 if units == "hours" else int(payload[4:6], 16)

    if msg.len >= 3:
        result = {
            "minutes" if units != "index" else "index": duration,
            "flags": flag8(payload[2:4]),
            "_new_speed_mode": new_speed,
            "_fallback_speed_mode": fallback_speed,
        }

    if msg.len >= 5 and payload[6:10] != "0000":  # new speed?
        result["rate"] = parser_22f1(f"00{payload[6:10]}", msg).get("rate")

    if msg.len >= 7:  # fallback speed?
        result.update({f"_{SZ_UNKNOWN}_5": payload[10:]})

    return result


@parser_decorator  # bypass_mode, HVAC
def parser_22f7(payload, msg) -> Optional[dict]:
    # RQ --- 37:171871 32:155617 --:------ 22F7 001 00
    # RP --- 32:155617 37:171871 --:------ 22F7 003 00FF00  # alse: 000000, 00C8C8

    #  W --- 37:171871 32:155617 --:------ 22F7 003 0000EF  # bypass off
    #  I --- 32:155617 37:171871 --:------ 22F7 003 000000
    #  W --- 37:171871 32:155617 --:------ 22F7 003 00C8EF  # bypass on
    #  I --- 32:155617 37:171871 --:------ 22F7 003 00C800
    #  W --- 37:171871 32:155617 --:------ 22F7 003 00FFEF  # bypass auto
    #  I --- 32:155617 37:171871 --:------ 22F7 003 00FFC8

    result = {
        "bypass_mode": {"00": "off", "C8": "on", "FF": "auto"}.get(payload[2:4]),
    }
    if msg.verb != W_ or payload[4:] != "EF":
        result["bypass_state"] = {"00": "off", "C8": "on"}.get(payload[4:])

    return result


@parser_decorator  # setpoint (of device/zones)
def parser_2309(payload, msg) -> Union[dict, list, None]:

    if msg._has_array:
        return [
            {
                SZ_ZONE_IDX: payload[i : i + 2],
                SZ_SETPOINT: temp_from_hex(payload[i + 2 : i + 6]),
            }
            for i in range(0, len(payload), 6)
        ]

    # RQ --- 22:131874 01:063844 --:------ 2309 003 020708
    if msg.verb == RQ and msg.len == 1:  # some RQs have a payload (why?)
        return {}

    return {SZ_SETPOINT: temp_from_hex(payload[2:])}


@parser_decorator  # zone_mode  # TODO: messy
def parser_2349(payload, msg) -> Optional[dict]:
    # RQ --- 34:225071 30:258557 --:------ 2349 001 00
    # RP --- 30:258557 34:225071 --:------ 2349 013 007FFF00FFFFFFFFFFFFFFFFFF
    # RP --- 30:253184 34:010943 --:------ 2349 013 00064000FFFFFF00110E0507E5
    #  I --- 10:067219 --:------ 10:067219 2349 004 00000001

    if msg.verb == RQ and msg.len <= 2:  # some RQs have a payload (why?)
        return {}

    assert msg.len in (7, 13), f"expected len 7,13, got {msg.len}"

    assert payload[6:8] in ZON_MODE_MAP, f"{SZ_UNKNOWN} zone_mode: {payload[6:8]}"
    result = {
        SZ_MODE: ZON_MODE_MAP.get(payload[6:8]),
        SZ_SETPOINT: temp_from_hex(payload[2:6]),
    }

    if msg.len >= 7:  # has a dtm if mode == "04"
        if payload[8:14] == "FF" * 3:  # 03/FFFFFF OK if W?
            assert payload[6:8] != ZON_MODE_MAP.COUNTDOWN, f"{payload[6:8]} (0x00)"
        else:
            assert payload[6:8] == ZON_MODE_MAP.COUNTDOWN, f"{payload[6:8]} (0x01)"
            result[SZ_DURATION] = int(payload[8:14], 16)

    if msg.len >= 13:
        if payload[14:] == "FF" * 6:
            assert payload[6:8] in (
                ZON_MODE_MAP.FOLLOW,
                ZON_MODE_MAP.PERMANENT,
            ), f"{payload[6:8]} (0x02)"
            result[SZ_UNTIL] = None  # TODO: remove?
        else:
            assert payload[6:8] != ZON_MODE_MAP.PERMANENT, f"{payload[6:8]} (0x03)"
            result[SZ_UNTIL] = dtm_from_hex(payload[14:26])

    return result


@parser_decorator  # unknown_2389, from 03:
def parser_2389(payload, msg) -> Optional[dict]:

    return {
        f"_{SZ_UNKNOWN}": temp_from_hex(payload[2:6]),
    }


@parser_decorator  # unknown_2400, from OTB
def parser_2400(payload, msg) -> Optional[dict]:

    assert payload == "0000000F", _INFORM_DEV_MSG

    return {
        SZ_PAYLOAD: payload,
    }


@parser_decorator  # unknown_2401, from OTB
def parser_2401(payload, msg) -> Optional[dict]:

    try:
        assert payload[2:4] == "00", f"byte 1: {payload[2:4]}"
        assert int(payload[4:6], 16) & 0b11110000 == 0, f"byte 2: {flag8(payload[4:6])}"
        assert int(payload[6:], 0x10) <= 200, f"byte 3: {payload[6:]}"
    except AssertionError as exc:
        _LOGGER.warning(f"{msg!r} < {_INFORM_DEV_MSG} ({exc})")

    return {
        SZ_PAYLOAD: payload,
        "_value_2": int(payload[4:6], 0x10),
        "_flags_2": flag8(payload[4:6]),
        "_percent_3": percent(payload[6:]),
    }


@parser_decorator  # unknown_2410, from OTB
def parser_2410(payload, msg) -> Optional[dict]:

    assert payload == "00" * 12 + "010000000100000C", _INFORM_DEV_MSG

    return {
        SZ_PAYLOAD: payload,
    }


@parser_decorator  # unknown_2411, HVAC
def parser_2411(payload, msg) -> Optional[dict]:

    assert payload[:4] == "0000", _INFORM_DEV_MSG

    return {
        f"{SZ_VALUE}_1": payload[4:6],
        f"{SZ_VALUE}_2": payload[6:],
    }


@parser_decorator  # unknown_2420, from OTB
def parser_2420(payload, msg) -> Optional[dict]:

    assert payload == "00000010" + "00" * 34, _INFORM_DEV_MSG

    return {
        SZ_PAYLOAD: payload,
    }


@parser_decorator  # _state (of unknown), from hometronics controller
def parser_2d49(payload, msg) -> dict:

    assert payload[2:] in ("0000", "C800"), _INFORM_DEV_MSG

    return {
        "_state": bool_from_hex(payload[2:4]),
    }


@parser_decorator  # system_mode
def parser_2e04(payload, msg) -> Optional[dict]:
    # if msg.verb == W_:

    #  I --— 01:020766 --:------ 01:020766 2E04 016 FFFFFFFFFFFFFF0007FFFFFFFFFFFF04  # Manual          # noqa: E501
    #  I --— 01:020766 --:------ 01:020766 2E04 016 FFFFFFFFFFFFFF0000FFFFFFFFFFFF04  # Automatic/times # noqa: E501

    if msg.len == 8:  # evohome
        assert payload[:2] in SYS_MODE_MAP, f"Unknown system mode: {payload[:2]}"

    elif msg.len == 16:  # hometronics, lifestyle ID:
        assert 0 <= int(payload[:2], 16) <= 15 or payload[:2] == FF, payload[:2]
        assert payload[16:18] in (SYS_MODE_MAP.AUTO, SYS_MODE_MAP.CUSTOM), payload[
            16:18
        ]
        assert payload[30:32] == SYS_MODE_MAP.DAY_OFF, payload[30:32]
        # assert False

    else:
        # msg.len in (8, 16)  # evohome 8, hometronics 16
        assert False, f"Packet length is {msg.len} (expecting 8, 16)"

    return {
        SZ_SYSTEM_MODE: SYS_MODE_MAP[payload[:2]],
        SZ_UNTIL: dtm_from_hex(payload[2:14]) if payload[14:16] != "00" else None,
    }  # TODO: double-check the final "00"


@parser_decorator  # presence_detect, from HVAC sensor
def parser_2e10(payload, msg) -> Optional[dict]:

    assert payload in ("0001", "000100"), _INFORM_DEV_MSG

    return {
        "presence_detected": bool(payload[2:4]),
        f"_{SZ_UNKNOWN}_4": payload[4:],
    }


@parser_decorator  # current temperature (of device, zone/s)
def parser_30c9(payload, msg) -> Optional[dict]:

    if msg._has_array:
        return [
            {
                SZ_ZONE_IDX: payload[i : i + 2],
                SZ_TEMPERATURE: temp_from_hex(payload[i + 2 : i + 6]),
            }
            for i in range(0, len(payload), 6)
        ]

    return {SZ_TEMPERATURE: temp_from_hex(payload[2:])}


@parser_decorator  # unknown_3110 - HVAC
def parser_3110(payload, msg) -> Optional[dict]:

    try:
        assert payload[2:4] == "00", f"byte 1: {payload[2:4]}"
        assert int(payload[4:6], 16) <= 200, f"byte 2: {payload[4:6]}"
        assert payload[6:] in ("10", "20"), f"byte 3: {payload[6:]}"
    except AssertionError as exc:
        _LOGGER.warning(f"{msg!r} < {_INFORM_DEV_MSG} ({exc})")

    return {
        f"_{SZ_UNKNOWN}_1": payload[2:4],
        "_percent_2": percent(payload[4:6]),
        "_value_3": payload[6:],
    }


@parser_decorator  # unknown_3120, from STA, FAN
def parser_3120(payload, msg) -> Optional[dict]:
    #  I --- 34:136285 --:------ 34:136285 3120 007 0070B0000000FF  # every ~3:45:00!
    # RP --- 20:008749 18:142609 --:------ 3120 007 0070B000009CFF
    #  I --- 37:258565 --:------ 37:258565 3120 007 0080B0010003FF

    try:
        assert payload[:2] == "00", f"byte 0: {payload[:2]}"
        assert payload[2:4] in ("00", "70", "80"), f"byte 1: {payload[2:4]}"
        assert payload[4:6] == "B0", f"byte 2: {payload[4:6]}"
        assert payload[6:8] in ("00", "01"), f"byte 3: {payload[6:8]}"
        assert payload[8:10] == "00", f"byte 4: {payload[8:10]}"
        assert payload[10:12] in ("00", "03", "0A", "9C"), f"byte 5: {payload[10:12]}"
        assert payload[12:] == "FF", f"byte 6: {payload[12:]}"
    except AssertionError as exc:
        _LOGGER.warning(f"{msg!r} < {_INFORM_DEV_MSG} ({exc})")

    return {
        f"{SZ_UNKNOWN}_0": payload[2:10],
        f"{SZ_UNKNOWN}_5": payload[10:12],
        f"{SZ_UNKNOWN}_2": payload[12:],
    }


@parser_decorator  # datetime
def parser_313f(payload, msg) -> Optional[dict]:  # TODO: look for TZ
    # 2020-03-28T03:59:21.315178 045 RP --- 01:158182 04:136513 --:------ 313F 009 00FC3500A41C0307E4  # noqa: E501
    # 2020-03-29T04:58:30.486343 045 RP --- 01:158182 04:136485 --:------ 313F 009 00FC8400C51D0307E4  # noqa: E501
    # 2020-05-31T11:37:50.351511 056  I --- --:------ --:------ 12:207082 313F 009 0038021ECB1F0507E4  # noqa: E501

    # https://www.automatedhome.co.uk/vbulletin/showthread.php?5085-My-HGI80-equivalent-Domoticz-setup-without-HGI80&p=36422&viewfull=1#post36422
    # every day at ~4am TRV/RQ->CTL/RP, approx 5-10secs apart (CTL respond at any time)

    assert msg.src.type != DEV_TYPE_MAP.CTL or payload[2:4] in (
        "F0",
        "FC",
    ), f"{payload[2:4]} unexpected for CTL"  # DEX
    assert (
        msg.src.type not in (DEV_TYPE_MAP.DTS, DEV_TYPE_MAP.DT2) or payload[2:4] == "38"
    ), f"{payload[2:4]} unexpected for DTS"  # DEX
    # assert (
    #     msg.src.type != DEV_TYPE_MAP.FAN or payload[2:4] == "7C"
    # ), f"{payload[2:4]} unexpected for FAN"  # DEX
    assert (
        msg.src.type != DEV_TYPE_MAP.RFG or payload[2:4] == "60"
    ), "{payload[2:4]} unexpected for RFG"  # DEX

    return {
        SZ_DATETIME: dtm_from_hex(payload[4:18]),
        SZ_IS_DST: True if bool(int(payload[4:6], 16) & 0x80) else None,
        f"_{SZ_UNKNOWN}_0": payload[2:4],
    }


@parser_decorator  # heat_demand (of device, FC domain) - valve status (%open)
def parser_3150(payload, msg) -> Union[list, dict, None]:
    # event-driven, and periodically; FC domain is maximum of all zones
    # TODO: all have a valid domain will UFC/CTL respond to an RQ, for FC, for a zone?

    #  I --- 04:136513 --:------ 01:158182 3150 002 01CA < often seen CA, artefact?

    def complex_idx(seqx, msg) -> dict:
        # assert seqx[:2] == FC or (int(seqx[:2], 16) < MAX_ZONES)  # <5, 8 for UFC
        idx_name = "ufx_idx" if msg.src.type == DEV_TYPE_MAP.UFC else SZ_ZONE_IDX  # DEX
        return {SZ_DOMAIN_ID if seqx[:1] == "F" else idx_name: seqx[:2]}

    if msg._has_array:
        return [
            {
                **complex_idx(payload[i : i + 2], msg),
                **valve_demand(payload[i + 2 : i + 4]),
            }
            for i in range(0, len(payload), 4)
        ]

    return valve_demand(payload[2:])  # TODO: check UFC/FC is == CTL/FC


@parser_decorator  # ventilation state basic, HVAC
def parser_31d9(payload, msg) -> Optional[dict]:
    # NOTE: I have a suspicion that Itho use 0x00-C8 for %, whilst Nuaire use 0x00-64
    try:
        assert (
            payload[4:6] == "FF" or int(payload[4:6], 16) <= 200
        ), f"byte 2: {payload[4:6]}"
    except AssertionError as exc:
        _LOGGER.warning(f"{msg!r} < {_INFORM_DEV_MSG} ({exc})")

    bitmap = int(payload[2:4], 16)

    result = {
        SZ_EXHAUST_FAN_SPEED: percent(
            payload[4:6], high_res=True
        ),  # NOTE: is 31DA/payload[38:40]
        "passive": bool(bitmap & 0x02),
        "damper_only": bool(bitmap & 0x04),
        "filter_dirty": bool(bitmap & 0x20),
        "frost_cycle": bool(bitmap & 0x40),
        "has_fault": bool(bitmap & 0x80),
        "flags": flag8(payload[2:4]),
    }

    if msg.len == 3:  # usu: I -->20: (no seq#)
        return result

    try:
        assert payload[6:8] in ("00", "FE"), f"byte 3: {payload[6:8]}"
    except AssertionError as exc:
        _LOGGER.warning(f"{msg!r} < {_INFORM_DEV_MSG} ({exc})")

    result.update({f"_{SZ_UNKNOWN}_3": payload[6:8]})

    if msg.len == 4:  # usu: I -->20: (no seq#)
        return result

    try:
        assert payload[8:32] in ("00" * 12, "20" * 12), f"byte 4: {payload[8:32]}"
        assert payload[32:] in ("00", "08"), f"byte 16: {payload[32:]}"
    except AssertionError as exc:
        _LOGGER.warning(f"{msg!r} < {_INFORM_DEV_MSG} ({exc})")

    return {
        **result,
        # f"_{SZ_UNKNOWN}_4": payload[8:32],
        f"{SZ_UNKNOWN}_16": payload[32:],
    }


@parser_decorator  # ventilation state extended, HVAC
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
        0x19: "-unknown-",
        0x1A: "-unknown-",
        0x1B: "-unknown-",
        0x1C: "-unknown-",
        0x1D: "-unknown-",
        0x1E: "-unknown-",
        0x1F: "-unknown-",
    }

    # I --- 37:261128 --:------ 37:261128 31DA 029 00004007D045EF7FFF7FFF7FFF7FFFF808EF03C8000000EFEF7FFF7FFF
    # I --- 37:053679 --:------ 37:053679 31DA 030 00EF007FFF41EF7FFF7FFF7FFF7FFFF800EF0134000000EFEF7FFF7FFF00
    try:
        # assert (
        #     int(payload[2:4], 16) <= 200
        #     or int(payload[2:4], 16) & 0xF0 == 0xF0
        #     or payload[2:4] == "EF"
        # ), f"[2:4] {payload[2:4]}"
        assert payload[4:6] in ("00", "40"), payload[4:6]
        # assert payload[6:10] in ("07D0", "7FFF"), payload[6:10]
        assert payload[10:12] == "EF" or int(payload[10:12], 16) <= 100, payload[10:12]
        assert (
            payload[12:14] == "EF" or int(payload[12:14], 16) <= 100
        ), f"[12:14] {payload[10:12]}"
        # assert payload[14:18] == "7FFF", payload[14:18]
        # assert payload[18:22] == "7FFF", payload[18:22]
        # assert payload[22:26] == "7FFF", payload[22:26]
        # assert payload[26:30] == "7FFF", payload[26:30]
        # assert payload[30:34] in ("0002", "F000", "F800", "F808", "7FFF"), payload[30:34]
        # assert payload[34:36] == "EF", payload[34:36]
        assert (
            payload[36:38] == "EF" or int(payload[36:38], 16) & 0x1F <= 0x18
        ), payload[36:38]
        assert int(payload[38:40], 16) <= 200 or payload[38:40] in (
            "EF",
            "FF",
        ), payload[38:40]
        # assert payload[40:42] in ("00", "EF", "FF"), payload[40:42]
        # assert payload[42:46] == "0000", payload[42:46]
        assert payload[46:48] in ("00", "EF"), f"[46:48] {payload[46:48]}"
        # assert payload[48:50] == "EF", payload[48:50]
        # assert payload[50:54] == "7FFF", payload[50:54]
        # assert payload[54:58] == "7FFF", payload[54:58]  # or: FFFF?
    except AssertionError as exc:
        _LOGGER.warning(f"{msg!r} < {_INFORM_DEV_MSG} ({exc})")

    return {
        SZ_EXHAUST_FAN_SPEED: percent(payload[38:40]),  # 31D9[4:6]
        SZ_FAN_INFO: CODE_31DA_FAN_INFO[int(payload[36:38], 16) & 0x1F],  # 22F3-ish
        SZ_REMAINING_TIME: double(payload[42:46]),  # mins, 22F3[2:6]
        #
        SZ_AIR_QUALITY: percent(payload[2:4]),  # 12C8[2:4]
        SZ_AIR_QUALITY_BASE: int(payload[4:6], 16),  # 12C8[4:6]
        SZ_CO2_LEVEL: double(payload[6:10]),  # ppm, 1298[2:6]
        SZ_INDOOR_HUMIDITY: percent(payload[10:12], high_res=False),  # 12A0?
        SZ_OUTDOOR_HUMIDITY: percent(payload[12:14], high_res=False),
        SZ_EXHAUST_TEMPERATURE: double(payload[14:18], factor=100),
        SZ_SUPPLY_TEMPERATURE: double(payload[18:22], factor=100),
        SZ_INDOOR_TEMPERATURE: double(payload[22:26], factor=100),
        SZ_OUTDOOR_TEMPERATURE: double(payload[26:30], factor=100),  # 1290?
        SZ_SPEED_CAP: int(payload[30:34], 16),
        SZ_BYPASS_POSITION: percent(payload[34:36]),
        SZ_SUPPLY_FAN_SPEED: percent(payload[40:42]),
        SZ_POST_HEAT: percent(payload[46:48], high_res=False),
        SZ_PRE_HEAT: percent(payload[48:50], high_res=False),
        SZ_SUPPLY_FLOW: double(payload[50:54], factor=100),  # L/sec
        SZ_EXHAUST_FLOW: double(payload[54:58], factor=100),  # L/sec
    }


@parser_decorator  # vent_demand, HVAC
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
    #  I --- 29:146052 32:023459 --:------ 31E0 003 00-00-00
    #  I --- 29:146052 32:023459 --:------ 31E0 003 00-00-C8

    #  I --- 32:168240 30:079129 --:------ 31E0 004 00-00-00-FF
    #  I --- 32:168240 30:079129 --:------ 31E0 004 00-00-00-FF
    #  I --- 32:166025 --:------ 30:079129 31E0 004 00-00-00-00

    #  I --- 32:168090 30:082155 --:------ 31E0 004 00-00-C8-00
    #  I --- 37:258565 37:261128 --:------ 31E0 004 00-00-01-00

    return {
        "vent_demand": percent(payload[4:6]),
        "flags_1": payload[2:4],
        f"_{SZ_UNKNOWN}_3": payload[6:],
    }


@parser_decorator  # supplied boiler water (flow) temp
def parser_3200(payload, msg) -> Optional[dict]:
    return {SZ_TEMPERATURE: temp_from_hex(payload[2:])}


@parser_decorator  # return (boiler) water temp
def parser_3210(payload, msg) -> Optional[dict]:
    return {SZ_TEMPERATURE: temp_from_hex(payload[2:])}


@parser_decorator  # opentherm_msg, from OTB
def parser_3220(payload, msg) -> Optional[dict]:

    try:
        ot_type, ot_id, ot_value, ot_schema = decode_frame(payload[2:10])
    except AssertionError as exc:
        raise AssertionError(f"OpenTherm: {exc}") from exc
    except ValueError as exc:
        raise InvalidPayloadError(f"OpenTherm: {exc}") from exc

    # NOTE: Unknown-DataId isn't an invalid payload & is useful to train the OTB device
    if ot_schema is None and ot_type != OtMsgType.UNKNOWN_DATAID:
        raise InvalidPayloadError(f"OpenTherm: Unknown data-id: {ot_id}")

    result = {
        MSG_ID: ot_id,
        MSG_TYPE: ot_type,
        MSG_NAME: ot_value.pop(MSG_NAME, None),
    }

    if msg.verb == RQ:  # RQs have a context: msg_id (and a payload)
        assert (
            ot_type != OtMsgType.READ_DATA
            or payload[6:10] == "0000"  # likely true for RAMSES
        ), f"OpenTherm: Invalid msg-type|data-value: {ot_type}|{payload[6:10]}"

        if ot_type != OtMsgType.READ_DATA:
            assert ot_type in (
                OtMsgType.WRITE_DATA,
                OtMsgType.INVALID_DATA,
            ), f"OpenTherm: Invalid msg-type for RQ: {ot_type}"

            result.update(ot_value)  # TODO: find some of these packets to review

    else:  # if msg.verb == RP:
        _LIST = (OtMsgType.DATA_INVALID, OtMsgType.UNKNOWN_DATAID, OtMsgType.RESERVED)
        assert ot_type not in _LIST or payload[6:10] in (
            "0000",
            "FFFF",
        ), f"OpenTherm: Invalid msg-type|data-value: {ot_type}|{payload[6:10]}"

        if ot_type not in _LIST:
            assert ot_type in (
                OtMsgType.READ_ACK,
                OtMsgType.WRITE_ACK,
            ), f"OpenTherm: Invalid msg-type for RP: {ot_type}"

            result.update(ot_value)

        try:
            assert ot_id != 0 or (
                [result[SZ_VALUE][i] for i in (2, 3, 4, 5, 6, 7)] == [0] * 6
            ), result[SZ_VALUE]

            assert ot_id != 0 or (
                [result[SZ_VALUE][8 + i] for i in (0, 4, 5, 6, 7)] == [0] * 5
            ), result[SZ_VALUE]
        except AssertionError:
            _LOGGER.warning(
                f"{msg!r} < {_INFORM_DEV_MSG}, with a description of your system"
            )

    result[MSG_DESC] = ot_schema.get(EN)
    return result


@parser_decorator  # unknown_3221, from OTB
def parser_3221(payload, msg) -> Optional[dict]:

    # 2021-11-03T09:55:43.112792 071 RP --- 10:052644 18:198151 --:------ 3221 002 000F
    # 2021-11-02T05:15:55.767108 046 RP --- 10:048122 18:006402 --:------ 3221 002 0000

    assert int(payload[2:], 16) <= 0xC8, _INFORM_DEV_MSG

    return {
        f"_{SZ_PAYLOAD}": payload,
        SZ_VALUE: int(payload[2:], 16),
    }


@parser_decorator  # unknown_3223, from OTB
def parser_3223(payload, msg) -> Optional[dict]:

    assert int(payload[2:], 16) <= 0xC8, _INFORM_DEV_MSG

    return {
        f"_{SZ_PAYLOAD}": payload,
        SZ_VALUE: int(payload[2:], 16),
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

    def complex_idx(payload, msg) -> dict:  # has complex idx
        if (
            msg.verb == I_
            and msg.src.type in (DEV_TYPE_MAP.CTL, DEV_TYPE_MAP.PRG)
            and msg.src is msg.dst
        ):  # DEX
            assert payload[:2] == FC
            return {SZ_DOMAIN_ID: FC}
        assert payload[:2] == "00"
        return {}

    assert msg.len == 2, msg.len
    assert payload[:2] == {
        DEV_TYPE_MAP.CTL: FC,
        DEV_TYPE_MAP.BDR: "00",
        DEV_TYPE_MAP.PRG: FC,
    }.get(
        msg.src.type, "00"
    )  # DEX
    assert payload[2:] == "C8", payload[2:]  # Could it be a percentage?

    return {
        **complex_idx(payload[:2], msg),
        "actuator_sync": bool_from_hex(payload[2:]),
    }


@parser_decorator  # actuator_state
def parser_3ef0(payload, msg) -> dict:

    if msg.src.type in DEV_TYPE_MAP.JIM:  # Honeywell Jasper, DEX
        assert msg.len == 20, f"expecting len 20, got: {msg.len}"
        return {
            "ordinal": f"0x{payload[2:8]}",
            "blob": payload[8:],
        }

    assert msg.len in (3, 6, 9)  # [2 + (4, 10, 16)]/2

    if msg.len == 3:  # I|BDR|003
        # .I --- 13:042805 --:------ 13:042805 3EF0 003 0000FF
        # .I --- 13:023770 --:------ 13:023770 3EF0 003 00C8FF
        assert payload[2:4] in ("00", "C8"), f"byte 1: {payload[2:4]}"
        assert payload[4:6] == "FF", f"byte 2: {payload[4:6]}"
        mod_level = percent(payload[2:4])

    if msg.len >= 6:  # RP|OTB|006 (to RQ|CTL/HGI/RFG)
        # RP --- 10:105624 01:133689 --:------ 3EF0 006 0000100000FF
        # RP --- 10:105624 01:133689 --:------ 3EF0 006 003B100C00FF
        assert payload[4:6] in ("00", "10", "11"), f"byte 2: {payload[4:6]}"
        mod_level = percent(payload[2:4], high_res=False)

    result = {
        "modulation_level": mod_level,
        "_flags_2": payload[4:6],
    }

    if msg.len >= 6:  # RP|OTB|006 (to RQ|CTL/HGI/RFG)
        # RP --- 10:138822 01:187666 --:------ 3EF0 006 000110FA00FF  # ?corrupt

        # for OTB (there's no reliable) modulation_level <-> flame_state)
        assert (
            payload[6:8] == "FF" or int(payload[6:8], 16) & 0b11110000 == 0
        ), f"byte 3: {payload[6:8]}"
        assert int(payload[8:10], 16) & 0b11110000 == 0, f"byte 4: {payload[8:10]}"
        assert payload[10:12] in ("00", "1C", "FF"), f"byte 5: {payload[10:12]}"

        result.update(
            {
                "_flags_3": flag8(payload[6:8]),
                "ch_active": bool(int(payload[6:8], 0x10) & 1 << 1),
                "dhw_active": bool(int(payload[6:8], 0x10) & 1 << 2),
                "flame_active": bool(int(payload[6:8], 0x10) & 1 << 3),  # flame_on
                f"_{SZ_UNKNOWN}_4": payload[8:10],
                f"_{SZ_UNKNOWN}_5": payload[10:12],  # rel_modulation?
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
                "ch_enabled": bool(int(payload[12:14], 0x10) & 1 << 0),
                "ch_setpoint": int(payload[14:16], 0x10),
                "max_rel_modulation": percent(payload[16:18], high_res=False),
            }
        )

    try:
        assert "_flags_3" not in result or (
            [result["_flags_3"][i] for i in (0, 1, 2, 3)] == [0] * 4
        ), result["_flags_3"]
        assert "_flags_6" not in result or (
            [result["_flags_6"][i] for i in (0, 1, 2, 3, 4, 5)] == [0] * 6
        ), result["_flags_6"]
    except AssertionError as exc:
        _LOGGER.warning(
            f"{msg!r} < {_INFORM_DEV_MSG} ({exc}), with a description of your system"
        )

    return result


@parser_decorator  # actuator_cycle
def parser_3ef1(payload, msg) -> dict:

    if msg.src.type == DEV_TYPE_MAP.JIM:  # Honeywell Jasper, DEX
        assert msg.len == 18, f"expecting len 18, got: {msg.len}"
        return {
            "ordinal": f"0x{payload[2:8]}",
            "blob": payload[8:],
        }

    if (
        msg.src.type == DEV_TYPE_MAP.JST
    ):  # and msg.len == 12:  # or (12, 20) Japser, DEX
        assert msg.len == 12, f"expecting len 12, got: {msg.len}"
        return {
            "ordinal": f"0x{payload[2:8]}",
            "blob": payload[8:],
        }

    if payload[12:] == "FF":  # is BDR
        # assert (
        #     re.compile(r"^00[0-9A-F]{10}FF").match(payload)
        # ), "doesn't match: " + r"^00[0-9A-F]{10}FF"
        assert int(payload[2:6], 16) <= 7200, f"byte 1: {payload[2:6]}"
        # assert payload[6:10] in ("87B3", "9DFA", "DCE1", "E638", "F8F7") or (
        #     int(payload[6:10], 16) <= 7200
        # ), f"byte 3: {payload[6:10]}"
        assert percent(payload[10:12]) in (0, 1), f"byte 5: {payload[10:12]}"

    else:  # is OTB
        # assert (
        #     re.compile(r"^00[0-9A-F]{10}10").match(payload)
        # ), "doesn't match: " + r"^00[0-9A-F]{10}10"
        assert payload[2:6] == "7FFF", f"byte 1: {payload[2:6]}"
        assert payload[6:10] == "003C", f"byte 3: {payload[6:10]}"  # 60 seconds
        assert percent(payload[10:12]) <= 1, f"byte 5: {payload[10:12]}"

    cycle_countdown = None if payload[2:6] == "7FFF" else int(payload[2:6], 16)

    return {
        "modulation_level": percent(payload[10:12]),
        "actuator_countdown": int(payload[6:10], 16),
        "cycle_countdown": cycle_countdown,
        f"_{SZ_UNKNOWN}_0": payload[12:],
    }


@parser_decorator  # timestamp - HVAC
def parser_4401(payload, msg) -> Optional[dict]:

    assert payload[:4] == "1000", _INFORM_DEV_MSG
    # assert payload[24:] == "0000000000000063", _INFORM_DEV_MSG

    return {
        "epoch_02": f"0x{payload[4:12]}",
        "epoch_07": f"0x{payload[14:22]}",
        "xxxxx_13": f"0x{payload[22:24]}",
        "epoch_13": f"0x{payload[26:34]}",
    }  # epoch are in seconds


# @parser_decorator  # faked puzzle pkt shouldn't be decorated
def parser_7fff(payload, msg) -> Optional[dict]:

    if payload[:2] != "00":
        _LOGGER.debug("Invalid/deprecated Puzzle packet")
        return {
            "msg_type": payload[:2],
            SZ_PAYLOAD: str_from_hex(payload[2:]),
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

    msg_type = LOOKUP_PUZZ.get(payload[2:4], SZ_PAYLOAD)

    if payload[2:4] == "11":
        msg = str_from_hex(payload[16:])
        result[msg_type] = f"{msg[:4]}|{msg[4:6]}|{msg[6:]}"

    elif payload[2:4] == "13":
        result[msg_type] = str_from_hex(payload[4:])

    elif payload[2:4] == "7F":
        result[msg_type] = payload[4:]

    else:
        result[msg_type] = str_from_hex(payload[16:])

    return {**result, "parser": f"v{VERSION}"}


@parser_decorator
def parser_unknown(payload, msg) -> Optional[dict]:
    # TODO: it may be useful to generically search payloads for hex_ids, commands, etc.

    # These are generic parsers
    if msg.len == 2 and payload[:2] == "00":
        return {
            f"_{SZ_PAYLOAD}": payload,
            f"_{SZ_VALUE}": {"00": False, "C8": True}.get(
                payload[2:], int(payload[2:], 16)
            ),
        }

    if msg.len == 3 and payload[:2] == "00":
        return {
            f"_{SZ_PAYLOAD}": payload,
            f"_{SZ_VALUE}": temp_from_hex(payload[2:]),
        }

    raise NotImplementedError


PAYLOAD_PARSERS = {
    k[7:].upper(): v
    for k, v in locals().items()
    if callable(v) and k.startswith("parser_") and k != "parser_unknown"
}

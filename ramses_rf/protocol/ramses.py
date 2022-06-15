#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser."""

import logging
from datetime import timedelta as td
from types import SimpleNamespace
from typing import Dict

from .const import DEV_TYPE, SZ_NAME, __dev_mode__

# skipcq: PY-W2000
from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
)

from .const import (  # isort: skip
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
    _0150,
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
    _1098,
    _10A0,
    _10B0,
    _10E0,
    _10E1,
    _10E2,
    _1100,
    _11F0,
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
    _1470,
    _1F09,
    _1F41,
    _1FC9,
    _1FCA,
    _1FD0,
    _1FD4,
    _2249,
    _22C9,
    _22D0,
    _22D9,
    _22F1,
    _22F3,
    _22F7,
    _2309,
    _2349,
    _2389,
    _2400,
    _2401,
    _2410,
    _2411,
    _2420,
    _2D49,
    _2E04,
    _2E10,
    _30C9,
    _3110,
    _3120,
    _313F,
    _3150,
    _31D9,
    _31DA,
    _31E0,
    _3200,
    _3210,
    _3220,
    _3221,
    _3223,
    _3B00,
    _3EF0,
    _3EF1,
    _4401,
    _PUZZ,
)

DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)

RQ_NULL = "rq_null"
EXPIRES = "expires"

EXPIRY = "expiry"

# The master list - all known codes are here, even if there's no corresponding parser
# Anything with a zone-idx should start: ^0[0-9A-F], ^(0[0-9A-F], or ^((0[0-9A-F]

#
########################################################################################
# CODES_SCHEMA - HEAT (CH/DHW, Honeywell/Resideo) vs HVAC (ventilation, Itho/Orcon/etc.)
#
CODES_SCHEMA: dict = {  # rf_unknown
    _0001: {
        SZ_NAME: "rf_unknown",
        I_: r"^00FFFF02(00|FF)$",  # loopback
        RQ: r"^00([28A]0)00(0[0-9A-F])(FF|04)$",  # HVAC
        RP: r"^00([28A]0)00(0[0-9A-F])",  # HVAC
        W_: r"^(0[0-9A-F]|FC|FF)000005(01|05)$",
    },  # TODO: there appears to be a dodgy? RQ/RP for UFC
    _0002: {  # WIP: outdoor_sensor - CODE_IDX_COMPLEX?
        SZ_NAME: "outdoor_sensor",
        I_: r"^0[0-4][0-9A-F]{4}(00|01|02|05)$",  # Domoticz sends ^02!!
        RQ: r"^00$",  # NOTE: sent by an RFG100
    },
    _0004: {  # zone_name
        SZ_NAME: "zone_name",
        I_: r"^0[0-9A-F]00([0-9A-F]){40}$",  # RP is same, null_rp: xxxx,7F*20
        RQ: r"^0[0-9A-F]00$",
        EXPIRES: td(days=1),
    },
    _0005: {  # system_zones
        SZ_NAME: "system_zones",
        #  I --- 34:092243 --:------ 34:092243 0005 012 000A0000-000F0000-00100000
        I_: r"^(00[01][0-9A-F]{5}){1,3}$",
        RQ: r"^00[01][0-9A-F]$",  # f"00{zone_type}", evohome wont respond to 00
        RP: r"^00[01][0-9A-F]{3,5}$",
        EXPIRES: False,
    },
    _0006: {  # schedule_version  # TODO: what for DHW schedule?
        SZ_NAME: "schedule_version",
        RQ: r"^00$",
        RP: r"^0005[0-9A-F]{4}$",
    },
    _0008: {  # relay_demand, TODO: check RP
        SZ_NAME: "relay_demand",
        # 000 I --- 31:012319 08:006244 --:------ 0008 013 0006958C33CA6ECD2067AA53DD
        I_: r"^((0[0-9A-F]|F[9AC])[0-9A-F]{2}|00[0-9A-F]{24})$",
        RQ: r"^00$",
        RP: r"^00[0-9A-F]{2}$",  # seems only 13: RP (TODO: what about 10:, 08/31:)
    },
    _0009: {  # relay_failsafe (only is_controller, OTB send an 0009?)
        SZ_NAME: "relay_failsafe",
        #  I --- 01:145038 --:------ 01:145038 0009 006 FC01FFF901FF
        #  I --- 01:145038 --:------ 01:145038 0009 003 0700FF
        #  I --- 10:040239 01:223036 --:------ 0009 003 000000
        #  I --- --:------ --:------ 12:227486 0009 003 0000FF
        I_: r"^((0[0-9A-F]|F[9AC])0[0-1](00|FF))+$",
    },
    _000A: {  # zone_params
        SZ_NAME: "zone_params",
        I_: r"^(0[0-9A-F][0-9A-F]{10}){1,8}$",
        W_: r"^0[0-9A-F][0-9A-F]{10}$",
        RQ: r"^0[0-9A-F]((00)?|([0-9A-F]{10})+)$",  # is: r"^0[0-9A-F]([0-9A-F]{10})+$"
        RP: r"^0[0-9A-F][0-9A-F]{10}$",  # null_rp: xx/007FFF7FFF
        # 17:54:13.126 063 RQ --- 34:064023 01:145038 --:------ 000A 001 03
        # 17:54:13.141 045 RP --- 01:145038 34:064023 --:------ 000A 006 031002260B86
        # 19:20:49.460 062 RQ --- 12:010740 01:145038 --:------ 000A 006 080001F40DAC
        # 19:20:49.476 045 RP --- 01:145038 12:010740 --:------ 000A 006 081001F40DAC
        EXPIRES: td(days=1),
    },
    _000C: {  # zone_devices, TODO: needs I/RP
        SZ_NAME: "zone_devices",
        # RP --- 01:145038 18:013393 --:------ 000C 012 0100-00-10DAF5,0100-00-10DAFB
        I_: r"^(0[0-9A-F][01][0-9A-F](0[0-9A-F]|7F)[0-9A-F]{6}){1,8}$",
        RQ: r"^0[0-9A-F][01][0-9A-F]$",  # TODO: f"{zone_idx}{device_type}"
        EXPIRES: False,
    },
    _000E: {  # unknown_000e
        SZ_NAME: "message_000e",
        I_: r"^000014$",
    },
    _0016: {  # rf_check
        SZ_NAME: "rf_check",
        RQ: r"^0[0-9A-F]([0-9A-F]{2})?$",  # TODO: officially: r"^0[0-9A-F]{3}$"
        RP: r"^0[0-9A-F]{3}$",
    },
    _0100: {  # language
        SZ_NAME: "language",
        RQ: r"^00([0-9A-F]{4}F{4})?$",  # NOTE: RQ/04/0100 has a payload
        RP: r"^00[0-9A-F]{4}F{4}$",
        EXPIRES: td(days=1),  # TODO: make longer?
    },
    _0150: {  # unknown_0150
        SZ_NAME: "message_0150",
        RQ: r"^00$",
        RP: r"^000000$",
    },
    _01D0: {  # unknown_01d0, TODO: definitely a real code, zone_idx is a guess
        SZ_NAME: "message_01d0",
        I_: r"^0[0-9A-F][0-9A-F]{2}$",
        W_: r"^0[0-9A-F][0-9A-F]{2}$",
        #  W --- 04:000722 01:158182 --:------ 01D0 002 0003  # is a guess, the
        #  I --- 01:158182 04:000722 --:------ 01D0 002 0003  # TRV was in zone 00
    },
    _01E9: {  # unknown_01e9, TODO: definitely a real code, zone_idx is a guess
        SZ_NAME: "message_01e9",
        I_: r"^0[0-9A-F][0-9A-F]{2}$",
        W_: r"^0[0-9A-F][0-9A-F]{2}$",
        #  W --- 04:000722 01:158182 --:------ 01E9 002 0003  # is a guess, the
        #  I --- 01:158182 04:000722 --:------ 01E9 002 0000  # TRV was in zone 00
    },
    _0404: {  # zone_schedule
        SZ_NAME: "zone_schedule",
        I_: r"^0[0-9A-F](20|23)0008[0-9A-F]{6}$",
        RQ: r"^0[0-9A-F](20|23)000800[0-9A-F]{4}$",
        RP: r"^0[0-9A-F](20|23)0008[0-9A-F]{6}[0-9A-F]{2,82}$",
        W_: r"^0[0-9A-F](20|23)0008[0-9A-F]{6}[0-9A-F]{2,82}$",  # as per RP
        EXPIRES: None,
    },
    _0418: {  # system_fault
        SZ_NAME: "system_fault",
        I_: r"^00(00|40|C0)[0-3][0-9A-F]B0[0-9A-F]{6}0000[0-9A-F]{12}FFFF700[012][0-9A-F]{6}$",
        RQ: r"^0000[0-3][0-9A-F]$",  # f"0000{log_idx}", no payload
    },
    _042F: {  # unknown_042f, # non-evohome are len==9, seen only once?
        # .I --- 32:168090 --:------ 32:168090 042F 009 000000100F00105050
        # RP --- 10:048122 18:006402 --:------ 042F 009 000200001400163010
        SZ_NAME: "message_042f",
        I_: r"^00([0-9A-F]{2}){7,8}$",
        RQ: r"^00$",
        RP: r"^00([0-9A-F]{2}){7,8}$",
    },
    _0B04: {  # unknown_0b04
        #  I --- --:------ --:------ 12:207082 0B04 002 00C8
        SZ_NAME: "message_0b04",
        I_: r"^00(00|C8)$",
    },
    _1030: {  # mixvalve_params
        SZ_NAME: "mixvalve_params",
        #  I --- --:------ --:------ 12:138834 1030 016 01C80137C9010FCA0196CB010FCC0101
        I_: r"^0[0-9A-F](C[89A-C]01[0-9A-F]{2}){5}$",
    },
    _1060: {  # device_battery
        SZ_NAME: "device_battery",
        I_: r"^0[0-9A-F](FF|[0-9A-F]{2})0[01]$",  # HCW: r"^(FF|0[0-9A-F]...
        EXPIRES: td(days=1),
    },
    _1081: {  # max_ch_setpoint
        SZ_NAME: "max_ch_setpoint",
        RQ: r"^00$",
        RP: r"^00[0-9A-F]{4}$",
    },
    _1090: {  # unknown_1090
        # 095 RP --- 23:100224 22:219457 --:------ 1090 005 00-7FFF-01F4
        SZ_NAME: "message_1090",
        RQ: r"^00$",
        RP: r"^00",
    },
    _1098: {  # unknown_1098
        SZ_NAME: "message_1098",
        RQ: r"^00$",
        RP: r"^00",
    },
    _10A0: {  # dhw_params
        SZ_NAME: "dhw_params",
        # RQ --- 07:045960 01:145038 --:------ 10A0 006 0013740003E4
        # RP --- 10:048122 18:006402 --:------ 10A0 003 001B58
        # NOTE: RFG100 uses a domain id! (00|01)
        # 19:14:24.662 051 RQ --- 30:185469 01:037519 --:------ 10A0 001 00
        # 19:14:31.463 053 RQ --- 30:185469 01:037519 --:------ 10A0 001 01
        I_: r"^0[01][0-9A-F]{4}([0-9A-F]{6})?$",  # NOTE: RQ/07/10A0 has a payload
        RQ: r"^0[01]([0-9A-F]{10})?$",  # NOTE: RQ/07/10A0 has a payload
        W_: r"^0[01][0-9A-F]{4}([0-9A-F]{6})?$",  # TODO: needs checking
        EXPIRES: td(hours=4),
    },
    _10B0: {  # unknown_10b0
        SZ_NAME: "message_10b0",
        RQ: r"^00$",
        RP: r"^00[0-9A-F]{8}$",
    },
    _10E0: {  # device_info
        SZ_NAME: "device_info",
        I_: r"^00[0-9A-F]{30,}$",  # r"^[0-9A-F]{32,}$" might be OK
        RQ: r"^00$",  # NOTE: will accept [0-9A-F]{2}
        # RP: r"^[0-9A-F]{2}([0-9A-F]){30,}$",  # NOTE: indx same as RQ
        EXPIRES: False,
    },
    _10E1: {  # device_id
        SZ_NAME: "device_id",
        RP: r"^00[0-9A-F]{6}$",
        RQ: r"^00$",
        EXPIRES: False,
    },
    _10E2: {  # unknown_10e2 - HVAC
        SZ_NAME: "unknown_10e2",
        I_: r"^00[0-9A-F]{4}$",
    },
    _1100: {  # tpi_params
        SZ_NAME: "tpi_params",
        # RQ --- 01:145038 13:163733 --:------ 1100 008 00180400007FFF01  # boiler relay
        # RP --- 13:163733 01:145038 --:------ 1100 008 00180400FF7FFF01
        # RQ --- 01:145038 13:035462 --:------ 1100 008 FC240428007FFF01  # not bolier relay
        # RP --- 13:035462 01:145038 --:------ 1100 008 00240428007FFF01
        I_: r"^(00|FC)[0-9A-F]{6}(00|FF)([0-9A-F]{4}01)?$",
        W_: r"^(00|FC)[0-9A-F]{6}(00|FF)([0-9A-F]{4}01)?$",  # TODO: is there no I?
        RQ: r"^(00|FC)([0-9A-F]{6}(00|FF)([0-9A-F]{4}01)?)?$",  # RQ/13:/00, or RQ/01:/FC:
        EXPIRES: td(days=1),
    },
    _11F0: {  # unknown_11f0, from heatpump relay
        SZ_NAME: "message_11f0",
        I_: r"^00",
    },
    _1260: {  # dhw_temp
        SZ_NAME: "dhw_temp",
        # RQ --- 30:185469 01:037519 --:------ 1260 001 00
        # RP --- 01:037519 30:185469 --:------ 1260 003 000837
        # RQ --- 18:200202 10:067219 --:------ 1260 002 0000
        # RP --- 10:067219 18:200202 --:------ 1260 003 007FFF
        #  I --- 07:045960 --:------ 07:045960 1260 003 0007A9
        I_: r"^0[01][0-9A-F]{4}$",  # NOTE: RP is same
        RQ: r"^0[01](00)?$",  # TODO: officially: r"^0[01]$"
        EXPIRES: td(hours=1),
    },
    _1280: {  # outdoor_humidity
        SZ_NAME: "outdoor_humidity",
        I_: r"^00[0-9A-F]{2}[0-9A-F]{8}?$",
    },
    _1290: {  # outdoor_temp
        SZ_NAME: "outdoor_temp",
        I_: r"^00[0-9A-F]{4}$",  # NOTE: RP is same
        RQ: r"^00$",
    },
    _1298: {  # co2_level
        SZ_NAME: "co2_level",
        I_: r"^00[0-9A-F]{4}$",
    },
    _12A0: {  # indoor_humidity
        # .I --- 32:168090 --:------ 32:168090 12A0 006 0030093504A8
        # .I --- 32:132125 --:------ 32:132125 12A0 007 003107B67FFF00  # only dev_id with 007
        # RP --- 20:008749 18:142609 --:------ 12A0 002 00EF
        SZ_NAME: "indoor_humidity",
        I_: r"^00[0-9A-F]{2}([0-9A-F]{8}(00)?)?$",
        EXPIRES: td(hours=1),
    },
    _12B0: {  # window_state  (HVAC % window open)
        SZ_NAME: "window_state",
        I_: r"^0[0-9A-F](0000|C800|FFFF)$",  # NOTE: RP is same
        RQ: r"^0[0-9A-F](00)?$",
        EXPIRES: td(hours=1),
    },
    _12C0: {  # displayed_temp (HVAC room temp)
        SZ_NAME: "displayed_temp",  # displayed room temp
        I_: r"^00[0-9A-F]{2}0[01](FF)?$",
    },
    _12C8: {  # air_quality, HVAC
        SZ_NAME: "air_quality",
        I_: r"^00[0-9A-F]{4}$",
    },
    _12F0: {  # dhw_flow_rate
        # 2021-11-05T06:25:20.399400 065 RP --- 10:023327 18:131597 --:------ 12F0 003 000307
        # 2021-11-05T06:25:20.669382 066 RP --- 10:023327 18:131597 --:------ 3220 005 00C01307C0
        # 2021-11-05T06:35:20.450201 065 RP --- 10:023327 18:131597 --:------ 12F0 003 000023
        # 2021-11-05T06:35:20.721228 066 RP --- 10:023327 18:131597 --:------ 3220 005 0040130059
        # 2021-12-06T06:35:54.575298 073 RP --- 10:051349 18:135447 --:------ 12F0 003 00059F
        # 2021-12-06T06:35:55.949502 071 RP --- 10:051349 18:135447 --:------ 3220 005 00C0130ECC
        SZ_NAME: "dhw_flow_rate",
        RQ: r"^00$",
        RP: r"^00[0-9A-F](4)$",
    },
    _1300: {  # cv water pressure (usu. for ch)
        SZ_NAME: "ch_pressure",
        RQ: r"^00$",
        RP: r"^00[0-9A-F]{4}$",
    },
    _1470: {  # HVAC - something to do with date/time? is RQ|1470 after RQ|313F
        SZ_NAME: "message_1470",
        RQ: r"^00$",
        RP: r"^00[0-9A-F]{14}$",
    },
    _1F09: {  # system_sync - FF (I), 00 (RP), F8 (W, after 1FC9)
        SZ_NAME: "system_sync",
        I_: r"^(00|01|DB|FF)[0-9A-F]{4}$",  # FF is evohome, DB is Hometronics
        RQ: r"^00$",
        RP: r"^00[0-9A-F]{4}$",  # xx-secs
        W_: r"^F8[0-9A-F]{4}$",
    },
    _1F41: {  # dhw_mode
        SZ_NAME: "dhw_mode",
        I_: r"^0[01](00|01|FF)0[0-5]F{6}(([0-9A-F]){12})?$",
        RQ: r"^0[01]$",  # will accept: r"^0[01](00)$"
        W_: r"^0[01](00|01|FF)0[0-5]F{6}(([0-9A-F]){12})?$",
        EXPIRES: td(hours=4),
    },
    _1FC9: {  # rf_bind
        # RP --- 13:035462 18:013393 --:------ 1FC9 018 00-3EF0-348A86 00-11F0-348A86 90-3FF1-956ABD  # noqa: E501
        # RP --- 13:035462 18:013393 --:------ 1FC9 018 00-3EF0-348A86 00-11F0-348A86 90-7FE1-DD6ABD  # noqa: E501
        # RP --- 01:145038 18:013393 --:------ 1FC9 012 FF-10E0-06368E FF-1FC9-06368E
        SZ_NAME: "rf_bind",  # idx-code-dev_id
        RQ: r"^00$",
        RP: r"^((0[0-9A-F]|F[9ABCF]|90)([0-9A-F]{10}))+$",  # #     NOTE: idx can be 90 (HEAT)
        I_: r"^((0[0-9A-F]|F[9ABCF]|63|67)([0-9A-F]{10}))+|00$",  # NOTE: idx can be 63|67 (HVAC), payload can be 00
        W_: r"^((0[0-9A-F]|F[9ABCF])([0-9A-F]{10}))+$",
    },
    _1FCA: {  # unknown_1fca
        SZ_NAME: "message_1fca",
        RQ: r"^00$",
        RP: r"^((0[0-9A-F]|F[9ABCF]|90)([0-9A-F]{10}))+$",  # xx-code-dev_id
        I_: r"^((0[0-9A-F]|F[9ABCF])([0-9A-F]{10}))+$",
        W_: r"^((0[0-9A-F]|F[9ABCF])([0-9A-F]{10}))+$",
    },
    _1FD0: {  # unknown_1fd0
        SZ_NAME: "message_1fd0",
        RQ: r"^00$",
        RP: r"^00",
    },
    _1FD4: {  # opentherm_sync
        SZ_NAME: "opentherm_sync",
        I_: r"^00([0-9A-F]{4})$",
    },
    _2249: {  # setpoint_now?
        SZ_NAME: "setpoint_now",  # setpt_now_next
        I_: r"^(0[0-9A-F]{13}){1,2}$",
    },  # TODO: This could be an array
    _22C9: {  # ufh_setpoint
        #  I --- 02:001107 --:------ 02:001107 22C9 024 0008340A2801-0108340A2801-0208340A2801-0308340A2801  # noqa: E501
        #  I --- 02:001107 --:------ 02:001107 22C9 006 04-0834-0A28-01
        SZ_NAME: "ufh_setpoint",
        I_: r"^(0[0-9A-F][0-9A-F]{8}0[12]){1,4}$",  # ~000A array, but max_len 24, not 48!
        # RP: Appear wont get any?,
    },
    _22D0: {  # unknown_22d0, HVAC system switch?
        SZ_NAME: "message_22d0",
        I_: r"^00",
    },
    _22D9: {  # boiler_setpoint
        SZ_NAME: "boiler_setpoint",
        RQ: r"^00$",
        RP: r"^00[0-9A-F]{4}$",
    },
    _22F1: {  # switch_speed, HVAC
        SZ_NAME: "switch_speed",
        I_: r"^(00|63)(0[0-9A-F]){2}$",
    },
    _22F7: {  # bypass on/off, HVAC
        SZ_NAME: "bypass_mode",
        I_: r"^00(00|C8|FF)(00|C8)$",  # RP is the same
        RQ: r"^00$",
        W_: r"^00(00|C8|FF)EF$",
    },
    _22F3: {  # switch_duration
        SZ_NAME: "switch_duration",
        I_: r"^(00|63)[0-9A-F]{4}([0-9A-F]{8})?$",
    },  # minutes
    _2309: {  # setpoint
        SZ_NAME: "setpoint",
        I_: r"^(0[0-9A-F]{5})+$",
        W_: r"^0[0-9A-F]{5}$",
        # RQ --- 12:010740 01:145038 --:------ 2309 003 03073A # No RPs
        RQ: r"^0[0-9A-F]([0-9A-F]{4})?$",  # NOTE: 12 uses: r"^0[0-9A-F]$"
        EXPIRES: td(minutes=30),
    },
    _2349: {  # zone_mode
        SZ_NAME: "zone_mode",
        I_: r"^0[0-9A-F]{5}0[0-4][0-9A-F]{6}([0-9A-F]{12})?$",
        W_: r"^0[0-9A-F]{5}0[0-4][0-9A-F]{6}([0-9A-F]{12})?$",
        # .W --- 18:141846 01:050858 --:------ 2349 013 02-0960-04-FFFFFF-0409160607E5
        # .W --- 18:141846 01:050858 --:------ 2349 007 02-08FC-01-FFFFFF
        RQ: r"^0[0-9A-F](00|[0-9A-F]{12})?$",
        # RQ --- 22:070483 01:063844 --:------ 2349 007 06-0708-03-000027
        EXPIRES: td(hours=4),
    },
    _2389: {  # unknown_2389 - CODE_IDX_COMPLEX?
        #  I 024 03:052382 --:------ 03:052382 2389 003 02001B
        SZ_NAME: "unknown_2389",
        I_: r"^0[0-4][0-9A-F]{4}$",
    },
    _2400: {  # unknown_2400, from OTB
        SZ_NAME: "message_2400",
        RQ: r"^00$",
        RP: r"^00",
    },
    _2401: {  # unknown_2401, from OTB
        SZ_NAME: "message_2401",
        RQ: r"^00$",
        RP: r"^00",
    },
    _2410: {  # unknown_2410, from OTB
        SZ_NAME: "message_2410",
        RQ: r"^00$",
        RP: r"^00",
    },
    _2411: {  # unknown_2411, HVAC
        SZ_NAME: "message_2411",
        I_: r"^0000[0-9A-F]{42}$",
        RQ: r"^0000[0-9A-F]{2}((00){19})?$",
        W_: r"^0000[0-9A-F]{42}$",
    },
    _2420: {  # unknown_2420, from OTB
        SZ_NAME: "message_2420",
        RQ: r"^00$",
        RP: r"^00",
    },
    _2D49: {  # unknown_2d49
        SZ_NAME: "message_2d49",
        # 10:14:08.526 045  I --- 01:023389 --:------ 01:023389 2D49 003 010000
        # 10:14:12.253 047  I --- 01:023389 --:------ 01:023389 2D49 003 00C800
        # 10:14:12.272 047  I --- 01:023389 --:------ 01:023389 2D49 003 01C800
        # 10:14:12.390 049  I --- 01:023389 --:------ 01:023389 2D49 003 880000
        # 10:14:12.399 048  I --- 01:023389 --:------ 01:023389 2D49 003 FD0000
        I_: r"^(0[0-9A-F]|88|FD)[0-9A-F]{2}00$",
    },  # seen with Hometronic systems
    _2E04: {  # system_mode
        SZ_NAME: "system_mode",
        I_: r"^0[0-7][0-9A-F]{12}0[01]$",
        RQ: r"^FF$",
        W_: r"^0[0-7][0-9A-F]{12}0[01]$",
        EXPIRES: td(hours=4),
    },
    _2E10: {  # presence_detect - HVAC
        SZ_NAME: "presence_detect",
        I_: r"^00(00|01)(00)?$",
    },
    _30C9: {  # temperature
        SZ_NAME: "temperature",
        I_: r"^(0[0-9A-F][0-9A-F]{4})+$",
        RQ: r"^0[0-9A-F](00)?$",  # TODO: officially: r"^0[0-9A-F]$"
        RP: r"^0[0-9A-F][0-9A-F]{4}$",  # Null: r"^0[0-9A-F]7FFF$"
        EXPIRES: td(hours=1),
    },
    _3110: {  # unknown_3110 - HVAC
        SZ_NAME: "message_3110",
        I_: r"^00",
    },
    _3120: {  # unknown_3120 - Error Report?
        SZ_NAME: "message_3120",
        I_: r"^00[0-9A-F]{10}FF$",  # only ever: 34:/0070B0000000FF
        RQ: r"^00$",  # 20: will RP an RQ?
        # RP: r"^00[0-9A-F]{10}FF$",  # only ever: 20:/0070B000009CFF
    },
    _313F: {  # datetime (time report)
        SZ_NAME: "datetime",
        I_: r"^00[0-9A-F]{16}$",  # NOTE: RP is same
        RQ: r"^00$",
        W_: r"^00[0-9A-F]{16}$",
        EXPIRES: td(seconds=3),
    },
    _3150: {  # heat_demand
        SZ_NAME: "heat_demand",
        I_: r"^((0[0-9A-F])[0-9A-F]{2}|FC[0-9A-F]{2})+$",
        EXPIRES: td(minutes=20),
    },
    _31D9: {  # ventilation_status
        SZ_NAME: "vent_status",
        # I_: r"^(00|21)[0-9A-F]{32}$",
        # I_: r"^(00|01|21)[0-9A-F]{4}((00|FE)(00|20){12}(00|08))?$",
        I_: r"^(00|01|21)[0-9A-F]{4}((00|FE)(00|20){0,12}(00|08)?)?$",  # 00-0004-FE
        RQ: r"^00$",
    },
    _31DA: {  # ventilation_unknown
        SZ_NAME: "vent_31da",
        I_: r"^(00|01|21)[0-9A-F]{56}(00)?$",
        RQ: r"^(00|01|21)$"
        # RQ --- 32:168090 30:082155 --:------ 31DA 001 21
    },
    _31E0: {  # ventilation demand
        # 10:15:42.712 077  I --- 29:146052 32:023459 --:------ 31E0 003 0000C8
        # 10:21:18.549 078  I --- 29:146052 32:023459 --:------ 31E0 003 000000
        # 07:56:50.522 095  I --- --:------ --:------ 07:044315 31E0 004 00006E00
        SZ_NAME: "vent_demand",
        I_: r"^00[0-9A-F]{4}(00|FF)?$",
    },
    _3200: {  # boiler output temp
        SZ_NAME: "boiler_output",
        RQ: r"^00$",
        RP: r"^00[0-9A-F]{4}$",
    },
    _3210: {  # boiler return temp
        SZ_NAME: "boiler_return",
        RQ: r"^00$",
        RP: r"^00[0-9A-F]{4}$",
    },
    _3220: {  # opentherm_msg
        SZ_NAME: "opentherm_msg",
        RQ: r"^00[0-9A-F]{4}0{4}$",  # is strictly: r"^00[0-9A-F]{8}$",
        RP: r"^00[0-9A-F]{8}$",
    },
    _3221: {  # unknown_3221, from OTB
        SZ_NAME: "message_3221",
        RQ: r"^00$",
        RP: r"^00",
    },
    _3223: {  # unknown_3223, from OTB
        SZ_NAME: "message_3223",
        RQ: r"^00$",
        RP: r"^00",
    },
    _3B00: {  # actuator_sync, NOTE: no RQ
        SZ_NAME: "actuator_sync",
        I_: r"^(00|FC)(00|C8)$",
    },
    _3EF0: {  # actuator_state
        SZ_NAME: "actuator_state",
        # .I --- 13:106039 --:------ 13:106039 3EF0 003 00-C8FF
        # .I --- 21:038634 --:------ 21:038634 3EF0 006 00-0000-0A0200  #                            # Itho spIDer
        # .I --- 10:030051 --:------ 10:030051 3EF0 009 00-0010-000000-020A64
        # .I --- 08:031043 31:077159 --:------ 3EF0 020 00-1191A72044399D2A50DE43F920478AF7185F3F  # # Jasper BLOB
        I_: r"^..((00|C8)FF|[0-9A-F]{10}|[0-9A-F]{16}|[0-9A-F]{38})$",
        RQ: r"^00(00)?$",
        RP: r"^00((00|C8)FF|[0-9A-F]{10}|[0-9A-F]{16})$",
    },
    _3EF1: {  # actuator_cycle
        SZ_NAME: "actuator_cycle",
        # RQ --- 31:004811 13:077615 --:------ 3EF1 001 00
        # RP --- 13:077615 31:004811 --:------ 3EF1 007 00024D001300FF
        # RQ --- 22:068154 13:031208 --:------ 3EF1 002 0000
        # RP --- 13:031208 22:068154 --:------ 3EF1 007 00024E00E000FF
        # RQ --- 31:074182 08:026984 --:------ 3EF1 012 0005D1341DA39B8C7DAFD4C1
        # RP --- 08:026984 31:074182 --:------ 3EF1 018 001396A7E087922FA77794280B66BE16A975
        RQ: r"^00((00)?|[0-9A-F]{22})$",  # NOTE: latter is Japser
        RP: r"^00([0-9A-F]{12}|[0-9A-F]{34})$",  # NOTE: latter is Japser
    },
    _4401: {  # unknown_4401 - HVAC
        SZ_NAME: "unknown_4401",
        I_: r"^[0-9A-F]{40}$",
        RQ: r"^[0-9A-F]{40}$",  # NOTE: no RP!
    },
    _PUZZ: {
        SZ_NAME: "puzzle_packet",
        I_: r"^00(([0-9A-F]){2})+$",
    },
}
for code in CODES_SCHEMA.values():  # map any RPs to (missing) I_s
    if RQ in code and RP not in code and I_ in code:
        code[RP] = code[I_]
#
# I --- 01:210309 --:------ 01:210309 0009 006 FC00FFF900FF
CODES_WITH_ARRAYS = {
    _0005: [4, ("34",)],
    _0009: [3, ("01", "12", "22")],
    _000A: [6, ("01", "12", "22")],  # single element I after a W
    _2309: [3, ("01", "12", "22")],
    _30C9: [3, ("01", "12", "22")],
    _2249: [7, ("23",)],
    _22C9: [6, ("02",)],  # *all* 22C9s are arrays (every 15min?)
    _3150: [2, ("02",)],
}  # TODO dex: element_length, src.type(s) (and dst.type too)
#
RQ_IDX_COMPLEX = [
    _0005,  # context: zone_type
    _000A,  # optional payload
    _000C,  # context: index, zone_type
    _0016,  # optional payload
    _0100,  # optional payload
    _0404,  # context: index, fragment_idx (fragment_header)
    _10A0,  # optional payload
    _1100,  # optional payload
    _2309,  # optional payload
    _2349,  # optional payload
    _3220,  # context: msg_id, and payload
]
RQ_NO_PAYLOAD = [
    k
    for k, v in CODES_SCHEMA.items()
    if v.get(RQ)
    in (r"^FF$", r"^00$", r"^00(00)?$", r"^0[0-9A-F](00)?$", r"^0[0-9A-F]00$")
]
RQ_NO_PAYLOAD.extend((_0418,))

# IDX_COMPLEX - *usually has* a context, but doesn't satisfy criteria for IDX_SIMPLE:
# all known codes should be in only one of IDX_COMPLEX, IDX_NONE, IDX_SIMPLE
CODE_IDX_COMPLEX = [_0005, _000C, _1100, _3220]  # TODO: 0005 to ..._NONE?
CODE_IDX_COMPLEX.sort()

# IDX_SIMPLE - *can have* a context, but sometimes not (usu. 00): only ever payload[:2],
# either a zone_idx, domain_id or (UFC) circuit_idx (or array of such, i.e. seqx[:2])
CODE_IDX_SIMPLE = [
    k
    for k, v in CODES_SCHEMA.items()
    if k not in CODE_IDX_COMPLEX
    and (
        (RQ in v and v[RQ].startswith(("^0[0-9A-F]", "^(0[0-9A-F]")))
        or (I_ in v and v[I_].startswith(("^0[0-9A-F]", "^(0[0-9A-F]", "^((0[0-9A-F]")))
    )
]
CODE_IDX_SIMPLE.extend((_10A0, _1260, _1F41, _3B00))
CODE_IDX_SIMPLE.sort()

# IDX_NONE - *never has* a context: most payloads start 00, but no context even if the
# payload starts with something else (e.g. 2E04)
CODE_IDX_NONE = [
    k
    for k, v in CODES_SCHEMA.items()
    if k not in CODE_IDX_COMPLEX + CODE_IDX_SIMPLE
    and ((RQ in v and v[RQ][:3] == "^00") or (I_ in v and v[I_][:3] == "^00"))
]
CODE_IDX_NONE.extend(
    (_0002, _22F1, _22F3, _2389, _2E04, _31DA, _4401)
)  # 31DA does appear to have an idx?
CODE_IDX_NONE.sort()

# CODE_IDX_DOMAIN - NOTE: not necc. mutex with other 3
CODE_IDX_DOMAIN = {
    _0001: "^F[ACF])",
    _0008: "^F[9AC]",
    _0009: "^F[9AC]",
    _1100: "^FC",
    _1FC9: "^F[9ABCF]",
    _3150: "^FC",
    _3B00: "^FC",
}

#
########################################################################################
# CODES_BY_DEV_SLUG - HEAT (CH/DHW) vs HVAC (ventilation)
#
_DEV_KLASSES_HEAT: Dict[SimpleNamespace, Dict] = {
    DEV_TYPE.RFG: {  # RFG100: RF to Internet gateway (and others)
        _0002: {RQ: {}},
        _0004: {I_: {}, RQ: {}},
        _0005: {RQ: {}},
        _0006: {RQ: {}},
        _000A: {RQ: {}},
        _000C: {RQ: {}},
        _000E: {W_: {}},
        _0016: {RP: {}},
        _0404: {RQ: {}, W_: {}},
        _0418: {RQ: {}},
        _10A0: {RQ: {}},
        _10E0: {I_: {}, RQ: {}, RP: {}},
        _1260: {RQ: {}},
        _1290: {I_: {}},
        _1F41: {RQ: {}},
        _1FC9: {RP: {}, W_: {}},
        _22D9: {RQ: {}},
        _2309: {I_: {}},
        _2349: {RQ: {}, RP: {}, W_: {}},
        _2E04: {RQ: {}, I_: {}, W_: {}},
        _30C9: {RQ: {}},
        _313F: {RQ: {}, RP: {}, W_: {}},
        _3220: {RQ: {}},
        _3EF0: {RQ: {}},
    },
    DEV_TYPE.CTL: {  # e.g. ATC928: Evohome Colour Controller
        _0001: {W_: {}},
        _0002: {I_: {}, RP: {}},
        _0004: {I_: {}, RP: {}},
        _0005: {I_: {}, RP: {}},
        _0006: {RP: {}},
        _0008: {I_: {}},
        _0009: {I_: {}},
        _000A: {I_: {}, RP: {}},
        _000C: {RP: {}},
        _0016: {RQ: {}, RP: {}},
        _0100: {RP: {}},
        _01D0: {I_: {}},
        _01E9: {I_: {}},
        _0404: {I_: {}, RP: {}},
        _0418: {I_: {}, RP: {}},
        _1030: {I_: {}},
        _10A0: {I_: {}, RP: {}},
        _10E0: {RP: {}},
        _1100: {I_: {}, RQ: {}, RP: {}, W_: {}},
        _1260: {RP: {}},
        _1290: {RP: {}},
        _12B0: {I_: {}, RP: {}},
        _1F09: {I_: {}, RP: {}, W_: {}},
        _1FC9: {I_: {}, RQ: {}, RP: {}, W_: {}},
        _1F41: {I_: {}, RP: {}},
        _2249: {I_: {}},  # Hometronics, not Evohome
        _22D9: {RQ: {}},
        _2309: {I_: {}, RP: {}},
        _2349: {I_: {}, RP: {}},
        _2D49: {I_: {}},
        _2E04: {I_: {}, RP: {}},
        _30C9: {I_: {}, RP: {}},
        _313F: {I_: {}, RP: {}, W_: {}},
        _3150: {I_: {}},
        _3220: {RQ: {}},
        _3B00: {I_: {}},
        _3EF0: {RQ: {}},
    },
    DEV_TYPE.PRG: {  # e.g. HCF82/HCW82: Room Temperature Sensor
        _0009: {I_: {}},
        _1090: {RP: {}},
        _10A0: {RP: {}},
        _1100: {I_: {}},
        _1F09: {I_: {}},
        _2249: {I_: {}},
        _2309: {I_: {}},
        _30C9: {I_: {}},
        _3B00: {I_: {}},
        _3EF1: {RP: {}},
    },
    DEV_TYPE.THM: {  # e.g. Generic Thermostat
        _0001: {W_: {}},
        _0005: {I_: {}},
        _0008: {I_: {}},
        _0009: {I_: {}},
        _000A: {I_: {}, RQ: {}, W_: {}},
        _000C: {I_: {}},
        _000E: {I_: {}},
        _0016: {RQ: {}},
        _042F: {I_: {}},
        _1030: {I_: {}},
        _1060: {I_: {}},
        _1090: {RQ: {}},
        _10E0: {I_: {}},
        _1100: {I_: {}},
        _12C0: {I_: {}},
        _1F09: {I_: {}},
        _1FC9: {I_: {}},
        _2309: {I_: {}, RQ: {}, W_: {}},
        _2349: {RQ: {}, W_: {}},
        _30C9: {I_: {}},
        _3120: {I_: {}},
        _313F: {I_: {}},  # W --- 30:253184 34:010943 --:------ 313F 009 006000070E0...
        _3B00: {I_: {}},
        _3EF0: {RQ: {}},  # when bound direct to a 13:
        _3EF1: {RQ: {}},  # when bound direct to a 13:
    },
    DEV_TYPE.UFC: {  # e.g. HCE80/HCC80: Underfloor Heating Controller
        _0001: {RP: {}, W_: {}},  # TODO: Ix RP
        _0005: {RP: {}},
        _0008: {I_: {}},
        _000A: {RP: {}},
        _000C: {RP: {}},
        _1FC9: {I_: {}},
        _10E0: {I_: {}, RP: {}},
        _22C9: {I_: {}},  # NOTE: No RP
        _22D0: {I_: {}, RP: {}},
        _2309: {RP: {}},
        _3150: {I_: {}},
    },
    DEV_TYPE.TRV: {  # e.g. HR92/HR91: Radiator Controller
        _0001: {W_: {r"^0[0-9A-F]"}},
        _0004: {RQ: {r"^0[0-9A-F]00$"}},
        _0016: {RQ: {}, RP: {}},
        _0100: {RQ: {r"^00"}},
        _01D0: {W_: {}},
        _01E9: {W_: {}},
        _1060: {I_: {r"^0[0-9A-F]{3}0[01]$"}},
        _10E0: {I_: {r"^00[0-9A-F]{30,}$"}},
        _12B0: {I_: {r"^0[0-9A-F]{3}00$"}},  # sends every 1h
        _1F09: {RQ: {r"^00$"}},
        _1FC9: {I_: {}, W_: {}},
        _2309: {I_: {r"^0[0-9A-F]{5}$"}},
        _30C9: {I_: {r"^0[0-9A-F]"}},
        _313F: {RQ: {r"^00$"}},
        _3150: {I_: {r"^0[0-9A-F]{3}$"}},
    },
    DEV_TYPE.DHW: {  # e.g. CS92: (DHW) Cylinder Thermostat
        _0016: {RQ: {}},
        _1060: {I_: {}},
        _10A0: {RQ: {}},  # This RQ/07/10A0 includes a payload
        _1260: {I_: {}},
        _1FC9: {I_: {}},
    },
    DEV_TYPE.OTB: {  # e.g. R8810/R8820: OpenTherm Bridge
        _0009: {I_: {}},  # 1/24h for a R8820 (not an R8810)
        _0150: {RP: {}},  # R8820A only?
        _042F: {I_: {}, RP: {}},
        _1081: {RP: {}},  # R8820A only?
        _1098: {RP: {}},  # R8820A only?
        _10A0: {RP: {}},
        _10B0: {RP: {}},  # R8820A only?
        _10E0: {I_: {}, RP: {}},
        _10E1: {RP: {}},  # R8820A only?
        _1260: {RP: {}},
        _1290: {RP: {}},
        _12F0: {RP: {}},  # R8820A only?
        _1300: {RP: {}},  # R8820A only?
        _1FC9: {I_: {}, W_: {}},
        _1FD0: {RP: {}},  # R8820A only?
        _1FD4: {I_: {}},  # 2/min for R8810, every ~210 sec for R8820
        _22D9: {RP: {}},
        _2400: {RP: {}},  # R8820A only?
        _2401: {RP: {}},  # R8820A only?
        _2410: {RP: {}},  # R8820A only?
        _2420: {RP: {}},  # R8820A only?
        _3150: {I_: {}},
        _3200: {RP: {}},  # R8820A only?
        _3210: {RP: {}},  # R8820A only?
        _3220: {RP: {}},
        _3221: {RP: {}},  # R8820A only?
        _3223: {RP: {}},  # R8820A only?
        _3EF0: {I_: {}, RP: {}},
        _3EF1: {RP: {}},
    },  # see: https://www.opentherm.eu/request-details/?post_ids=2944
    DEV_TYPE.BDR: {  # e.g. BDR91A/BDR91T: Wireless Relay Box
        _0008: {RP: {}},  # doesn't RP/0009
        _0016: {RP: {}},
        # _10E0: {},  # 13: will not RP/10E0 # TODO: how to indicate that fact here
        _1100: {I_: {}, RP: {}},
        _11F0: {I_: {}},  # BDR91T in heatpump mode
        _1FC9: {RP: {}, W_: {}},
        _3B00: {I_: {}},
        _3EF0: {I_: {}},
        # RP: {},  # RQ --- 01:145038 13:237335 --:------ 3EF0 001 00
        _3EF1: {RP: {}},
    },
    DEV_TYPE.OUT: {
        _0002: {I_: {}},
        _1FC9: {I_: {}},
    },  # i.e. HB85 (ext. temperature/luminosity(lux)), HB95 (+ wind speed)
    #
    DEV_TYPE.JIM: {  # Jasper Interface Module, 08
        _0008: {RQ: {}},
        _10E0: {I_: {}},
        _1100: {I_: {}},
        _3EF0: {I_: {}},
        _3EF1: {RP: {}},
    },
    DEV_TYPE.JST: {  # Jasper Stat, 31
        _0008: {I_: {}},
        _10E0: {I_: {}},
        _3EF1: {RQ: {}, RP: {}},
    },
    # DEV_TYPE.RND: {  # e.g. TR87RF: Single (round) Zone Thermostat
    #     _0005: {I_: {}},
    #     _0008: {I_: {}},
    #     _000A: {I_: {}, RQ: {}},
    #     _000C: {I_: {}},
    #     _000E: {I_: {}},
    #     _042F: {I_: {}},
    #     _1060: {I_: {}},
    #     _10E0: {I_: {}},
    #     _12C0: {I_: {}},
    #     _1FC9: {I_: {}},
    #     _2309: {I_: {}, RQ: {}, W_: {}},
    #     _2349: {RQ: {}},
    #     _30C9: {I_: {}},
    #     _3120: {I_: {}},
    #     _313F: {I_: {}},  # W --- 30:253184 34:010943 --:------ 313F 009 006000070E0...
    #     _3EF0: {RQ: {}},  # when bound direct to a 13:
    #     _3EF1: {RQ: {}},  # when bound direct to a 13:
    # },
    # DEV_TYPE.DTS: {  # e.g. DTS92(E)
    #     _0001: {W_: {}},
    #     _0008: {I_: {}},
    #     _0009: {I_: {}},
    #     _000A: {I_: {}, RQ: {}, W_: {}},
    #     _0016: {RQ: {}},
    #     # "0B04": {I_: {}},
    #     _1030: {I_: {}},
    #     _1060: {I_: {}},
    #     _1090: {RQ: {}},
    #     _1100: {I_: {}},
    #     _1F09: {I_: {}},
    #     _1FC9: {I_: {}},
    #     _2309: {I_: {}, RQ: {}, W_: {}},
    #     _2349: {RQ: {}, W_: {}},
    #     _30C9: {I_: {}},
    #     _313F: {I_: {}},
    #     _3B00: {I_: {}},
    #     _3EF1: {RQ: {}},
    # },
    # DEV_TYPE.HCW: {  # e.g. HCF82/HCW82: Room Temperature Sensor
    #     _0001: {W_: {}},
    #     _0002: {I_: {}},
    #     _0008: {I_: {}},
    #     _0009: {I_: {}},
    #     _1060: {I_: {}},
    #     _1100: {I_: {}},
    #     _1F09: {I_: {}},
    #     _1FC9: {I_: {}},
    #     _2309: {I_: {}},
    #     _2389: {I_: {}},
    #     _30C9: {I_: {}},
    # },
}
# TODO: add 1FC9 everywhere?
_DEV_KLASSES_HVAC: Dict[SimpleNamespace, Dict] = {
    DEV_TYPE.RFS: {  # Itho spIDer: RF to Internet gateway (like a RFG100)
        _1060: {I_: {}},
        _10E0: {I_: {}, RP: {}},
        _12C0: {I_: {}},
        _22C9: {I_: {}},
        _22F1: {I_: {}},
        _22F3: {I_: {}},
        _2E10: {I_: {}},
        _30C9: {I_: {}},
        _3110: {I_: {}},
        _3120: {I_: {}},
        _31D9: {RQ: {}},
        _31DA: {RQ: {}},
        _3EF0: {I_: {}},
    },
    DEV_TYPE.FAN: {
        _0001: {RP: {}},
        _042F: {I_: {}},
        _10E0: {I_: {}, RP: {}},
        _1298: {I_: {}},
        _12A0: {I_: {}},
        _12C8: {I_: {}},
        _1470: {RP: {}},
        _1F09: {I_: {}, RP: {}},
        _1FC9: {W_: {}},
        _22F7: {I_: {}, RP: {}},
        _2411: {I_: {}, RP: {}},
        _3120: {I_: {}},
        _313F: {I_: {}, RP: {}},
        _31D9: {I_: {}, RP: {}},
        _31DA: {I_: {}, RP: {}},
        # _31E0: {I_: {}},
    },
    DEV_TYPE.CO2: {
        _042F: {I_: {}},
        _10E0: {I_: {}, RP: {}},
        _1298: {I_: {}},
        _1FC9: {I_: {}},
        _2411: {RQ: {}},
        _2E10: {I_: {}},
        _3120: {I_: {}},
        _31DA: {RQ: {}},
        _31E0: {I_: {}},
    },
    DEV_TYPE.HUM: {
        _042F: {I_: {}},
        _1060: {I_: {}},
        _10E0: {I_: {}},
        _12A0: {I_: {}},
        _1FC9: {I_: {}},
        _31DA: {RQ: {}},
        _31E0: {I_: {}},
    },
    DEV_TYPE.SWI: {  # HVAC: two-way switch; also an "06/22F1"?
        _0001: {RQ: {}},  # from a VMI (only?)
        _042F: {I_: {}},  # from a VMI (only?)
        _1060: {I_: {}},
        _10E0: {I_: {}, RQ: {}},  # RQ from a VMI (only?)
        _1470: {RQ: {}},  # from a VMI (only?)
        _1FC9: {I_: {}},
        _22F1: {I_: {}},
        _22F3: {I_: {}},
        _22F7: {RQ: {}, W_: {}},  # from a VMI (only?)
        _2411: {RQ: {}, W_: {}},  # from a VMI (only?)
        _313F: {RQ: {}, W_: {}},  # from a VMI (only?)
        _31DA: {RQ: {}},  # to a VMI (only?)
        # _31E0: {I_: {}},
    },  # https://www.ithodaalderop.nl/nl-NL/professional/product/536-0124
    None: {  # unknown, TODO: make generic HVAC
        _4401: {I_: {}},
    },
}

CODES_BY_DEV_SLUG: Dict[SimpleNamespace, Dict] = {
    DEV_TYPE.HGI: {  # HGI80: RF to (USB) serial gateway interface
        _PUZZ: {I_: {}, RQ: {}, W_: {}},
    },  # HGI80s can do what they like
    **{k: v for k, v in _DEV_KLASSES_HVAC.items() if k is not None},
    **{k: v for k, v in _DEV_KLASSES_HEAT.items() if k is not None},
}

_CODES_EXCLUDED = (
    _0001,
    _0002,
    _000E,
    _0016,
    _0100,
    _0150,
    _01D0,
    _01E9,
    _0B04,
    _10E0,
    _1FC9,
)
_CODES_HEAT = dict.fromkeys(
    c for k in _DEV_KLASSES_HEAT.values() for c in k if c not in _CODES_EXCLUDED
)
_CODES_HVAC = dict.fromkeys(
    c for k in _DEV_KLASSES_HVAC.values() for c in k if c not in _CODES_EXCLUDED
)
CODES_HEAT_ONLY = tuple(c for c in sorted(list(_CODES_HEAT)) if c not in _CODES_HVAC)
CODES_HVAC_ONLY = tuple(c for c in sorted(list(_CODES_HVAC)) if c not in _CODES_HEAT)

_CODE_FROM_NON_CTL = dict.fromkeys(
    c
    for k, v1 in CODES_BY_DEV_SLUG.items()
    for c, v2 in v1.items()
    if k != DEV_TYPE.CTL and (I_ in v2 or RP in v2)
)
_CODE_FROM_CTL = _DEV_KLASSES_HEAT[DEV_TYPE.CTL].keys()

_CODE_ONLY_FROM_CTL = tuple(c for c in _CODE_FROM_CTL if c not in _CODE_FROM_NON_CTL)
CODES_ONLY_FROM_CTL = [_1030, _1F09, _22D0, _313F]  # I packets, TODO: 31Dx too?

#
########################################################################################
# CODES_BY_ZONE_TYPE
#
# RAMSES_ZONES = {
#     "ALL": {
#         _0004: {I_: {}, RP: {}},
#         _000C: {RP: {}},
#         _000A: {I_: {}, RP: {}},
#         _2309: {I_: {}, RP: {}},
#         _2349: {I_: {}, RP: {}},
#         _30C9: {I_: {}, RP: {}},
#     },
#     ZON_ROLE.RAD: {
#         _12B0: {I_: {}, RP: {}},
#         "3150a": {},
#     },
#     ZON_ROLE.ELE: {
#         _0008: {I_: {}},
#         _0009: {I_: {}},
#     },
#     ZON_ROLE.VAL: {
#         _0008: {I_: {}},
#         _0009: {I_: {}},
#         "3150a": {},
#     },
#     ZON_ROLE.UFH: {
#         _3150: {I_: {}},
#     },
#     ZON_ROLE.MIX: {
#         _0008: {I_: {}},
#         "3150a": {},
#     },
#     ZON_ROLE.DHW: {
#         _10A0: {RQ: {}, RP: {}},
#         _1260: {I_: {}},
#         _1F41: {I_: {}},
#     },
# }
# RAMSES_ZONES_ALL = RAMSES_ZONES.pop("ALL")
# RAMSES_ZONES_DHW = RAMSES_ZONES[ZON_ROLE.DHW]
# [RAMSES_ZONES[k].update(RAMSES_ZONES_ALL) for k in RAMSES_ZONES if k != ZON_ROLE.DHW]

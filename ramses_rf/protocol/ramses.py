#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser."""

import logging
from datetime import timedelta as td

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
    _1FCA,
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

DEV_MODE = True or __dev_mode__

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)

RQ_NULL = "rq_null"
EXPIRES = "expires"

NAME = "name"
EXPIRY = "expiry"

# The master list - all known codes are here, even if there's no corresponding parser
# Anything with a zone-idx should start: ^0[0-9A-F], ^(0[0-9A-F], or ^((0[0-9A-F]
#
##############
# RAMSES_CODES
#
RAMSES_CODES = {  # rf_unknown
    _0001: {
        NAME: "rf_unknown",
        W_: r"^(0[0-9A-F]|F[ACF])000005(05|01)$",
    },  # TODO: there appears to be a RQ/RP for UFC
    _0002: {  # WIP: outdoor_sensor
        NAME: "outdoor_sensor",
        I_: r"^0[0-4][0-9A-F]{4}(00|01|02|05)$",  # Domoticz sends ^02!!
        RQ: r"^00$",  # NOTE: sent by an RFG100
        RP: r"^00[0-9A-F]{4}(00|01)$",  # 007FFF00 is null resp?
    },
    _0004: {  # zone_name
        NAME: "zone_name",
        I_: r"^0[0-9A-F]00([0-9A-F]){40}$",  # RP is same, null_rp: xxxx,7F*20
        RQ: r"^0[0-9A-F]00$",
        EXPIRES: td(days=1),
    },
    _0005: {  # system_zones
        NAME: "system_zones",
        #  I --- 34:092243 --:------ 34:092243 0005 012 000A0000-000F0000-00100000
        I_: r"^(00[01][0-9A-F]{5}){1,3}$",
        RQ: r"^00[01][0-9A-F]$",  # f"00{zone_type}", evohome wont respond to 00
        RP: r"^00[01][0-9A-F]{5}$",
        EXPIRES: False,
    },
    _0006: {  # schedule_sync  # TODO: what for DHW schedule?
        NAME: "schedule_sync",
        RQ: r"^00$",
        RP: r"^0005[0-9A-F]{4}$",
    },
    _0008: {  # relay_demand, TODO: check RP
        NAME: "relay_demand",
        # 000 I --- 31:012319 08:006244 --:------ 0008 013 0006958C33CA6ECD2067AA53DD
        I_: r"^((0[0-9A-F]|F[9AC])[0-9A-F]{2}|00[0-9A-F]{24})$",
        RQ: r"^00$",
        RP: r"^00[0-9A-F]{2}$",  # seems only 13: RP (TODO: what about 10:, 08/31:)
    },
    _0009: {  # relay_failsafe (only is_controller, OTB send an 0009?)
        NAME: "relay_failsafe",
        #  I --- 01:145038 --:------ 01:145038 0009 006 FC01FFF901FF
        #  I --- 01:145038 --:------ 01:145038 0009 003 0700FF
        #  I --- 10:040239 01:223036 --:------ 0009 003 000000
        #  I --- --:------ --:------ 12:227486 0009 003 0000FF
        I_: r"^((0[0-9A-F]|F[9AC])0[0-1](00|FF))+$",
    },
    _000A: {  # zone_params
        NAME: "zone_params",
        I_: r"^(0[0-9A-F][0-9A-F]{10}){1,8}$",
        RQ: r"^0[0-9A-F]((00)?|([0-9A-F]{10})+)$",  # is: r"^0[0-9A-F]([0-9A-F]{10})+$"
        RP: r"^0[0-9A-F]([0-9A-F]{10})+$",  # null_rp: xx,007FFF7FFF
        # 17:54:13.126 063 RQ --- 34:064023 01:145038 --:------ 000A 001 03
        # 17:54:13.141 045 RP --- 01:145038 34:064023 --:------ 000A 006 031002260B86
        # 19:20:49.460 062 RQ --- 12:010740 01:145038 --:------ 000A 006 080001F40DAC
        # 19:20:49.476 045 RP --- 01:145038 12:010740 --:------ 000A 006 081001F40DAC
        EXPIRES: td(days=1),
    },
    _000C: {  # zone_devices, TODO: needs I/RP
        NAME: "zone_devices",
        # RP --- 01:145038 18:013393 --:------ 000C 012 0100-00-10DAF5,0100-00-10DAFB
        I_: r"^(0[0-9A-F][01][0-9A-F](0[0-9A-F]|7F)[0-9A-F]{6}){1,8}$",
        RQ: r"^0[0-9A-F][01][0-9A-F]$",  # TODO: f"{zone_idx}{device_type}"
        EXPIRES: False,
    },
    _000E: {  # unknown
        NAME: "message_000e",
        I_: r"^000014$",
    },
    _0016: {  # rf_check
        NAME: "rf_check",
        RQ: r"^0[0-9A-F]([0-9A-F]{2})?$",  # TODO: officially: r"^0[0-9A-F]{3}$"
        RP: r"^0[0-9A-F]{3}$",
    },
    _0100: {  # language
        NAME: "language",
        RQ: r"^00([0-9A-F]{4}F{4})?$",  # NOTE: RQ/04/0100 has a payload
        RP: r"^00[0-9A-F]{4}F{4}$",
        EXPIRES: td(days=1),  # TODO: make longer?
    },
    _01D0: {  # TODO: not well understood, definitely a real code, zone_idx is a guess
        NAME: "message_01d0",
        I_: r"^0[0-9A-F][0-9A-F]{2}$",
        W_: r"^0[0-9A-F][0-9A-F]{2}$",
        #  W --- 04:000722 01:158182 --:------ 01D0 002 0003  # is a guess, the
        #  I --- 01:158182 04:000722 --:------ 01D0 002 0003  # TRV was in zone 00
    },
    _01E9: {  # TODO: not well understood, definitely a real code, zone_idx is a guess
        NAME: "message_01e9",
        I_: r"^0[0-9A-F][0-9A-F]{2}$",
        W_: r"^0[0-9A-F][0-9A-F]{2}$",
        #  W --- 04:000722 01:158182 --:------ 01E9 002 0003  # is a guess, the
        #  I --- 01:158182 04:000722 --:------ 01E9 002 0000  # TRV was in zone 00
    },
    _0404: {  # zone_schedule
        NAME: "zone_schedule",
        RP: r"^0[0-9A-F](20|23)0008[0-9A-F]{6}[0-9A-F]{2,82}$",
        RQ: r"^0[0-9A-F](20|23)000800[0-9A-F]{4}$",
    },
    _0418: {  # system_fault
        NAME: "system_fault",
        I_: r"^00(00|40|C0)[0-3][0-9A-F]B0[0-9A-F]{6}0000[0-9A-F]{12}FFFF7000[0-9A-F]{6}$",
        RQ: r"^0000[0-3][0-9A-F]$",  # f"0000{log_idx}", no payload
    },
    _042F: {  # unknown, # non-evohome are len==9, seen only once?
        # .I --- 32:168090 --:------ 32:168090 042F 009 000000100F00105050
        NAME: "message_042f",
        I_: r"^00([0-9A-F]{2}){7}$",
    },
    _0B04: {  # unknown
        #  I --- --:------ --:------ 12:207082 0B04 002 00C8
        NAME: "message_0b04",
        I_: r"^00(00|C8)$",
    },
    _1030: {  # mixvalve_params
        NAME: "mixvalve_params",
        #  I --- --:------ --:------ 12:138834 1030 016 01C80137C9010FCA0196CB010FCC0101
        I_: r"^0[0-9A-F](C[89A-C]01[0-9A-F]{2}){5}$",
    },
    _1060: {  # device_battery
        NAME: "device_battery",
        I_: r"^0[0-9A-F](FF|[0-9A-F]{2})0[01]$",
        EXPIRES: td(days=1),
    },
    _1090: {  # unknown
        NAME: "message_1090",
        # RQ: r"^00$",  # TODO:
    },
    _10A0: {  # dhw_params
        NAME: "dhw_params",
        # RQ --- 07:045960 01:145038 --:------ 10A0 006 0013740003E4
        # NOTE: RFG100 uses a domain id! (00|01)
        # 19:14:24.662 051 RQ --- 30:185469 01:037519 --:------ 10A0 001 00
        # 19:14:31.463 053 RQ --- 30:185469 01:037519 --:------ 10A0 001 01
        RQ: r"^0[01]([0-9A-F]{10})?$",  # NOTE: RQ/07/10A0 has a payload
        EXPIRES: td(hours=4),
    },
    _10E0: {  # device_info
        NAME: "device_info",
        I_: r"^00[0-9A-F]{30,}$",  # NOTE: RP is same
        RQ: r"^00$",  # NOTE: will accept [0-9A-F]{2}
        # RP: r"^[0-9A-F]{2}([0-9A-F]){30,}$",  # NOTE: indx same as RQ
        EXPIRES: False,
    },
    _1100: {  # tpi_params
        NAME: "tpi_params",
        # RQ --- 01:145038 13:163733 --:------ 1100 008 00180400007FFF01  # boiler relay
        # RP --- 13:163733 01:145038 --:------ 1100 008 00180400FF7FFF01
        # RQ --- 01:145038 13:035462 --:------ 1100 008 FC240428007FFF01  # not bolier relay
        # RP --- 13:035462 01:145038 --:------ 1100 008 00240428007FFF01
        RQ: r"^(00|FC)([0-9A-F]{6}(00|FF)([0-9A-F]{4}01)+)?$",  # RQ/13:/00, or RQ/01:/FC:
        RP: r"^(00|FC)[0-9A-F]{6}(00|FF)([0-9A-F]{4}01)+$",
        W_: r"^(00|FC)[0-9A-F]{6}(00|FF)([0-9A-F]{4}01)+$",  # TODO: is there no I?
        EXPIRES: td(days=1),
    },
    _1260: {  # dhw_temp
        NAME: "dhw_temp",
        # RQ --- 30:185469 01:037519 --:------ 1260 001 00
        # RP --- 01:037519 30:185469 --:------ 1260 003 000837
        # RQ --- 18:200202 10:067219 --:------ 1260 002 0000
        # RP --- 10:067219 18:200202 --:------ 1260 003 007FFF
        #  I --- 07:045960 --:------ 07:045960 1260 003 0007A9
        I_: r"^00[0-9A-F]{4}$",  # NOTE: RP is same
        RQ: r"^00(00)?$",  # TODO: officially: r"^00$"
        EXPIRES: td(hours=1),
    },
    _1280: {  # outdoor_humidity
        NAME: "outdoor_humidity",
    },
    _1290: {  # outdoor_temp
        NAME: "outdoor_temp",
        I_: r"^00[0-9A-F]{4}$",  # NOTE: RP is same
        RQ: r"^00$",
    },
    _1298: {  # hvac_1298 - temperature/C?
        NAME: "hvac_1298",
        I_: r"^00[0-9A-F]{4}$",
    },
    _12A0: {  # indoor_humidity
        NAME: "indoor_humidity",
        I_: r"^00[0-9A-F]{10}$",
        EXPIRES: td(hours=1),
    },
    _12B0: {  # window_state  (HVAC % window open)
        NAME: "window_state",
        I_: r"^0[0-9A-F](0000|C800|FFFF)$",  # NOTE: RP is same
        RQ: r"^0[0-9A-F](00)?$",
        EXPIRES: td(hours=1),
    },
    _12C0: {  # displayed_temp (HVAC room temp)
        NAME: "displayed_temp",  # displayed room temp
        I_: r"^00[0-9A-F]{2}01$",
    },
    _12C8: {  # hvac_12C8 - %?
        NAME: "hvac_12C8",
        I_: r"^0000[0-9A-F]{2}$",
    },
    _1F09: {  # system_sync - "FF" (I), "00" (RP), "F8" (W, after 1FC9)
        NAME: "system_sync",
        I_: r"^(00|01|DB|FF)[0-9A-F]{4}$",  # FF is evohome, DB is Hometronics
        RQ: r"^00$",
        RP: r"^00[0-9A-F]{4}$",  # xx-secs
        W_: r"^F8[0-9A-F]{4}$",
    },
    _1F41: {  # dhw_mode
        NAME: "dhw_mode",
        I_: r"^00(00|01|FF)0[0-5]F{6}(([0-9A-F]){12})?$",
        RQ: r"^00$",  # will accept: r"^00(00)$"
        W_: r"^00(00|01|FF)0[0-5]F{6}(([0-9A-F]){12})?$",
        EXPIRES: td(hours=4),
    },
    _1FC9: {  # rf_bind
        # RP --- 13:035462 18:013393 --:------ 1FC9 018 00-3EF0-348A86 00-11F0-348A86 90-3FF1-956ABD
        # RP --- 13:035462 18:013393 --:------ 1FC9 018 00-3EF0-348A86 00-11F0-348A86 90-7FE1-DD6ABD
        # RP --- 01:145038 18:013393 --:------ 1FC9 012 FF-10E0-06368E FF-1FC9-06368E
        NAME: "rf_bind",
        RQ: r"^00$",
        RP: r"^((0[0-9A-F]|F[9ABCF]|90)([0-9A-F]{10}))+$",  # xx-code-dev_id
        I_: r"^((0[0-9A-F]|F[9ABCF])([0-9A-F]{10}))+$",
        W_: r"^((0[0-9A-F]|F[9ABCF])([0-9A-F]{10}))+$",
    },
    _1FCA: {  # unknown
        #  W --- 30:248208 34:021943 --:------ 1FCA 009 00-01FF-7BC990-FFFFFF  # sent x2
        # RP --- 30:248208 18:006402 --:------ 1FCA 009 00-xxxx-302E31-322E30  # 2 STAs
        NAME: "message_1fca",
        W_: r"^00[0-9A-F]{4}[0-9A-F]{12}$",
    },
    _1FD4: {  # opentherm_sync
        NAME: "opentherm_sync",
        I_: r"^00([0-9A-F]{4})$",
    },
    _2249: {
        NAME: "setpoint_now",  # setpt_now_next
        I_: r"^(0[0-9A-F]{13}){1,2}$",
    },  # TODO: This could be an array
    _22C9: {  # ufh_setpoint
        #  I --- 02:001107 --:------ 02:001107 22C9 024 0008340A2801-0108340A2801-0208340A2801-0308340A2801  # noqa
        #  I --- 02:001107 --:------ 02:001107 22C9 006 04-0834-0A28-01
        NAME: "ufh_setpoint",
        I_: r"^(0[0-9A-F][0-9A-F]{8}01){1,4}$",  # ~000A array, but max_len 24, not 48!
        # RQ: None?,
    },
    _22D0: {  # HVAC system switch
        NAME: "message_22d0",
        I_: r"^00000002$",  # TODO:
    },
    _22D9: {  # boiler_setpoint
        NAME: "boiler_setpoint",
        RQ: r"^00$",
        RP: r"^00[0-9A-F]{4}$",
    },
    _22F1: {  # switch_speed - TODO - change name - Sent by an UFC
        NAME: "switch_speed",
        I_: r"^00(0[0-9A-F]){2}$",
    },
    _22F3: {  # switch_duration
        NAME: "switch_duration",
        I_: r"^0000[0-9A-F]{2}$",
    },  # minutes
    _2309: {  # setpoint
        NAME: "setpoint",
        I_: r"^(0[0-9A-F]{5})+$",
        # RQ --- 12:010740 01:145038 --:------ 2309 003 03073A # No RPs
        RQ: r"^0[0-9A-F]([0-9A-F]{4})?$",  # NOTE: 12 uses: r"^0[0-9A-F]$"
        EXPIRES: td(minutes=30),
    },
    _2349: {  # zone_mode
        NAME: "zone_mode",
        I_: r"^0[0-9A-F]([0-9A-F]{12}){1,2}$",
        # RQ --- 22:070483 01:063844 --:------ 2349 007 06070803000027
        RQ: r"^0[0-9A-F](00|[0-9A-F]{12})?$",
        EXPIRES: td(hours=4),
    },
    _2D49: {  # unknown
        NAME: "message_2d49",
        # 10:14:08.526 045  I --- 01:023389 --:------ 01:023389 2D49 003 010000
        # 10:14:12.253 047  I --- 01:023389 --:------ 01:023389 2D49 003 00C800
        # 10:14:12.272 047  I --- 01:023389 --:------ 01:023389 2D49 003 01C800
        # 10:14:12.390 049  I --- 01:023389 --:------ 01:023389 2D49 003 880000
        # 10:14:12.399 048  I --- 01:023389 --:------ 01:023389 2D49 003 FD0000
        I_: r"^(0[0-9A-F]|88|FD)[0-9A-F]{2}00$",
    },  # seen with Hometronic systems
    _2E04: {  # system_mode
        NAME: "system_mode",
        I_: r"^0[0-7][0-9A-F]{12}0[01]$",  # evo: r"^0[0-7][0-9A-F]{12}0[01]$",
        RQ: r"^FF$",
        W_: r"^0[0-7][0-9A-F]{12}0[01]$",
        EXPIRES: td(hours=4),
    },
    _30C9: {  # temperature
        NAME: "temperature",
        I_: r"^(0[0-9A-F][0-9A-F]{4})+$",
        RQ: r"^0[0-9A-F](00)?$",  # TODO: officially: r"^0[0-9A-F]$"
        RP: r"^0[0-9A-F][0-9A-F]{4}$",  # Null: r"^0[0-9A-F]7FFF$"
        EXPIRES: td(hours=1),
    },
    _3120: {  # unknown - Error Report?
        NAME: "message_3120",
        I_: r"^00[0-9A-F]{10}FF$",  # only ever: 34:/0070B0000000FF
        RQ: r"^00$",  # 20: will RP an RQ?
        # RP: r"^00[0-9A-F]{10}FF$",  # only ever: 20:/0070B000009CFF
    },
    _313F: {  # datetime (time report)
        NAME: "datetime",
        I_: r"^00[0-9A-F]{16}$",  # NOTE: RP is same
        RQ: r"^00$",
        W_: r"^00[0-9A-F]{16}$",
        EXPIRES: td(seconds=3),
    },
    _3150: {  # heat_demand
        NAME: "heat_demand",
        I_: r"^((0[0-9A-F])[0-9A-F]{2}|FC[0-9A-F]{2})+$",
        EXPIRES: td(minutes=20),
    },
    _31D9: {  # ventilation_status
        NAME: "vent_status",
        # I_: r"^(00|21)[0-9A-F]{32}$",
        I_: r"^(00|01|21)[0-9A-F]{4}([02]{28})?$",
        RQ: r"^00$",
    },
    _31DA: {  # ventilation_unknown
        NAME: "vent_31da",
        I_: r"^(00|01|21)[0-9A-F]{56}(00)?$",
        RQ: r"^(00|01|21)$"
        # RQ --- 32:168090 30:082155 --:------ 31DA 001 21
    },
    _31E0: {  # ext_ventilation - External Ventilation Status
        NAME: "ext_ventilation",
        I_: r"^0000(00|C8)00$",
    },
    _3220: {  # opentherm_msg
        NAME: "opentherm_msg",
        RQ: r"^00[0-9A-F]{4}0{4}$",  # is strictly: r"^00[0-9A-F]{8}$",
        RP: r"^00[0-9A-F]{8}$",
    },
    _3B00: {  # actuator_sync, NOTE: no RQ
        NAME: "actuator_sync",
        I_: r"^(00|FC)(00|C8)$",
    },
    _3EF0: {  # actuator_state
        NAME: "actuator_state",
        # .I --- 13:106039 --:------ 13:106039 3EF0 003 00C8FF
        # .I --- 10:030051 --:------ 10:030051 3EF0 009 000010000000020A64
        # .I --- 08:031043 31:077159 --:------ 3EF0 020 001191A72044399D2A50DE43F920478AF7185F3F  # Jasper
        I_: r"^00((00|C8)FF|[0-9A-F]{16}|[0-9A-F]{38})$",  # NOTE: latter is Japser
        RQ: r"^00(00)?$",
        RP: r"^00((00|C8)FF|[0-9A-F]{10}|[0-9A-F]{16})$",
    },
    _3EF1: {  # actuator_cycle
        NAME: "actuator_cycle",
        # RQ --- 31:004811 13:077615 --:------ 3EF1 001 00
        # RP --- 13:077615 31:004811 --:------ 3EF1 007 00024D001300FF
        # RQ --- 22:068154 13:031208 --:------ 3EF1 002 0000
        # RP --- 13:031208 22:068154 --:------ 3EF1 007 00024E00E000FF
        # RQ --- 31:074182 08:026984 --:------ 3EF1 012 0005D1341DA39B8C7DAFD4C1
        # RP --- 08:026984 31:074182 --:------ 3EF1 018 001396A7E087922FA77794280B66BE16A975
        RQ: r"^00((00)?|[0-9A-F]{22})$",  # NOTE: latter is Japser
        RP: r"^00([0-9A-F]{12}|[0-9A-F]{34})$",  # NOTE: latter is Japser
    },
    _PUZZ: {
        NAME: "puzzle_packet",
        I_: r"^00[0-9A-F]{12}7F[0-9A-F]{4}7F[0-9A-F]{4}(7F)+",
    },
}
for code in RAMSES_CODES.values():
    if RQ in code and RP not in code and I_ in code:
        code[RP] = code[I_]

CODE_ONLY_FROM_CTL = [_1030, _1F09, _22D0, _313F]  # I packets, TODO: 31Dx too?

#
CODES_WITH_ARRAYS = {
    _0009: [3, ("01", "12", "22")],
    _000A: [6, ("01", "12", "22")],
    _2309: [3, ("01", "12", "22")],
    _30C9: [3, ("01", "12", "22")],
    _2249: [7, ("23",)],
    _22C9: [6, ("02",)],
    _3150: [2, ("02",)],
}  # element_length, src.type(s) (and dst.type too)

#
CODE_RQ_COMPLEX = [
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
    _3120,  # context: msg_id, and payload
]
# CODE_RQ_COMPLEX = []
RQ_NO_PAYLOAD = [
    k
    for k, v in RAMSES_CODES.items()
    if v.get(RQ)
    in (r"^FF$", r"^00$", r"^00(00)?$", r"^0[0-9A-F](00)?$", r"^0[0-9A-F]00$")
]
RQ_NO_PAYLOAD.extend((_0418,))
RQ_IDX_ONLY = [
    k
    for k, v in RAMSES_CODES.items()
    if k not in RQ_NO_PAYLOAD
    and RQ in v
    and (v[RQ] in (r"^0[0-9A-F]00$", r"^0[0-9A-F](00)?$"))
]
RQ_IDX_ONLY.extend((_0418,))  # _31D9, _31DA, _3220, _3EF1))
CODE_RQ_UNKNOWN = [
    k
    for k, v in RAMSES_CODES.items()
    if k not in RQ_NO_PAYLOAD + RQ_IDX_ONLY and RQ in v
]
RQ_NO_PAYLOAD.sort()  # or print(f"no: idx, ctx, payload = {list(RQ_NO_PAYLOAD)}")
RQ_IDX_ONLY.sort()  # or print(f"     no: ctx, payload = {list(RQ_IDX_ONLY)}")
CODE_RQ_COMPLEX.sort()  # or print(f"          no: payload = {list(CODE_RQ_COMPLEX)}")
CODE_RQ_UNKNOWN.sort()  # or print(f"unknown  = {list(CODE_RQ_UNKNOWN)}\r\n")

# IDX_COMPLEX - *usually has* a context, but doesn't satisfy criteria for IDX_SIMPLE:
# all known codes are in one of IDX_COMPLEX, IDX_NONE, IDX_SIMPLE
CODE_IDX_COMPLEX = [_0005, _000C, _1100, _3220]  # TODO: move 0005 to ..._NONE?

# IDX_SIMPLE - *can have* a context, but sometimes not (usu. 00): only ever payload[:2],
# either a zone_idx, domain_id or (UFC) circuit_idx (or array of such, i.e. seqx[:2])
CODE_IDX_SIMPLE = [
    k
    for k, v in RAMSES_CODES.items()
    if k not in CODE_IDX_COMPLEX
    and (
        (RQ in v and v[RQ].startswith(("^0[0-9A-F]", "^(0[0-9A-F]")))
        or (I_ in v and v[I_].startswith(("^0[0-9A-F]", "^(0[0-9A-F]", "^((0[0-9A-F]")))
    )
]
CODE_IDX_SIMPLE.extend((_10A0, _1100, _3B00))

# IDX_NONE - *never has* a context: most payloads start 00, but no context even if the
# payload starts with something else (e.g. 2E04)
CODE_IDX_NONE = [
    k
    for k, v in RAMSES_CODES.items()
    if k not in CODE_IDX_COMPLEX + CODE_IDX_SIMPLE
    and ((RQ in v and v[RQ][:3] == "^00") or (I_ in v and v[I_][:3] == "^00"))
]
CODE_IDX_NONE.extend((_0001, _2E04, _31DA, _PUZZ))  # 31DA does appear to have an idx?
#
#
_CODE_IDX_UNKNOWN = [
    k
    for k, v in RAMSES_CODES.items()
    if k not in CODE_IDX_COMPLEX + CODE_IDX_NONE + CODE_IDX_SIMPLE
]  # TODO: remove as not needed?
#
CODE_IDX_DOMAIN = {  # not necc. mutex
    _0001: "^F[ACF])",
    _0008: "^F[9AC]",
    _0009: "^F[9AC]",
    _1100: "^FC",
    _1FC9: "^F[9ABCF]",
    _3150: "^FC",
    _3B00: "^FC",
}
#
CODE_IDX_COMPLEX.sort()  # or print(f"complex = {CODE_IDX_COMPLEX}")  # TODO: remove
CODE_IDX_NONE.sort()  # or print(f"none    = {CODE_IDX_NONE}")  # TODO: remove
CODE_IDX_SIMPLE.sort()  # or print(f"simple  = {CODE_IDX_SIMPLE}")  # TODO: remove
_CODE_IDX_UNKNOWN.sort()  # or print(f"unknown = {_CODE_IDX_UNKNOWN}")  # TODO: remove
# print(f"domains = {list(CODE_IDX_DOMAIN)}")

################
# RAMSES_DEVICES
#
RAMSES_DEVICES = {
    "01": {  # e.g. ATC928: Evohome Colour Controller
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
        _1FCA: {W_: {}},
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
    "02": {  # e.g. HCE80/HCC80: Underfloor Heating Controller
        _0001: {RP: {}, W_: {}},  # TODO: Ix RP
        _0005: {RP: {}},
        _0008: {I_: {}},
        _000A: {RP: {}},
        _000C: {RP: {}},
        _10E0: {I_: {}, RP: {}},
        _22C9: {I_: {}},  # NOTE: No RP
        _22D0: {I_: {}, RP: {}},
        _22F1: {I_: {}},
        _2309: {RP: {}},
        _3150: {I_: {}},
    },
    "03": {  # e.g. HCF82/HCW82: Room Temperature Sensor
        _0001: {W_: {}},
        _0008: {I_: {}},
        _0009: {I_: {}},
        _1060: {I_: {}},
        _1100: {I_: {}},
        _1F09: {I_: {}},
        _1FC9: {I_: {}},
        _2309: {I_: {}},
        _30C9: {I_: {}},
    },
    "04": {  # e.g. HR92/HR91: Radiator Controller
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
    "07": {  # e.g. CS92: (DHW) Cylinder Thermostat
        _0016: {RQ: {}},
        _1060: {I_: {}},
        _10A0: {RQ: {}},  # This RQ/07/10A0 includes a payload
        _1260: {I_: {}},
        _1FC9: {I_: {}},
    },
    "08": {
        _0008: {RQ: {}},
        _10E0: {I_: {}},
        _1100: {I_: {}},
        _3EF0: {I_: {}},
        _3EF1: {RP: {}},
    },
    "10": {  # e.g. R8810/R8820: OpenTherm Bridge
        _0009: {I_: {}},  # 1/24h for a R8820 (not an R8810)
        _10A0: {RP: {}},
        _10E0: {I_: {}, RP: {}},
        _1260: {RP: {}},
        _1290: {RP: {}},
        _1FC9: {I_: {}, W_: {}},
        _1FD4: {I_: {}},
        _22D9: {RP: {}},
        _3150: {I_: {}},
        _3220: {RP: {}},
        _3EF0: {I_: {}, RP: {}},
        _3EF1: {RP: {}},
    },  # see: https://www.opentherm.eu/request-details/?post_ids=2944
    "12": {  # e.g. DTS92(E): Digital Room Thermostat
        _0001: {W_: {}},
        _0008: {I_: {}},
        _0009: {I_: {}},
        _000A: {I_: {}, RQ: {}, W_: {}},
        _0016: {RQ: {}},
        # "0B04": {I_: {}},
        _1030: {I_: {}},
        _1060: {I_: {}},
        _1090: {RQ: {}},
        _1100: {I_: {}},
        _1F09: {I_: {}},
        _1FC9: {I_: {}},
        _2309: {I_: {}, RQ: {}, W_: {}},
        _2349: {RQ: {}, W_: {}},
        _30C9: {I_: {}},
        _313F: {I_: {}},
        _3B00: {I_: {}},
        _3EF1: {RQ: {}},
    },
    "13": {  # e.g. BDR91A/BDR91T: Wireless Relay Box
        _0008: {RP: {}},  # doesn't RP/0009
        _0016: {RP: {}},
        # _10E0: {},  # 13: will not RP/10E0 # TODO: how to indicate that fact here
        _1100: {I_: {}, RP: {}},
        _1FC9: {RP: {}, W_: {}},
        _3B00: {I_: {}},
        _3EF0: {I_: {}},
        # RP: {},  # RQ --- 01:145038 13:237335 --:------ 3EF0 001 00
        _3EF1: {RP: {}},
    },
    "17": {
        _0002: {I_: {}},
        _1FC9: {I_: {}},
    },  # i.e. HB85 (ext. temperature/luminosity(lux)), HB95 (+ wind speed)
    "18": {
        _3220: {RQ: {}},
    },
    "20": {  # HVAC: ventilation unit, or switch/sensor?
        _10E0: {I_: {}, RP: {}},
        _12A0: {RP: {}},
        _22F1: {I_: {}},
        _22F3: {I_: {}},
        _3120: {RP: {}},
        _31D9: {I_: {}, RP: {}},
        _31DA: {I_: {}},
    },  # e.g. https://www.ithodaalderop.nl/nl-NL/professional/product/545-5036
    "23": {
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
    "29": {  # HVAC: Orcon MVS-15RP / MVS-15LF (vent mech. control)
        _10E0: {I_: {}},  # VMC-15RP01 / VMN-15LF01
        _31D9: {I_: {}},
    },  # e.g. https://www.orcon.nl/blueline-mvs-15rp-2/
    "30": {  # e.g. RFG100 (and others)
        # RFG:185469 - Honeywell RFG100
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
        _1FCA: {W_: {}},
        _22D9: {RQ: {}},
        _2309: {I_: {}},
        _2349: {RQ: {}, RP: {}, W_: {}},
        _2E04: {RQ: {}, I_: {}, W_: {}},
        _30C9: {RQ: {}},
        _313F: {RQ: {}, RP: {}, W_: {}},
        _3220: {RQ: {}},
        _3EF0: {RQ: {}},
        # VMS:082155 - HVAC: Nuaire Ventilation
        # _10E0: {I_: {}, RP: {},},
        _1F09: {I_: {}, RP: {}},
        _31D9: {I_: {}},
        _31DA: {I_: {}, RP: {}},
    },
    "31": {
        _0008: {I_: {}},
        _10E0: {I_: {}},
        _3EF1: {RQ: {}, RP: {}},
    },
    "32": {  # HVAC: switch/sensor?
        _1060: {I_: {}},
        _10E0: {I_: {}, RP: {}},
        _12A0: {I_: {}},
        _22F1: {I_: {}},
        _31DA: {RQ: {}},
        _31E0: {I_: {}},
    },
    "34": {  # e.g. TR87RF: Single (round) Zone Thermostat
        _0005: {I_: {}},
        _0008: {I_: {}},
        _000A: {I_: {}, RQ: {}},
        _000C: {I_: {}},
        _000E: {I_: {}},
        _042F: {I_: {}},
        _1060: {I_: {}},
        _10E0: {I_: {}},
        _12C0: {I_: {}},
        _1FC9: {I_: {}},
        _1FCA: {I_: {}},
        _2309: {I_: {}, RQ: {}, W_: {}},
        _2349: {RQ: {}},
        _30C9: {I_: {}},
        _3120: {I_: {}},
        _313F: {
            I_: {}
        },  # W --- 30:253184 34:010943 --:------ 313F 009 006000070E0E0507E5
        _3EF0: {RQ: {}},  # when bound direct to a 13:
        _3EF1: {RQ: {}},  # when bound direct to a 13:
    },
    "37": {  # HVAC: ventilation unit
        _10E0: {I_: {}, RP: {}},
        _1298: {I_: {}},
        _12C8: {I_: {}},
        _3120: {I_: {}},
        _31D9: {I_: {}},
        _31DA: {I_: {}},
    },
    "39": {  # HVAC: two-way switch; also an "06/22F1"?
        _22F1: {I_: {}},
        _22F3: {I_: {}},
    },  # https://www.ithodaalderop.nl/nl-NL/professional/product/536-0124
}
RAMSES_DEVICES["00"] = RAMSES_DEVICES["04"]  # HR80
RAMSES_DEVICES["21"] = RAMSES_DEVICES["34"]  # T87RF1003
RAMSES_DEVICES["22"] = RAMSES_DEVICES["12"]  # DTS92

#
#
RAMSES_ZONES = {
    "ALL": {
        _0004: {I_: {}, RP: {}},
        _000C: {RP: {}},
        _000A: {I_: {}, RP: {}},
        _2309: {I_: {}, RP: {}},
        _2349: {I_: {}, RP: {}},
        _30C9: {I_: {}, RP: {}},
    },
    "RAD": {
        _12B0: {I_: {}, RP: {}},
        "3150a": {},
    },
    "ELE": {
        _0008: {I_: {}},
        _0009: {I_: {}},
    },
    "VAL": {
        _0008: {I_: {}},
        _0009: {I_: {}},
        "3150a": {},
    },
    "UFH": {
        _3150: {I_: {}},
    },
    "MIX": {
        _0008: {I_: {}},
        "3150a": {},
    },
    "DHW": {
        _10A0: {RQ: {}, RP: {}},
        _1260: {I_: {}},
        _1F41: {I_: {}},
    },
}
RAMSES_ZONES_ALL = RAMSES_ZONES.pop("ALL")
RAMSES_ZONES_DHW = RAMSES_ZONES["DHW"]
[RAMSES_ZONES[k].update(RAMSES_ZONES_ALL) for k in RAMSES_ZONES if k != "DHW"]

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser."""

I_, RQ, RP, W_ = " I", "RQ", "RP", " W"

_0001 = "0001"
_0002 = "0002"
_0004 = "0004"
_0005 = "0005"
_0006 = "0006"
_0008 = "0008"
_0009 = "0009"
_000A = "000A"
_000C = "000C"
_000E = "000E"
_0016 = "0016"
_0100 = "0100"
_01D0 = "01D0"
_01E9 = "01E9"
_0404 = "0404"
_0418 = "0418"
_042F = "042F"
_1030 = "1030"
_1060 = "1060"
_1090 = "1090"
_10A0 = "10A0"
_10E0 = "10E0"
_1100 = "1100"
_1260 = "1260"
_1280 = "1280"
_1290 = "1290"
_1298 = "1298"
_12A0 = "12A0"
_12B0 = "12B0"
_12C0 = "12C0"
_12C8 = "12C8"
_1F09 = "1F09"
_1F41 = "1F41"
_1FC9 = "1FC9"
_1FD4 = "1FD4"
_2249 = "2249"
_22C9 = "22C9"
_22D0 = "22D0"
_22D9 = "22D9"
_22F1 = "22F1"
_22F3 = "22F3"
_2309 = "2309"
_2349 = "2349"
_2D49 = "2D49"
_2E04 = "2E04"
_30C9 = "30C9"
_3120 = "3120"
_313F = "313F"
_3150 = "3150"
_31D9 = "31D9"
_31DA = "31DA"
_31E0 = "31E0"
_3220 = "3220"
_3B00 = "3B00"
_3EF0 = "3EF0"
_3EF1 = "3EF1"
_PUZZ = "7FFF"

RQ_NULL = "rq_null"
RQ_MAY_HAVE_PAYLOAD = "rq_may_have_payload"

NAME = "name"
EXPIRY = "expiry"

# The master list - all known codes are here, even if there's no corresponding parser
# Anything with a zone-idx should start: ^0[0-9A-F], ^(0[0-9A-F], or ^((0[0-9A-F]
#
RAMSES_CODES = {  # rf_unknown
    _0001: {
        NAME: "rf_unknown",
        W_: r"^(0[0-9A-F]|F[ACF])0{4}05(05|01)$",
    },  # TODO: there appears to be a RQ/RP for UFC
    _0002: {  # WIP: outdoor_sensor
        NAME: "outdoor_sensor",
        I_: r"^0[0-4][0-9A-F]{4}(00|01|02|05)$",  # Domoticz sends ^02!!
        RQ: r"^00$",  # NOTE: sent by an RFG100
        RP: r"^00[0-9A-F]{4}(00|01)$",  # 007FFF00 is null resp?
    },
    _0004: {  # zone_name
        NAME: "zone_name",
        I_: r"^0[0-9A-F]00([0-9A-F]){40}$",  # NOTE: RP is same
        RQ: r"^0[0-9A-F]00$",
    },
    _0005: {  # system_zones
        NAME: "system_zones",
        I_: r"^00[01][0-9A-F]{5}$",  # NOTE: RP is same
        RQ: r"^00[01][0-9A-F]$",  # f"00{zone_type}"
        RQ_MAY_HAVE_PAYLOAD: True,
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
    _0009: {  # relay_failsafe
        NAME: "relay_failsafe",
        I_: r"^((0[0-9A-F]|F[9AC])0[0-1]FF)+$",
    },
    _000A: {  # zone_params
        NAME: "zone_params",
        I_: r"^(0[0-9A-F][0-9A-F]{10}){1,8}$",
        RQ: r"^0[0-9A-F]((00)?|([0-9A-F]{10})+)$",  # is: r"^0[0-9A-F]([0-9A-F]{10})+$"
        RP: r"^0[0-9A-F]([0-9A-F]{10})+$",  # TODO: null_rp: ..7FFF7FFF
        RQ_MAY_HAVE_PAYLOAD: True,
        # 17:54:13.126 063 RQ --- 34:064023 01:145038 --:------ 000A 001 03
        # 17:54:13.141 045 RP --- 01:145038 34:064023 --:------ 000A 006 031002260B86
        # 19:20:49.460 062 RQ --- 12:010740 01:145038 --:------ 000A 006 080001F40DAC
        # 19:20:49.476 045 RP --- 01:145038 12:010740 --:------ 000A 006 081001F40DAC
    },
    _000C: {  # zone_devices, TODO: needs I/RP
        NAME: "zone_devices",
        RQ: r"^0[0-9A-F][01][0-9A-F]$",  # TODO: f"{zone_idx}{device_type}"
        RQ_MAY_HAVE_PAYLOAD: True,
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
        RQ_MAY_HAVE_PAYLOAD: True,
    },  # NOTE: parser has been checked
    _01D0: {  # unknown, but definitely real
        NAME: "message_01d0",
    },
    _01E9: {  # unknown, but definitely real
        NAME: "message_01e9",
    },
    _0404: {  # zone_schedule
        NAME: "zone_schedule",
        RQ: r"^0[0-9A-F](20|23)000800[0-9A-F]{4}$",
        RQ_MAY_HAVE_PAYLOAD: True,
    },
    _0418: {  # system_fault
        NAME: "system_fault",
        RQ: r"^0000[0-3][0-9A-F]$",  # f"0000{log_idx}", no payload
        RP: r"^00[0-9A-F]{42}",  # TODO: 004000B0061C040000008F14B0DB7FFFFF7000367F95
    },
    _042F: {  # unknown, # non-evohome are len==9, seen only once?
        # 16:48:11.813119 060  I --- 32:168090 --:------ 32:168090 042F 009 000000100F00105050  # noqa
        NAME: "message_042f",
        I_: r"^00([0-9A-F]{2}){7}$",
    },
    _1030: {  # mixvalve_params
        NAME: "mixvalve_params",
        #  I --- --:------ --:------ 12:138834 1030 016 01C80137C9010FCA0196CB010FCC0101
        I_: r"^0[0-9A-F](C[89A-C]01[0-9A-F]{2}){5}$",
    },
    _1060: {  # device_battery
        NAME: "device_battery",
        I_: r"^0[0-9A-F](FF|[0-9A-F]{2})0[01]$",
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
        RQ_MAY_HAVE_PAYLOAD: True,
    },
    _10E0: {  # device_info
        NAME: "device_info",
        I_: r"^00([0-9A-F]){30,}$",  # NOTE: RP is same
        RQ: r"^00$",  # NOTE: will accept [0-9A-F]{2}
        # RP: r"^[0-9A-F]{2}([0-9A-F]){30,}$",  # NOTE: indx same as RQ
    },
    _1100: {  # tpi_params
        NAME: "tpi_params",
        RQ: r"^(00|FC)([0-9A-F]{12}01)?$",  # TODO: is there no RP?
        W_: r"^(00|FC)[0-9A-F]{12}01$",  # TODO: is there no I?
    },
    _1260: {  # dhw_temp
        NAME: "dhw_temp",
        # 18:51:49.158262 063 RQ --- 30:185469 01:037519 --:------ 1260 001 00
        # 18:51:49.174182 051 RP --- 01:037519 30:185469 --:------ 1260 003 000837
        # 16:48:51.536036 000 RQ --- 18:200202 10:067219 --:------ 1260 002 0000
        # 16:49:51.644184 068 RP --- 10:067219 18:200202 --:------ 1260 003 007FFF
        # 10:02:21.128654 049  I --- 07:045960 --:------ 07:045960 1260 003 0007A9
        I_: r"^00[0-9A-F]{4}$",  # NOTE: RP is same
        RQ: r"^00(00)?$",  # TODO: officially: r"^00$"
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
    },
    _12B0: {  # window_state  (HVAC % window open)
        NAME: "window_state",
        I_: r"^0[0-9A-F](0000|C800|FFFF)$",  # NOTE: RP is same
        RQ: r"^0[0-9A-F](00)?$",
        EXPIRY: 60 * 60,
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
        RQ: r"^00(00)?$",  # officially: r"^00$"
        RP: r"^00(00|01|FF)0[0-5]F{6}(([0-9A-F]){12})?$",
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
    _1FD4: {  # opentherm_sync
        NAME: "opentherm_sync",
        I_: r"^00([0-9A-F]{4})$",
    },
    _2249: {
        NAME: "setpoint_now",
        I_: r"^0[0-9A-F]{13}$",
    },  # setpoint_now
    _22C9: {  # ufh_setpoint
        NAME: "ufh_setpoint",
        I_: r"^(0[0-9A-F][0-9A-F]{10}){1,4}$",  # like a 000A array, but shorter!
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
        RQ: r"^0[0-9A-F]([0-9A-F]{4})?$",  # NOTE: 12 uses: r"^0[0-9A-F]$"
        I_: r"^(0[0-9A-F]{5})+$",
        RQ_MAY_HAVE_PAYLOAD: True,
        # RQ --- 12:010740 01:145038 --:------ 2309 003 03073A # No RPs
    },
    _2349: {  # zone_mode
        NAME: "zone_mode",
        # RQ: r"^0[0-9A-F](00)?$",  # is usually: r"^0[0-9A-F]$"
        RQ: r"^0[0-9A-F].*",  # r"^0[0-9A-F](00)?$",
        I_: r"^0[0-9A-F](([0-9A-F]){12}){1,2}$",
    },
    _2D49: {  # unknown
        NAME: "message_2d49",
    },  # seen with Hometronic systems
    _2E04: {  # system_mode
        NAME: "system_mode",
        I_: r"^0[0-7][0-9A-F]{12}0[01]$",  # evo: r"^0[0-7][0-9A-F]{12}0[01]$",
        RQ: r"^FF$",
        W_: r"^0[0-7][0-9A-F]{12}0[01]$",
    },
    _30C9: {  # temperature
        NAME: "temperature",
        I_: r"^(0[0-9A-F][0-9A-F]{4})+$",
        RQ: r"^0[0-9A-F](00)?$",  # TODO: officially: r"^0[0-9A-F]$"
        RP: r"^0[0-9A-F][0-9A-F]{4}$",  # Null: r"^0[0-9A-F]7FFF$"
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
        # RP: r"^00[0-9A-F]{16}$",
        W_: r"^00[0-9A-F]{16}$",
    },
    _3150: {  # heat_demand
        NAME: "heat_demand",
        I_: r"^(FC[0-9A-F]{2}|(0[0-9A-F])[0-9A-F]{2})+$",
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
        RQ_MAY_HAVE_PAYLOAD: True,
    },
    _3B00: {  # actuator_sync
        NAME: "actuator_sync",
        I_: r"^(00|FC)(00|C8)$",
    },  # No RQ
    _3EF0: {  # actuator_state
        NAME: "actuator_state",
        # I_: r"^00[0-9A-C][0-9A-F]([0-9A-F]{6})?FF$",
        I_: r"^00",
        RQ: r"^00$",
        RP: r"^00",
    },
    _3EF1: {  # actuator_cycle
        NAME: "actuator_cycle",
        RQ: r"^(0[0-9A-F](00)?|00[0-9A-F]{22})$",  # NOTE: both seen in the wild
        # RP: r"^(0[0-9A-F](00)?|00[0-9A-F]{22})$", # TODO
        RQ_MAY_HAVE_PAYLOAD: True,
    },
    _PUZZ: {
        NAME: "puzzle_packet",
        I_: r"^7F[0-9A-F]{12}7F[0-9A-F]{4}7F[0-9A-F]{4}(7F)+",
    },
}
for code in RAMSES_CODES.values():
    if RQ in code and RP not in code and I_ in code:
        code[RP] = code[I_]

CODE_IDX_COMPLEX = [_0005, _000C, _0404, _0418, _3220]  # also: 0008?
CODE_IDX_SIMPLE = [
    k
    for k, v in RAMSES_CODES.items()
    if k not in CODE_IDX_COMPLEX
    and (
        (RQ in v and v[RQ].startswith("^0[0-9A-F]"))
        or (I_ in v and v[I_].startswith(("^0[0-9A-F]", "^(0[0-9A-F]", "^((0[0-9A-F]")))
    )
]
CODE_IDX_SIMPLE.extend([_10A0, _1100, _3150])
CODE_IDX_NONE = [
    k
    for k, v in RAMSES_CODES.items()
    if k not in CODE_IDX_COMPLEX + CODE_IDX_SIMPLE
    and ((RQ in v and v[RQ][:3] == "^00") or (I_ in v and v[I_][:3] == "^00"))
]
CODE_IDX_NONE.extend([_2E04, _3B00])  # treat 3B00 as no domain
_CODE_IDX_UNKNOWN = [
    k
    for k, v in RAMSES_CODES.items()
    if k not in CODE_IDX_COMPLEX + CODE_IDX_NONE + CODE_IDX_SIMPLE
]  # TODO: remove
CODE_IDX_COMPLEX.sort() or print(f"complex = {CODE_IDX_COMPLEX}")  # TODO: remove
CODE_IDX_NONE.sort() or print(f"none    = {CODE_IDX_NONE}")  # TODO: remove
CODE_IDX_SIMPLE.sort() or print(f"simple  = {CODE_IDX_SIMPLE}")  # TODO: remove
_CODE_IDX_UNKNOWN.sort() or print(f"unknown = {_CODE_IDX_UNKNOWN}")  # TODO: remove

# TODO: deprecate these
CODES_WITH_COMPLEX_IDX = (_0001, _0008, _000C, _0418, _1100, _1F41, _3B00)
CODES_WITHOUT_IDX = (_1F09, _2E04)  # other than r"^00"

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
        _0404: {RP: {}},
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
        _2249: {I_: {}},
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
        _0001: {W_: {}},
        _0004: {RQ: {}},
        _0016: {RQ: {}},
        _0100: {RQ: {}},
        _01D0: {W_: {}},
        _01E9: {W_: {}},
        _1060: {I_: {}},
        _10E0: {I_: {}},
        _1F09: {RQ: {}},
        _12B0: {I_: {}},  # sends every 1h
        _1FC9: {I_: {}, W_: {}},
        _2309: {I_: {}},
        _30C9: {I_: {}},
        _313F: {RQ: {}},
        _3150: {I_: {}},
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
    "10": {  # e.g. R8810: OpenTherm Bridge
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
        "0B04": {I_: {}},
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
        _0008: {RP: {}},
        "0009a": {RP: {}},  # TODO: needs confirming
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
        # GWY:185469 - Honeywell RFG100
        _0002: {RQ: {}},
        _0004: {I_: {}, RQ: {}},
        _0005: {RQ: {}},
        _0006: {RQ: {}},
        _000A: {RQ: {}},
        _000C: {RQ: {}},
        _000E: {W_: {}},
        _0016: {RP: {}},
        _0404: {RQ: {}},
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


def pkt_has_array(pkt: str):  # TODO:
    """Return the True is the packet payload is an array.

    Currently returns True if the payload *could be* an array.
    """

    verb = pkt[4:6]
    code = pkt[41:45]
    payload = pkt[50:]

    if code in (_0009, _2309, _30C9) and verb == I_:
        if len(payload) > 6:  # TODO: remove
            assert (pkt[11:13] == pkt[31:33] == "01") or (
                pkt[11:13] == "--" and pkt[31:33] in ("12", "22")
            )
        return pkt[11:13] == pkt[31:33] == "01"  # TODO: use CTL/PRG?

    if code in (_000A,) and verb == I_:
        if len(payload) > 12:  # TODO: remove
            assert pkt[11:13] == pkt[31:33] == "01" or (
                pkt[11:13] == "--" and pkt[31:33] in ("12", "22")
            )
        return pkt[11:13] == pkt[31:33] == "01" or (
            pkt[11:13] == "--" and pkt[31:33] in ("12", "22")
        )  # TODO: use CTL/PRG?

    if code in (_22C9,) and verb == I_:
        if len(payload) > 12:  # TODO: remove
            assert pkt[11:13] == pkt[31:33] == "02"
        return pkt[11:13] == pkt[31:33] == "02"  # TODO: use UFC

    # .I --- 34:092243 --:------ 34:092243 1FC9 030 0030C98968530023098968530010608968530010E0896853001FC9896853
    if code in (_1FC9,):
        return True  # I_, RP and I_ are all arrays

    # .I --- 02:001107 --:------ 02:001107 3150 010 007A017A027A036A046A
    if code in (_3150,) and verb == I_:
        if len(payload) > 4:
            assert pkt[11:13] == pkt[31:33] == "02"
        return pkt[11:13] == pkt[31:33] == "02"  # TODO: use UFC?

    return None


def pkt_has_idx(pkt: str):  # TODO:
    """Return the index/domain of a packet, or False if there isn't one.

    Payloads that are arrays return False. There will be false +ves, but no false -ves.
    """

    verb = pkt[4:6]
    code = pkt[41:45]
    payload = pkt[50:]

    # TODO: check: 0008, 0009, 0100, 10A0, 2249, 3150, 31Dx, 3EFx,

    # 1st: handle the arrays (first, because some are common)...

    # .I --- 01:063844 --:------ 01:063844 0008 002 FA00
    # .I --- 01:063844 --:------ 01:063844 0008 002 FC22
    # .I --- 01:063844 --:------ 01:063844 0008 002 F9C8
    # .I --- 02:000921 --:------ 02:000921 0008 002 FA00
    # .I --- 02:001075 --:------ 02:001075 0008 002 FCC8

    # .I --- 01:145038 --:------ 01:145038 0008 002 0B14
    # .I --- 01:145038 --:------ 01:145038 0008 002 042A
    # .I --- 01:145038 --:------ 01:145038 0008 002 0B14
    # .I --- 01:145038 --:------ 01:145038 0008 002 0914
    # .I --- 01:145038 --:------ 01:145038 0008 002 0332
    if code in (_0008,):
        if payload[:2] != "00":  # or verb != "RQ":  # TODO: remove
            assert pkt[11:13] == pkt[31:33] and pkt[11:13] in ("01", "02")
        return pkt[11:13] == pkt[31:33] and (
            pkt[11:13] in ("01", "02")
        )  # TODO: use CTL/UFC

    if code in (_0009, _2309, _30C9):
        return False if pkt_has_array(pkt) else payload[:2]

    if code in (_000A, _22C9):
        return False if pkt_has_array(pkt) else payload[:2]

    # .W --- 01:145038 34:092243 --:------ 1FC9 006 07230906368E
    # .I --- 01:145038 --:------ 01:145038 1FC9 018 07000806368EFC3B0006368E071FC906368E
    # .I --- 01:145038 --:------ 01:145038 1FC9 018 FA000806368EFC3B0006368EFA1FC906368E
    if code in (_1FC9,):
        return False  # 1FC9: I_, RP, I_ are arrays

    if code in (_3150,):
        return False if pkt_has_array(pkt) else payload[:2]

    # 2nd: handle the complex cases...
    if code in (_0005, _000C):  # zone_idx, zone_type/device_class
        return payload[:4]

    if code == _0404:  # zone_schedule: zone_idx, frag_idx
        return payload[:2] + payload[10:12]

    if code == _0418:  # fault_log: log_idx
        if payload == "000000B0000000000000000000007FFFFF7000000000":
            return False
        else:
            return payload[4:6]

    if code == _3220:  #
        return payload[4:6]  # ot_msg_id (is ot_msg_type needed to?)

    # These three lists should be mutex
    if code in CODE_IDX_COMPLEX:
        raise NotImplementedError

    # 4th: generic cases - simple idx/domain
    if code in CODE_IDX_NONE:
        return False

    if code in CODE_IDX_SIMPLE:  # TODO: lots of potential for false positives
        return payload[:2] if verb == "RQ" else payload[:2]

    # if code in CODE_IDX_UNKNOWN:
    #     return NotImplementedError

    # if payload[:2] != "00":
    #     raise ValueError()

    return "*****"  # TODO: None  # CODE_IDX_UNKNOWN

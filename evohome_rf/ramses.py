#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome RF - a RAMSES-II protocol decoder & analyser."""

I_ = " I"
W_ = " W"
RQ = "RQ"
RP = "RP"

NAME = "name"
EXPIRY = "expiry"

# This is the master list - all codes are here, even if there's no corresponding parser
RAMSES_CODES = {
    "0001": {
        NAME: "rf_unknown",
    },
    "0002": {
        NAME: "sensor_weather",
    },
    "0004": {
        NAME: "zone_name",
    },
    "0005": {
        NAME: "system_zones",
    },
    "0006": {
        NAME: "schedule_sync",
    },
    "0008": {
        NAME: "relay_demand",
    },
    "0009": {
        NAME: "relay_failsafe",
    },
    "000A": {
        NAME: "zone_params",
    },
    "000C": {
        NAME: "zone_devices",
    },
    "000E": {
        NAME: "message_000e",
    },
    "0016": {
        NAME: "rf_check",
    },
    "0100": {
        NAME: "language",
    },
    "01D0": {
        NAME: "message_01d0",
    },
    "01E9": {
        NAME: "message_01e9",
    },
    "0404": {
        NAME: "zone_schedule",
    },
    "0418": {
        NAME: "system_fault",
    },
    "042F": {
        NAME: "message_042f",
    },
    "0B04": {
        NAME: "message_0b04",
    },
    "1030": {
        NAME: "mixvalve_params",
    },
    "1060": {
        NAME: "device_battery",
    },
    "1090": {
        NAME: "message_1090",
    },
    "10A0": {
        NAME: "dhw_params",
    },
    "10E0": {
        NAME: "device_info",
    },
    "1100": {
        NAME: "tpi_params",
    },
    "1260": {
        NAME: "dhw_temp",
    },
    "1280": {
        NAME: "outdoor_humidity",
    },
    "1290": {
        NAME: "outdoor_temp",
    },
    "12A0": {
        NAME: "indoor_humidity",
    },
    "12B0": {
        NAME: "window_state",
        EXPIRY: 60 * 60,
    },
    "12C0": {
        NAME: "message_12c0",
    },
    "1F09": {
        NAME: "system_sync",
    },
    "1F41": {
        NAME: "dhw_mode",
    },
    "1FC9": {
        NAME: "rf_bind",
    },
    "1FD4": {
        NAME: "opentherm_sync",
    },
    "2249": {
        NAME: "setpoint_now",
    },
    "22C9": {
        NAME: "ufh_setpoint",
    },
    "22D0": {
        NAME: "message_22d0",
    },
    "22D9": {
        NAME: "boiler_setpoint",
    },
    "22F1": {
        NAME: "switch_vent",
    },
    "22F3": {
        NAME: "switch_other",
    },
    "2309": {
        NAME: "setpoint",
    },
    "2349": {
        NAME: "zone_mode",
    },
    "2D49": {
        NAME: "message_2d49",
    },
    "2E04": {
        NAME: "system_mode",
    },
    "30C9": {
        NAME: "temperature",
    },
    "3120": {
        NAME: "message_3120",
    },
    "313F": {
        NAME: "datetime",
    },
    "3150": {
        NAME: "heat_demand",
    },
    "31D9": {
        NAME: "message_31d9",
    },
    "31DA": {
        NAME: "message_31da",
    },
    "31E0": {
        NAME: "message_31e0",
    },
    "3220": {
        NAME: "opentherm_msg",
    },
    "3B00": {
        NAME: "actuator_sync",
    },
    "3EF0": {
        NAME: "actuator_state",
    },
    "3EF1": {
        NAME: "actuator_cycle",
    },
}  # also: "7FFF": {NAME: "puzzle_packet",},

RAMSES_DEVICES = {
    "01": {
        "0001": {
            W_: {},
        },
        "0002": {
            RP: {},
        },
        "0004": {
            I_: {},
            RP: {},
        },
        "0005": {
            I_: {},
            RP: {},
        },
        "0006": {
            RP: {},
        },
        "0008": {
            I_: {},
        },
        "0009": {
            I_: {},
        },
        "000A": {
            I_: {},
            RP: {},
        },
        "000C": {
            RP: {},
        },
        "0016": {
            RP: {},
        },
        "0100": {
            RP: {},
        },
        "0404": {
            RP: {},
        },
        "0418": {
            I_: {},
            RP: {},
        },
        "1030": {
            I_: {},
        },
        "10A0": {
            RP: {},
        },
        "10E0": {
            RP: {},
        },
        "1100": {
            I_: {},
            RP: {},
            W_: {},
        },
        "1260": {
            RP: {},
        },
        "1290": {
            RP: {},
        },
        "12B0": {
            I_: {},
            RP: {},
        },
        "1F09": {
            I_: {},
            RP: {},
            W_: {},
        },
        "1FC9": {
            I_: {},
        },
        "1F41": {
            RP: {},
        },
        "22D9": {
            RQ: {},
        },
        "2309": {
            I_: {},
            RP: {},
        },
        "2349": {
            I_: {},
            RP: {},
        },
        "2E04": {
            I_: {},
            RP: {},
        },
        "30C9": {
            I_: {},
            RP: {},
        },
        "313F": {
            I_: {},
            RP: {},
            W_: {},
        },
        "3150": {
            I_: {},
        },
        "3220": {
            RQ: {},
        },
        "3B00": {
            I_: {},
        },
        "3EF0": {
            RQ: {},
        },
    },
    "02": {
        "0001a": {},
        "0005a": {},
        "0008": {
            I_: {},
        },
        "000Aa": {},
        "000Ca": {},
        "10E0": {
            I_: {},
            RP: {},
        },
        "22C9": {
            I_: {},
        },
        "22D0": {
            I_: {},
        },
        "2309a": {},
        "3150": {
            I_: {},
        },
    },
    "03": {
        "0001": {
            W_: {},
        },
        "0008": {
            I_: {},
        },
        "0009": {
            I_: {},
        },
        "1060": {
            I_: {},
        },
        "1100": {
            I_: {},
        },
        "1F09": {
            I_: {},
        },
        "1FC9": {
            I_: {},
        },
        "2309": {
            I_: {},
        },
        "30C9": {
            I_: {},
        },
    },
    "04": {
        "0001": {
            W_: {},
        },
        "0004": {
            RQ: {},
        },
        "0100": {
            RQ: {},
        },
        "01D0": {
            W_: {},
        },
        "01E9": {
            W_: {},
        },
        "1060": {
            I_: {},
        },
        "10E0": {
            I_: {},
        },
        "1F09": {
            RQ: {},
        },
        "12B0": {
            I_: {},
        },  # sends every 1h
        "2309": {
            I_: {},
        },
        "30C9": {
            I_: {},
        },
        "313F": {
            RQ: {},
        },
        "3150": {
            I_: {},
        },
    },
    "07": {
        "0016": {
            RQ: {},
        },
        "1060": {
            I_: {},
        },
        "10A0": {
            RQ: {},
        },
        "1260": {
            I_: {},
        },
        "1FC9": {
            I_: {},
        },
    },
    "08": {
        "0008": {
            RQ: {},
        },
        "10E0": {
            I_: {},
        },
        "1100": {
            RQ: {},
        },
        "3EF0": {
            I_: {},
        },
        "3EF1": {
            RP: {},
        },
    },
    "10": {
        "10A0": {
            RP: {},
        },
        "10E0": {
            I_: {},
            RP: {},
        },
        "1260": {
            RP: {},
        },
        "1290": {
            RP: {},
        },
        "1FD4": {
            I_: {},
        },
        "22D9": {
            RP: {},
        },
        "2349": {
            I_: {},
        },
        "3150": {
            I_: {},
        },
        "3220": {
            RP: {},
        },
        "3EF0": {
            I_: {},
            RP: {},
        },
        "3EF1": {
            RP: {},
        },
    },
    "12": {  # TODO: also 22:
        "0008": {
            I_: {},
        },
        "0009": {
            I_: {},
        },
        "1100": {
            I_: {},
        },
        "000A": {
            RQ: {},
            W_: {},
        },
        "0B04": {
            I_: {},
        },
        "1030": {
            I_: {},
        },
        "1060": {
            I_: {},
        },
        "1090": {
            RQ: {},
        },
        "2309": {
            I_: {},
            RQ: {},
            W_: {},
        },
        "2349": {
            W_: {},
        },
        "30C9": {
            I_: {},
        },
        "313F": {
            I_: {},
        },
        "3B00": {
            I_: {},
        },
        "3EF1": {
            RQ: {},
        },
    },
    "13": {
        "0008": {
            RP: {},
        },
        "0009a": {
            RP: {},
        },  # needs confirming
        "0016": {
            RP: {},
        },
        "1100": {
            I_: {},
            RP: {},
        },
        "1FC9": {
            RP: {},
            W_: {},
        },
        "3B00": {
            I_: {},
        },
        "3EF0": {
            I_: {},
        },
        "3EF1": {
            RP: {},
        },
    },
    "20": {
        "10E0": {
            I_: {},
            RP: {},
        },
        "31D9": {
            I_: {},
        },
    },
    "23": {
        "1090": {
            RP: {},
        },
    },
    "30": {
        # GWY:185469 - Honeywell RFG100
        "0002": {
            RQ: {},
        },
        "0004": {
            RQ: {},
        },
        "0005": {
            RQ: {},
        },
        "0006": {
            RQ: {},
        },
        "000A": {
            RQ: {},
        },
        "000C": {
            RQ: {},
        },
        "0404": {
            RQ: {},
        },
        "0418": {
            RQ: {},
        },
        "10A0": {
            RQ: {},
        },
        "10E0": {
            I_: {},
            RQ: {},
            RP: {},
        },
        "1260": {
            RQ: {},
        },
        "1290": {
            I_: {},
        },
        "1F41": {
            RQ: {},
        },
        # "2349": {RQ: {},},
        "2E04": {
            RQ: {},
        },
        "313F": {
            RQ: {},
            W_: {},
        },
        "3EF0": {
            RQ: {},
        },
        # GWY:185469 - ???
        "2349": {
            RQ: {},
            RP: {},
        },
        # VMS:082155 - Nuaire Ventilation
        # "10E0": {I_: {}, RP: {},},
        "1F09": {
            I_: {},
        },
        "31D9": {
            I_: {},
        },
        "31DA": {
            I_: {},
            RP: {},
        },
    },
    "31": {
        "0008": {
            I_: {},
        },
        "10E0": {
            I_: {},
        },
        "3EF1": {
            RQ: {},
        },
    },
    "32": {
        "1060": {
            I_: {},
        },
        "10E0": {
            I_: {},
        },
        "12A0": {
            I_: {},
        },
        "22F1": {
            I_: {},
        },
        "31DA": {
            RQ: {},
        },
        "31E0": {
            I_: {},
        },
    },
    "34": {
        "0005": {
            I_: {},
        },
        "0008": {
            I_: {},
        },
        "000A": {
            RQ: {},
        },
        "000C": {
            I_: {},
        },
        "000E": {
            I_: {},
        },
        "042F": {
            I_: {},
        },
        "1060": {
            I_: {},
        },
        "10E0": {
            I_: {},
        },
        "12C0": {
            I_: {},
        },
        "2309": {
            I_: {},
            RQ: {},
            W_: {},
        },
        "2349": {
            RQ: {},
        },
        "30C9": {
            I_: {},
        },
        "3120": {
            I_: {},
        },
    },
    "37": {},
}

RAMSES_DEVICES["00"] = RAMSES_DEVICES["04"]
RAMSES_DEVICES["22"] = RAMSES_DEVICES["12"]

RAMSES_ZONES = {
    "RAD": {},
    "ELE": {},
    "VAL": {},
    "UFH": {},
    "MIX": {},
    "DHW": {},
}

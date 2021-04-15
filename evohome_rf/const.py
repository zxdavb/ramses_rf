#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome RF - a RAMSES-II protocol decoder & analyser."""

import functools
import re
from collections import namedtuple
from types import SimpleNamespace

DEV_MODE = __dev_mode__ = True

# grep ' F[89ABxDE]' | grep -vE ' (0008|1F09/F8|1FC9|2D49/FD) '
# grep ' F[89ABCDE]' | grep -vE ' (0008|1F09/xx|1FC9|0001|0009|1100|3150|3B00) '

Address = namedtuple("DeviceAddress", "id, type")


@functools.lru_cache(maxsize=128)
def id_to_address(device_id) -> Address:
    return Address(id=device_id, type=device_id[:2])


def slug(string: str) -> str:
    return re.sub(r"[\W_]+", "_", string.lower())


DEFAULT_MAX_ZONES = 16 if DEV_MODE else 12
# Evohome: 12 (0-11), older/initial version was 8
# Hometronics: 16 (0-15), or more?
# Sundial RF2: 2 (0-1), usually only one, but ST9520C can do two zones

HGI_DEVICE_ID = "18:000730"  # default type and address of HGI, 18:013393
NON_DEVICE_ID = "--:------"
NUL_DEVICE_ID = "63:262142"  # 7FFFFF - send here if not bound?

HGI_DEV_ADDR = id_to_address(HGI_DEVICE_ID)
NON_DEV_ADDR = id_to_address(NON_DEVICE_ID)
NUL_DEV_ADDR = id_to_address(NUL_DEVICE_ID)

# ATTR_DEVICE_ID = "device_id"
# ATTR_SENSOR_ID = "sensor_id"
# ATTR_CTL_DEVICE_ID = "controller_id"
# ATTR_DHW_SENSOR_ID = "sensor_id"
# ATTR_HTG_DEVICE_ID = "heater_id"
# ATTR_UFC_DEVICE_ID = "ufh_controller_id"
# ATTR_RELAY_DEVICE_ID = "relay_id"

ALL_DEVICE_ID = r"^[0-9]{2}:[0-9]{6}$"
ZON_SENSOR_ID = r"^('01'|'03'|'04'|'12'|'22'|'34'):[0-9]{6}$"
CTL_DEVICE_ID = r"^(01|23):[0-9]{6}$"
DHW_SENSOR_ID = r"^07:[0-9]{6}$"
GWY_DEVICE_ID = r"^18:[0-9]{6}$"
HTG_DEVICE_ID = r"^(10|13):[0-9]{6}$"
UFC_DEVICE_ID = r"^02:[0-9]{6}$"
RLY_DEVICE_ID = r"^13:[0-9]{6}$"


# Packet codes (this dict is being deprecated) - check against ramses.py
CODE_SCHEMA = {
    "0001": {"uses_zone_idx": True},  # unknown
    "0004": {"rq_len": 2, "uses_zone_idx": True},  # "null_resp": "7F" * 20,
    "0005": {"rq_length": 2},
    "0006": {"rq_len": 1},
    "0008": {"uses_zone_idx": True},
    "0009": {"uses_zone_idx": True},
    "000A": {"rq_len": 3, "uses_zone_idx": True},  # "null_resp": "007FFF7FFF",
    "000E": {"uses_zone_idx": False},
    "0016": {"rq_length": 2},
    "0100": {"rq_length": 5},
    "01D0": {"uses_zone_idx": True},  # might yet be False
    "01E9": {"uses_zone_idx": True},  # might yet be False
    "0404": {"uses_zone_idx": True},
    "0418": {"null_rp": "000000B0000000000000000000007FFFFF7000000000"},
    "042F": {"uses_zone_idx": False},
    "1030": {"uses_zone_idx": True},
    "1060": {"uses_zone_idx": True},
    "10A0": {"rq_length": len("0000") / 2},
    "12B0": {"uses_zone_idx": True},
    "1F09": {"rq_len": 1},
    "1FC9": {"uses_zone_idx": True, "rq_len": 1},  # was bind_device
    "2249": {"uses_zone_idx": True},
    "22D0": {"uses_zone_idx": None},
    "2309": {"uses_zone_idx": True, "rq_len": 1},
    "2349": {"uses_zone_idx": True},  # "null_resp": "7FFF00FFFFFF"
    "2E04": {"uses_zone_idx": False},
    "30C9": {"uses_zone_idx": True},
    "3120": {"uses_zone_idx": False},
    "3150": {"uses_zone_idx": True},
    "3EF0": {"uses_zone_idx": False},
    "3EF1": {"uses_zone_idx": True, "rq_length": 2},
}

MAY_USE_DOMAIN_ID = ["0001", "0008", "0009", "1100", "1FC9", "3150", "3B00"]
MAY_USE_ZONE_IDX = [k for k, v in CODE_SCHEMA.items() if v.get("uses_zone_idx")]

DEVICE_TABLE = {
    # Honeywell evohome
    "01": {
        "type": "CTL",
        "name": "Controller",
        "has_battery": False,
        "has_zone_sensor": False,  # a special case
        "is_actuator": False,
        "is_controller": True,
        "is_sensor": True,
        "archetype": "ATC928",
        "poll_codes": ["000C", "10E0", "1100", "313F"],
        "discover_schema": [],
    },  # rechargeable
    "02": {
        "type": "UFC",
        "name": "UFH Controller",
        "has_battery": False,
        "is_actuator": None,
        "is_controller": None,
        "is_sensor": None,
        "archetype": "HCE80(R)",
        "discover_schema": [],
    },
    "03": {
        "type": "STa",
        "name": "Room Sensor/Stat",
        "has_battery": True,
        "has_zone_sensor": True,
        "is_actuator": False,
        "is_sensor": True,
        "archetype": "HCW82",  # also: HCF82
        "discover_schema": [],
    },
    "04": {
        "type": "TRV",
        "name": "Radiator Valve",
        "has_battery": True,
        "has_zone_sensor": True,
        "is_actuator": True,
        "is_sensor": True,
        "archetype": "HR92",  # also: HR80
        "discover_schema": [],
    },  #
    "07": {
        "type": "DHW",
        "name": "DHW Sensor",
        "has_battery": True,
        "is_actuator": False,
        "is_sensor": True,
        "archetype": "CS92A",
        "discover_schema": [],
    },
    "10": {
        "type": "OTB",
        "name": "OpenTherm Bridge",
        "has_battery": False,
        "is_actuator": None,
        "is_sensor": False,
        "archetype": "R8810",
        "poll_codes": [
            "0008",
            "10A0",
            "1100",
            "1260",
            "1290",
            "22D9",
            "3150",
            "3220",
            "3EF0",
            "3EF1",
        ],
        "discover_schema": [],
    },  #
    "13": {
        "type": "BDR",
        "name": "Wireless Relay",
        "has_battery": False,
        "is_actuator": None,
        "is_sensor": False,
        "archetype": "BDR91",  # also: HC60NG?
        "poll_codes": ["0008", "1100", "3EF1"],
        "discover_schema": [],  # excl.: 10E0
    },
    "22": {
        "type": "THM",
        "name": "Room Thermostat",
        "has_battery": True,
        "has_zone_sensor": True,
        "is_actuator": False,
        "is_sensor": True,
        "archetype": "DTS92(E)",
        "discover_schema": [],
    },
    "30": {
        "type": "GWY",
        "name": "Internet Gateway",
        "has_battery": False,
        "is_actuator": False,
        "is_sensor": False,
        "archetype": "-unclear-",  # RFG100, VMS?
        "discover_schema": [],
    },
    "34": {
        "type": "STA",
        "name": "Round Thermostat",
        "has_battery": True,
        "has_zone_sensor": True,
        "is_actuator": False,
        "is_sensor": True,
        "archetype": "T87RF",
        "discover_schema": [],
    },
    # Honeywell evohome TBD
    "x1": {
        "type": "HM8",
        "name": "Mixing Valve",
        "has_battery": False,
        "is_actuator": None,
        "is_sensor": None,
        "archetype": "HM80",
    },  # TODO: ???
    # Honeywell, non-evohome
    "17": {
        "type": " 17",
        "name": "Outdoor Sensor?",
        "has_battery": None,
        "is_actuator": False,
        "is_sensor": False,
    },  # TODO: HB85?
    "18": {
        "type": "HGI",
        "name": "Honeywell Gateway",
        "has_battery": False,
        "is_actuator": False,
        "is_sensor": False,
        "archetype": "HGI80",
    },
    "23": {
        "type": "PRG",
        "name": "Programmer (wired)",
        "has_battery": False,
        "is_actuator": False,
        "is_sensor": True,
        "archetype": "ST9420C",
    },
    # Honeywell Jasper, HVAC?
    "08": {"type": "JIM", "name": "HVAC?"},  # Jasper equipment interface module
    "31": {"type": "JST", "name": "HVAC?"},  # Jasper Stat TXXX
    # non-Honeywell, HVAC? (also, 30: is a Nuaire PIV)
    "20": {"type": "VCE", "name": "HVAC?"},  # VCE-RF unit
    "32": {"type": "VMS", "name": "HVAC?"},  # sensor/switch
    "37": {"type": " 37", "name": "HVAC?"},  # VCE
    "39": {"type": "VMS", "name": "HVAC?"},  # sensor/switch
    "49": {"type": " 49", "name": "HVAC?"},  # VCE switch
    # specials
    "63": {"type": "NUL", "name": "Null Device"},
    "--": {"type": "---", "name": "No Device"},
}
# VMS includes Nuaire VMS-23HB33, VMS-23LMH23
# What about Honeywell MT4 actuator?

DEVICE_TABLE["12"] = dict(DEVICE_TABLE["22"])
DEVICE_TABLE["12"]["type"] = "THm"

DEVICE_TABLE["00"] = dict(DEVICE_TABLE["04"])
DEVICE_TABLE["00"]["type"] = "TRv"

# Example of:
#  - Sundial RF2 Pack 3: 23:(ST9420C), 07:(CS92), and 22:(DTS92(E))

# HCW80 has option of being wired (normally wireless)
# ST9420C has battery back-up (as does evohome)

DEVICE_TYPES = {k: v["type"] for k, v in DEVICE_TABLE.items()}
DEVICE_LOOKUP = {v: k for k, v in DEVICE_TYPES.items()}
# DEVICE_CLASSES = {v["type"]: v["name"] for _, v in DEVICE_TABLE.items()}

DEVICE_HAS_BATTERY = tuple(
    k for k, v in DEVICE_TABLE.items() if v.get("has_battery") is True
)  # more correctly: is battery-powered (and so won't respond to RQs)
DEVICE_HAS_ZONE_SENSOR = tuple(
    k for k, v in DEVICE_TABLE.items() if v.get("has_zone_sensor") is True
)  # other sensors (e.g. 07:) can't be used as a zone sensor
# DEVICE_IS_ACTUATOR = tuple(
#     k for k, v in DEVICE_TABLE.items() if v.get("is_actuator") is True
# )  # c.f. 000C packet

# Domains
DOMAIN_TYPE_MAP = {
    "F8": None,
    "F9": "heating_valve",  # DHW Heating Valve
    "FA": "hotwater_valve",  # DHW HW Valve (or UFH loop if src.type == "02"?)
    "FB": None,
    "FC": "heating_control",  # "heat_relay": BDR (Boiler, District heating), or OTB
    "FD": "unknown",  # seen with hometronics
    # "FF": "system",  # TODO: remove this, is not a domain
}  # "21": "Ventilation",
DOMAIN_TYPE_LOOKUP = {v: k for k, v in DOMAIN_TYPE_MAP.items() if k != "FF"}

SYS_MODE_AUTO = "00"
SYS_MODE_HEAT_OFF = "01"
SYS_MODE_ECO_BOOST = "02"  # Eco, or Boost
SYS_MODE_AWAY = "03"
SYS_MODE_DAY_OFF = "04"
SYS_MODE_DAY_OFF_ECO = "05"  # set to Eco when DayOff ends
SYS_MODE_AUTO_WITH_RESET = "06"
SYS_MODE_CUSTOM = "07"

SystemMode = SimpleNamespace(
    AUTO="auto",
    AWAY="away",
    CUSTOM="custom",
    DAY_OFF="day_off",
    DAY_OFF_ECO="day_off_eco",
    ECO_BOOST="eco_boost",
    HEAT_OFF="heat_off",
    RESET="auto_with_reset",
)
SYSTEM_MODE_MAP = {
    SYS_MODE_AUTO: SystemMode.AUTO,
    SYS_MODE_HEAT_OFF: SystemMode.HEAT_OFF,
    SYS_MODE_ECO_BOOST: SystemMode.ECO_BOOST,
    SYS_MODE_AWAY: SystemMode.AWAY,
    SYS_MODE_DAY_OFF: SystemMode.DAY_OFF,
    SYS_MODE_DAY_OFF_ECO: SystemMode.DAY_OFF_ECO,
    SYS_MODE_AUTO_WITH_RESET: SystemMode.RESET,
    SYS_MODE_CUSTOM: SystemMode.CUSTOM,
}
SYSTEM_MODE_LOOKUP = {v: k for k, v in SYSTEM_MODE_MAP.items()}

ZONE_MODE_FOLLOW_SCHEDULE = "00"
ZONE_MODE_ADVANCED_OVERRIDE = "01"  # until the next scheduled setpoint
ZONE_MODE_PERMANENT_OVERRIDE = "02"  # indefinitely
ZONE_MODE_COUNTDOWN_OVERRIDE = "03"  # for a number of minutes (duration, max 1,215)
ZONE_MODE_TEMPORARY_OVERRIDE = "04"  # until a given date/time (until)

ZoneMode = SimpleNamespace(
    SCHEDULE="follow_schedule",
    ADVANCED="advanced_override",  # until the next setpoint
    PERMANENT="permanent_override",  # indefinitely
    COUNTDOWN="countdown_override",  # for a number of minutes (max 1,215)
    TEMPORARY="temporary_override",  # until a given date/time
)
ZONE_MODE_MAP = {
    ZONE_MODE_FOLLOW_SCHEDULE: ZoneMode.SCHEDULE,
    ZONE_MODE_ADVANCED_OVERRIDE: ZoneMode.ADVANCED,
    ZONE_MODE_PERMANENT_OVERRIDE: ZoneMode.PERMANENT,
    ZONE_MODE_COUNTDOWN_OVERRIDE: ZoneMode.COUNTDOWN,
    ZONE_MODE_TEMPORARY_OVERRIDE: ZoneMode.TEMPORARY,
}
ZONE_MODE_LOOKUP = {v: k for k, v in ZONE_MODE_MAP.items()}

DHW_STATE_MAP = {"00": "off", "01": "on"}
DHW_STATE_LOOKUP = {v: k for k, v in DHW_STATE_MAP.items()}

# Electric Heat - on/off relay (only)
# Zone Valve    - on/off relay AND requests heat from the boiler, 3150

ZONE_TABLE = {
    "UFH": {"type": "02", "actuator": "UFC", "name": "Underfloor Heating"},
    "RAD": {"type": "04", "actuator": "TRV", "name": "Radiator Valve"},
    "ELE": {"type": "13", "actuator": "BDR", "name": "Electric Heat"},
    "VAL": {"type": "x0", "actuator": "BDR", "name": "Zone Valve"},
    "MIX": {"type": "x1", "actuator": "HM8", "name": "Mixing Valve"},
    "DHW": {"type": "x2", "sensor": "DHW", "name": "Stored DHW"},
}
ZONE_CLASS_MAP = {v["type"]: k for k, v in ZONE_TABLE.items()}
ZONE_CLASS_MAP["00"] = ZONE_CLASS_MAP["04"]
ZONE_TYPE_MAP = {k: slug(v["name"]) for k, v in ZONE_TABLE.items()}
ZONE_TYPE_SLUGS = {slug(v["name"]): k for k, v in ZONE_TABLE.items()}

DTM_LONG_REGEX = re.compile(
    r"\d{4}-[01]\d-[0-3]\d(T| )[0-2]\d:[0-5]\d:[0-5]\d\.\d{6} ?"
)  # 2020-11-30T13:15:00.123456
DTM_TIME_REGEX = re.compile(r"[0-2]\d:[0-5]\d:[0-5]\d\.\d{3} ?")  # 13:15:00.123

# Used by packet structure validators
r = r"(-{3}|\d{3}|\.{3})"  # RSSI, '...' was used by an older version of evofw3
v = r"( I|RP|RQ| W)"  # Verb
d = r"(-{2}:-{6}|\d{2}:\d{6})"  # Device ID
c = r"[0-9A-F]{4}"  # Code
l = r"\d{3}"  # Length # noqa: E741
p = r"([0-9A-F]{2}){1,48}"  # Payload

DEVICE_ID_REGEX = re.compile(f"^{d}$")
COMMAND_REGEX = re.compile(f"^{v} {r} {d} {d} {d} {c} {l} {p}$")
MESSAGE_REGEX = re.compile(f"^{r} {v} {r} {d} {d} {d} {c} {l} {p}$")

MSG_FORMAT_10 = "|| {:10s} | {:10s} | {:2s} | {:16s} | {:8s} || {}"
MSG_FORMAT_18 = "|| {:18s} | {:18s} | {:2s} | {:16s} | {:8s} || {}"

ATTR_CONTROLLER = "controller"
ATTR_DEVICES = "devices"
ATTR_DHW_SENSOR = "hotwater_sensor"
ATTR_DHW_VALVE = "hotwater_valve"
ATTR_DHW_VALVE_HTG = "heating_valve"
ATTR_HTG_CONTROL = "heating_control"  # aka boiler relay, heating appliance
ATTR_HTG_PUMP = "heat_pump_control"  # same as ATTR_HTG_CONTROL, but parameters differ
ATTR_HEAT_DEMAND = "heat_demand"
ATTR_WINDOW_OPEN = "window_open"
ATTR_ORPHANS = "orphans"
ATTR_SETPOINT = "setpoint"
ATTR_STORED_HW = "stored_hotwater"
ATTR_SYSTEM = "system"
ATTR_TEMP = "temperature"
ATTR_UFH_CONTROLLERS = "ufh_controllers"
ATTR_ZONE_ACTUATORS = "zone_actuators"
ATTR_ZONE_IDX = "zone_idx"
ATTR_ZONE_SENSOR = "sensor"
ATTR_ZONE_TYPE = "heating_type"
ATTR_ZONES = "zones"

# RP|system_zones = {'zone_mask': [1,1,0,0,0,0,0,0,0,0,0,0], 'zone_type': 'dhw_actuator'}  # noqa


ATTR_RAD_VALVE = "radiator_valve"
ATTR_UFH_HTG = "underfloor_heating"
ATTR_ZON_VALVE = "zone_valve"
ATTR_MIX_VALVE = "mixing_valve"
ATTR_ELEC_HEAT = "electric_heat"


BDR_ROLES = {
    0: ATTR_HTG_CONTROL,
    1: ATTR_HTG_PUMP,
    2: ATTR_DHW_VALVE,
    3: ATTR_DHW_VALVE_HTG,
    4: ATTR_ZON_VALVE,
    5: ATTR_ELEC_HEAT,
}


CODE_0005_ZONE_TYPE = {
    "00": "configured_zones",  # same as 04?
    # "01": None,
    # "02": None,  # no response?
    # "03": None,
    "04": "configured_zones_alt",  # zones that can have a sensor?
    # "05": None,  # no response?
    # "06": None,  # no response
    # "07": None,  # no response
    "08": ATTR_RAD_VALVE,
    "09": ATTR_UFH_HTG,
    "0A": ATTR_ZON_VALVE,
    "0B": ATTR_MIX_VALVE,
    # "0C": None,
    "0D": ATTR_DHW_SENSOR,
    "0E": ATTR_DHW_VALVE,  # can be 0, 1 or 2 (i.e. 1,1,0,...) of them
    "0F": ATTR_HTG_CONTROL,
    # "10": None,
    "11": ATTR_ELEC_HEAT,
}  # 03, 05, 06, 07: & >11 - no response from 01:

# RP|zone_devices | 000E0... || {'domain_id': 'FA', 'device_class': 'dhw_actuator', 'devices': ['13:081807']}  # noqa
# RP|zone_devices | 010E0... || {'domain_id': 'FA', 'device_class': 'dhw_actuator', 'devices': ['13:106039']}  # noqa

CODE_000C_DEVICE_TYPE = {
    "00": "zone_actuators",
    # "01": None,
    # "02": None,
    # "03": None,  # no response
    "04": ATTR_ZONE_SENSOR,  # 03:, 04:, 34: (if is 01:, will == [], as if no sensor)
    # "05": None,  # no response
    # "06": None,  # no response
    # "07": None,  # no response
    "08": "rad_actuators",
    "09": "ufh_actuators",
    "0A": "val_actuators",
    "0B": "mix_actuators",
    # "0C": None,
    "0D": ATTR_DHW_SENSOR,  # FA, z_idx 0 only
    "0E": ATTR_DHW_VALVE,  # FA, could be F9, ATTR_DHW_VALVE_HTG
    "0F": ATTR_HTG_CONTROL,  # FC, z_idx 0 only
    "10": "Unknown",  # seen when binding a TR87RF
    "11": "ele_actuators",
}

# Used by 0418/system_fault parser
CODE_0418_DEVICE_CLASS = {
    "00": "controller",
    "01": "sensor",
    "04": "actuator",  # if domain is FC, then "boiler_relay"
    "05": "dhw_sensor",  # not ATTR_DHW_SENSOR
    "06": "remote_gateway",  # 30:185469
}
CODE_0418_FAULT_STATE = {
    "00": "fault",
    "40": "restore",
    "C0": "unknown_c0",  # C0s do not appear in the evohome UI
}
CODE_0418_FAULT_TYPE = {
    "01": "system_fault",
    "03": "mains_low",
    "04": "battery_low",
    "06": "comms_fault",
    "0A": "sensor_error",
}

DISCOVER_NOTHING = 0
DISCOVER_SCHEMA = 1
DISCOVER_PARAMS = 2
DISCOVER_STATUS = 4
DISCOVER_ALL = DISCOVER_SCHEMA | DISCOVER_PARAMS | DISCOVER_STATUS

SystemType = SimpleNamespace(
    CHRONOTHERM="chronotherm",
    EVOHOME="evohome",
    HOMETRONICS="hometronics",
    PROGRAMMER="programmer",
    SUNDIAL="sundial",
    GENERIC="generic",
)

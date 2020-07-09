"""Evohome serial."""
from collections import namedtuple
import re

# grep ' F[89ABxDE]' | grep -vE ' (0008|1F09/F8|1FC9|2D49/FD) '
# grep ' F[89ABCDE]' | grep -vE ' (0008|1F09/xx|1FC9|0001|0009|1100|3150|3B00) '

__dev_mode__ = True

HGI_DEV_ID = "18:000730"  # default type and address of HGI, 18:013393
NON_DEV_ID = "--:------"
NUL_DEV_ID = "63:262142"  # 7FFFFF - send here if not bound?

Address = namedtuple("DeviceAddress", "id, type")

HGI_DEVICE = Address(id=HGI_DEV_ID, type=HGI_DEV_ID[:2])
NON_DEVICE = Address(id=NON_DEV_ID, type=NON_DEV_ID[:2])
NUL_DEVICE = Address(id=NUL_DEV_ID, type=NUL_DEV_ID[:2])


# Packet codes
CODE_SCHEMA = {
    # main codes - every sync_cycle
    "1F09": {"name": "system_sync"},
    "2309": {"name": "setpoint", "uses_zone_idx": True},
    "30C9": {"name": "temperature", "uses_zone_idx": True},
    "000A": {"name": "zone_config", "uses_zone_idx": True},
    # zone-specific codes
    "0004": {"name": "zone_name", "uses_zone_idx": True, "rq_length": 2},
    "000C": {"name": "zone_actuators", "uses_zone_idx": True},
    "0404": {"name": "zone_schedule", "uses_zone_idx": True},
    "12B0": {"name": "window_state", "uses_zone_idx": True},
    "2349": {"name": "zone_mode", "uses_zone_idx": True},
    "3150": {"name": "heat_demand", "uses_zone_idx": True},
    # controller/system codes
    "313F": {"name": "datetime"},  # aka ping, datetime_req
    "2E04": {"name": "system_mode", "uses_zone_idx": False},
    "0418": {"name": "system_fault"},
    # device codes
    "0001": {"name": "rf_unknown", "uses_zone_idx": True},  # unknown
    "0016": {"name": "rf_check", "rq_length": 2},
    "0100": {"name": "language", "rq_length": 5},
    "1060": {"name": "device_battery", "uses_zone_idx": True},
    "10E0": {"name": "device_info"},
    "1FC9": {"name": "rf_bind", "uses_zone_idx": True},  # was bind_device
    # dhw codes
    "10A0": {"name": "dhw_params"},
    "1260": {"name": "dhw_temp"},
    "1F41": {"name": "dhw_mode"},
    # tpi codes
    "1100": {"name": "tpi_params"},
    "3B00": {"name": "actuator_sync"},  # was: tpi_sync/actuator_req
    "3EF0": {"name": "actuator_enabled", "uses_zone_idx": False},
    "3EF1": {"name": "actuator_state", "uses_zone_idx": False, "rq_length": 2},
    # OpenTherm codes
    "1FD4": {"name": "opentherm_sync"},
    "22D9": {"name": "boiler_setpoint"},
    "3220": {"name": "opentherm_msg"},
    # Other codes...
    "0008": {"name": "relay_demand", "uses_zone_idx": True},
    "0009": {"name": "relay_failsafe", "uses_zone_idx": True},
    "1030": {"name": "mixvalve_config", "uses_zone_idx": True},
    # UFH-specific codes...
    "22C9": {"name": "ufh_setpoint"},
    "22D0": {"name": "message_22d0", "uses_zone_idx": None},  # system switch?
    # unknown/unsure codes - some maybe not evohome, maybe not even Honeywell
    "0002": {"name": "sensor_weather"},
    "0005": {"name": "system_zone", "rq_length": 2},
    "0006": {"name": "schedule_sync"},  # for F9/FA/FC, idx for BDR, F8/FF (all?)
    "1280": {"name": "outdoor_humidity"},
    "1290": {"name": "outdoor_temp"},
    "12A0": {"name": "indoor_humidity"},  # Nuaire ventilation
    "2249": {"name": "oth_setpoint", "uses_zone_idx": None},  # now/next setpoint
    # "2389": {"name": "message_2389"},  # not real?
    "22F1": {"name": "vent_switch"},
    "22F3": {"name": "other_switch"},
    "2D49": {"name": "message_2d49"},  # hometronics only? has a domain = FD!
    "31D9": {"name": "message_31d9"},  # HVAC/ventilation 30 min sync cycle?
    "31DA": {"name": "message_31da"},  # from HCE80, also Nuaire: Contains R/humidity??
    "31E0": {"name": "message_31e0"},  # Nuaire ventilation
    # unknown codes, sent only by STA
    "000E": {"name": "message_000e", "uses_zone_idx": False},
    "042F": {"name": "message_042f", "uses_zone_idx": False},
    "3120": {"name": "message_3120", "uses_zone_idx": False},
    # unknown codes, initiated only by HR91
    "01D0": {"name": "message_01d0", "uses_zone_idx": True},  # might yet be False
    "01E9": {"name": "message_01e9", "uses_zone_idx": True},  # might yet be False
}

MAY_USE_DOMAIN_ID = ["0001", "0008", "0009", "1100", "1FC9", "3150", "3B00"]
MAY_USE_ZONE_IDX = [k for k, v in CODE_SCHEMA.items() if v.get("uses_zone_idx")]
# DES_SANS_ZONE_IDX = ["0002", "2E04"]  # not sure about "0016", "22C9"

CODE_MAP = {k: v["name"] for k, v in CODE_SCHEMA.items()}

# TODO: which device type/config pairs send what packets?
DEVICE_TABLE = {
    # Honeywell evohome
    "01": {
        "type": "CTL",
        "name": "Controller",
        "has_battery": False,
        "is_actuator": False,
        "is_controller": True,
        "is_sensor": True,
    },  # rechargeable
    "02": {
        "type": "UFH",
        "name": "UFH Controller",
        "has_battery": False,
        "is_actuator": None,
        "is_controller": None,
        "is_sensor": None,
    },  # HCE80(R)
    "03": {
        "type": "STa",
        "name": "Room Sensor/Stat",
        "has_battery": True,
        "is_actuator": False,
        "is_sensor": True,
    },  # HCW80 (HCF82)
    "04": {
        "type": "TRV",
        "name": "Radiator Valve",
        "has_battery": True,
        "is_actuator": True,
        "is_sensor": True,
    },  # HR80, HR92
    "07": {
        "type": "DHW",
        "name": "DHW Sensor",
        "has_battery": True,
        "is_actuator": False,
        "is_sensor": True,
    },  # CS92
    "10": {
        "type": "OTB",
        "name": "OpenTherm Bridge",
        "has_battery": False,
        "is_actuator": None,
        "is_sensor": False,
    },  # R8810
    "12": {
        "type": "THm",
        "name": "Room Thermostat",
        "has_battery": True,
        "is_actuator": False,
        "is_sensor": True,
    },  # DTS92(E)
    "13": {
        "type": "BDR",
        "name": "Wireless Relay",
        "has_battery": False,
        "is_actuator": None,
        "is_sensor": False,
    },  # BDR91, HC60NG?
    "22": {
        "type": "THM",
        "name": "Room Thermostat",
        "has_battery": True,
        "is_actuator": False,
        "is_sensor": True,
    },  # DTS92(E)
    "30": {
        "type": "GWY",
        "name": "Internet Gateway",
        "has_battery": False,
        "is_actuator": False,
        "is_sensor": False,
    },  # RFG100, VMS?
    "34": {
        "type": "STA",
        "name": "Round Thermostat",
        "has_battery": True,
        "is_actuator": False,
        "is_sensor": True,
    },  # T87RF
    # Honeywell evohome TBD
    "x1": {
        "type": "MIX",
        "name": "Mixing Valve",
        "has_battery": False,
        "is_actuator": None,
        "is_sensor": None,
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
    },  # HGI80
    "23": {
        "type": "PRG",
        "name": "Programmer (wired)",
        "has_battery": False,
        "is_actuator": False,
        "is_sensor": True,
    },  # ST9420C
    # non-Honeywell, HVAC? (also, 30: is a Nuaire PIV)
    "20": {"type": "VCE", "name": "AC/Ventilation?",},  # VCE-RF unit
    "32": {"type": "VMS", "name": "AC/Ventilation?",},  # sensor/switch
    "37": {"type": " 37", "name": "AC/Ventilation?",},  # VCE
    "49": {"type": " 49", "name": "AC/Ventilation?",},  # VCE switch
    # specials
    "63": {"type": "NUL", "name": "Null Device",},
    "--": {"type": "---", "name": "No Device",},
}
# VMS includes Nuaire VMS-23HB33, VMS-23LMH23
# What about Honeywell MT4 actuator?

# Example of:
#  - Sundial RF2 Pack 3: 23:(ST9420C), 07:(CS92), and 22:(DTS92(E))

# HCW80 has option of being wired
# ST9420C has battery back-up (as does evohome)

DEVICE_TYPES = {k: v["type"] for k, v in DEVICE_TABLE.items()}
DEVICE_LOOKUP = {v: k for k, v in DEVICE_TYPES.items()}
DEVICE_CLASSES = {v["type"]: v["name"] for _, v in DEVICE_TABLE.items()}
DEVICE_HAS_BATTERY = [
    k for k, v in DEVICE_TABLE.items() if v.get("has_battery") is True
]

# Domains
DOMAIN_TYPE_MAP = {
    "F8": "TBD",
    "F9": "Heating",  # Central Heating
    "FA": "HotWater",  # Stored DHW loop? (or UFH loop if src.type == "02"?)
    "FB": "TBD",  # TODO: bind CS92 with BDRs in both modes
    "FC": "Boiler",  # "Heat Source": BDR (Boiler, District heating), or OTB
    "FF": "System",  # TODO: remove this, is not a domain
}  # "21": "Ventilation",
DOMAIN_TYPE_LOOKUP = {v: k for k, v in DOMAIN_TYPE_MAP.items() if k != "FF"}

SYSTEM_MODE_MAP = {
    "00": "Auto",
    "01": "HeatOff",
    "02": "Eco",
    "03": "Away",
    "04": "DayOff",
    "05": "DayOffThenEco",  # set to Eco when DayOff ends
    "06": "AutoWithReset",
    "07": "Custom",
}
SYSTEM_MODE_LOOKUP = {v: k for k, v in SYSTEM_MODE_MAP.items()}

ZONE_MODE_MAP = {
    "00": "FollowSchedule",
    "01": "AdvancedOverride",  # until the next scheduled setpoint
    "02": "PermanentOverride",
    # "03": "DayOverride",  # ignores until, uses duration of 20h 15m!
    "04": "TemporaryOverride",  # requires an until (datetime)
}
ZONE_MODE_LOOKUP = {v: k for k, v in ZONE_MODE_MAP.items()}

DHW_STATE_MAP = {
    "00": "Off",
    "01": "On",
}
DHW_STATE_LOOKUP = {v: k for k, v in DHW_STATE_MAP.items()}

# Electric Heat - on/off relay (only)
# Zone Valve    - on/off relay AND requests heat from the boiler, 3150

MAX_ZONES = 12
# Evohome: 12 (0-11), older/initial version was 8
# Hometronics: 16 (0-15), or more?
# Sundial RF2: 2 (0-1), usually only one, but ST9520C can do two zones

ZONE_TABLE = {
    "UFH": {"type": "02", "name": "Underfloor Heating"},
    "TRV": {"type": "04", "name": "Radiator Valve(s)"},
    "BDR": {"type": "13", "name": "Electric Heat"},
    "VAL": {"type": "x0", "name": "Zone Valve"},
    "MIX": {"type": "x1", "name": "Mixing Valve"},
    "DHW": {"type": "FC", "name": "Stored DHW"},
}
ZONE_TYPE_MAP = {k: v["name"] for k, v in ZONE_TABLE.items()}
ZONE_CLASS_MAP = {v["type"]: k for k, v in ZONE_TABLE.items()}

# Used by 0418/system_fault parser
FAULT_DEVICE_CLASS = {
    "00": "Controller?",
    "01": "Sensor",
    "04": "Actuator",
    "05": "DhwSensor?",
}
FAULT_STATE = {"00": "Fault", "40": "Restore", "C0": "Unknown (C0)"}
FAULT_TYPE = {
    "03": "MainsLow",
    "04": "BatteryLow",
    "06": "CommsFault",
    "0A": "SensorError",
}

ISO_FORMAT_REGEX = r"\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\d\.\d{6} ?"

# Used by packet structure validators
a = r"(-{3}|\d{3})"
b = r"( I|RP|RQ| W)"
c = r"(-{2}:-{6}|\d{2}:\d{6})"
d = r"[0-9A-F]{4}"
e = r"\d{3}"
f = r"([0-9A-F]{2})+"

COMMAND_REGEX = re.compile(f"^{b} {a} {c} {c} {c} {d} {e} {f}$")
MESSAGE_REGEX = re.compile(f"^{a} {b} {a} {c} {c} {c} {d} {e} {f}$")

COMMAND_FORMAT = "{:<2} --- {} {} --:------ {} {:03d} {}"
MSG_FORMAT_10 = "|| {:10s} | {:10s} | {:2s} | {:16s} | {:8s} || {}"
MSG_FORMAT_18 = "|| {:18s} | {:18s} | {:2s} | {:16s} | {:8s} || {}"

# Packet codes/classes - lengths are in bytes, len(0xFF) == 1
TBD_COMMAND_MAGIC = {
    "0004": {
        "length": {"RQ": 2, "RP": 22, " I": 22, " W": 22},
        "zone_idx": 2 * 2,
        "null_resp": "7F" * 20,
    },
    "000A": {
        "length": {"RQ": [1, 6], "RP": 6, " I": 6, " W": 0},
        "zone_idx": True,
        "null_resp": "007FFF7FFF",
    },  # CTL/I is an array
    "000C": {
        "length": {"RQ": 2, "RP": 6, " I": 0, " W": 0},
        "zone_idx": True,
        "null_resp": "007FFFFFFF",
    },  # RP is an array
    "2309": {
        "length": {"RQ": 1, "RP": 3, " I": 3, " W": 0},
        "zone_idx": True,
        "null_resp": "7FFF",
    },  # CTL/I is an array
    "30C9": {
        "length": {"RQ": 1, "RP": 3, " I": 0, " W": 0},
        "zone_idx": True,
        "null_resp": "7FFF",
    },  # CTL/I is an array
    "12B0": {
        "length": {"RQ": 1, "RP": 3, " I": 0, " W": 0},
        "zone_idx": True,
        "null_resp": "7FFF",
    },
    "2349": {
        "length": {"RQ": 1, "RP": 7, " I": 3, " W": 0},
        "zone_idx": True,
        "null_resp": "7FFF00FFFFFF",
    },
    "0008": {"length": {"RQ": 0, "RP": 0, " I": 2, " W": 0}},
    "1060": {"length": {"RQ": 0, "RP": 0, " I": 3, " W": 0}},  # zone for 04:
    "3150": {"length": {"RQ": 0, "RP": 0, " I": 2, " W": 0}},
    "1F09": {"length": {"RQ": 1, "RP": 3, " I": 0, " W": 0}},
    "2E04": {"length": {"RQ": 1, "RP": 8, " I": 0, " W": 0}},
}

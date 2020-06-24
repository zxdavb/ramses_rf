"""Evohome serial."""
import re

__dev_mode__ = False

NON_DEV_ID = "--:------"
NUL_DEV_ID = "63:262142"  # 7FFFFF - send here if not bound?
HGI_DEV_ID = "18:000730"  # default type and address of HGI, 18:013393

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
    "2D49": {"name": "message_2d49"},  # hometronics only?
    "31D9": {"name": "message_31d9"},  # Nuaire ventilation
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

#
# sed -e 's/ 01:/ CTL:/g' -e 's/ 02:/ UFH:/g' -e 's/ 04:/ TRV:/g' -i pkts.out
# sed -e 's/ 07:/ DHW:/g' -e 's/ 10:/ OTB:/g' -e 's/ 12:/ THM:/g' -i pkts.out
# sed -e 's/ 13:/ BDR:/g' -e 's/ 18:/ HGI:/g' -e 's/ 22:/ THm:/g' -i pkts.out
# sed -e 's/ 30:/ GWY:/g' -e 's/ 32:/ VNT:/g' -e 's/ 34:/ STA:/g' -i pkts.out
# sed -e 's/ 63:/ ALL:/g' -e 's/ --:/  --:/g' -i pkts.out

# TODO: which device type/config pairs send what packets?
DEVICE_TABLE = {
    "01": {"type": "CTL", "name": "Controller", "battery": False},  # rechargeable
    "02": {"type": "UFH", "name": "UFH Controller", "battery": False},  # HCE80(R)
    "03": {"type": "STa", "name": "Room Sensor/Stat", "battery": None},  # HCF82, HCW82
    "04": {"type": "TRV", "name": "Radiator Valve", "battery": True},  # HR80, HR92
    "07": {"type": "DHW", "name": "DHW Sensor", "battery": True},  # CS92
    "10": {"type": "OTB", "name": "OpenTherm Bridge", "battery": False},  # R8810
    "12": {"type": "THm", "name": "Room Thermostat", "battery": True},  # DTS92(E)
    "13": {"type": "BDR", "name": "Wireless Relay", "battery": False},  # BDR91, HC60NG?
    "17": {"type": " 17", "name": "Outdoor Sensor?", "battery": None},  # TODO: HB85?
    "18": {"type": "HGI", "name": "Honeywell Gateway?", "battery": False},  # HGI80
    "20": {"type": "VCE", "name": "Ventilation?", "battery": None},  # VCE-RF
    "22": {"type": "THM", "name": "Room Thermostat", "battery": True},  # DTS92(E)
    "23": {"type": "PRG", "name": "Programmer (wired)", "battery": False},  # ST9420C
    "30": {"type": "GWY", "name": "Internet Gateway", "battery": False},  # RFG100, VMS?
    "32": {"type": "VMS", "name": "Ventilation?", "battery": None},  # all have battery?
    "34": {"type": "STA", "name": "Round Thermostat", "battery": True},  # T87RF
    "37": {"type": " 37", "name": "Ventilation?", "battery": None},
    #
    "63": {"type": "NUL", "name": "Null Device", "battery": None},
    "--": {"type": "---", "name": "No Device", "battery": None},
    "??": {"type": "MIX", "name": "Mixing Valve", "battery": False},  # TODO: ???
}
# VMS includes Nuaire VMS-23HB33, VMS-23LMH23
# What about Honeywell MT4 actuator?

# Example of:
#  - Sundial RF2 Pack 3: 23:(ST9420C), 07:(CS92), and 22:(DTS92(E))

DEVICE_TYPES = {k: v["type"] for k, v in DEVICE_TABLE.items()}
DEVICE_LOOKUP = {v: k for k, v in DEVICE_TYPES.items()}
DEVICE_CLASSES = {v["type"]: v["name"] for _, v in DEVICE_TABLE.items()}
DEVICE_HAS_BATTERY = [k for k, v in DEVICE_TABLE.items() if v["battery"] is True]

# Domains
DOMAIN_TYPE_MAP = {
    "F8": "TBD",
    "F9": "Heating",  # Central Heating
    "FA": "HotWater",  # Stored DHW loop? (or UFH loop if src.type == "02"?)
    "FB": "TBD",  # TODO: bind CS92 with BDRs in both modes
    "FC": "Boiler",  # "Heat Source": BDR (Boiler, District heating), or OTB
    "FF": "System",  # TODO: remove this, is not a domain
}  # "21": "Ventilation",

SYSTEM_MODE_MAP = {
    "00": "Auto",
    "01": "HeatOff",
    "02": "Eco",
    "03": "Away",
    "04": "DayOff",
    "07": "Custom",
}  # what about 5, 6 & AutoWithReset?

ZONE_MODE_MAP = {
    "00": "FollowSchedule",
    "02": "PermanentOverride",
    "04": "TemporaryOverride",  # will incl. a datetime
}  # "01": until next SP?

# Electric Heat - on/off relay (only)
# Zone Valve    - on/off relay AND requests heat from the boiler, 3150
ZONE_TYPE_MAP = {
    "TRV": "Radiator Valve(s)",
    "BDR": "Electric Heat",  # Zone Valve
    "UFH": "Underfloor Heating",
    "MIX": "Mixing Valve",
    "VAL": "Zone Valve",
}

# Used by 0418/system_fault parser
FAULT_DEVICE_CLASS = {
    "00": "Controller?",
    "01": "Sensor",
    "04": "Actuator",
    "05": "DhwSensor?",
}
FAULT_STATE = {"00": "Fault", "40": "Restore", "C0": "Unknown (C0)"}
FAULT_TYPE = {
    # "03": "???",
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

# Used by SQL DB
TABLE_SQL = """
    CREATE TABLE IF NOT EXISTS packets(
        dt      TEXT PRIMARY KEY,
        rssi    TEXT NOT NULL,
        verb    TEXT NOT NULL,
        seq     TEXT NOT NULL,
        dev_0   TEXT NOT NULL,
        dev_1   TEXT NOT NULL,
        dev_2   TEXT NOT NULL,
        code    TEXT NOT NULL,
        len     TEXT NOT NULL,
        payload TEXT NOT NULL
    ) WITHOUT ROWID;
"""

INDEX_SQL = "CREATE INDEX IF NOT EXISTS code_idx ON packets(code);"

INSERT_SQL = """
    INSERT INTO packets(dt, rssi, verb, seq, dev_0, dev_1, dev_2, code, len, payload)
    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
"""

# BEGIN TRANSACTION;
RENAME_0 = """
    CREATE TABLE IF NOT EXISTS pkts_temp(
        dt      TEXT PRIMARY KEY,
        rssi    TEXT NOT NULL,
        verb    TEXT NOT NULL,
        seq     TEXT NOT NULL,
        dev_0   TEXT NOT NULL,
        dev_1   TEXT NOT NULL,
        dev_2   TEXT NOT NULL,
        code    TEXT NOT NULL,
        len     TEXT NOT NULL,
        payload TEXT NOT NULL
    ) WITHOUT ROWID;
"""

RENAME_1 = """
    INSERT INTO pkts_temp(dt, rssi, verb, seq, dev_0, dev_1, dev_2, code, len, payload)
    SELECT dt, rssi, verb, seq, dev_1, dev_2, dev_3, code, len, payload
    FROM packets;
"""

RENAME_2 = """
    DROP TABLE packets;
"""

RENAME_3 = """
    ALTER TABLE pkts_temp
    RENAME TO packets;
"""
# COMMIT;

RENAME_3 = """
    VACUUM;
"""

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

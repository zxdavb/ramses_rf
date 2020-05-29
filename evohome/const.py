"""Evohome serial."""
import re

__dev_mode__ = True

NON_DEV_ID = "--:------"
NUL_DEV_ID = "63:262142"  # 7FFFFF - send here if not bound?
HGI_DEV_ID = "18:000730"  # default type and address of HGI, 18:013393

# CTL_DEV_ID = "01:145038"  # 06368E
# TPI_DEV_ID = "13:237335"  # Boiler relay


# Packet codes/classes - lengths are in bytes, len(0xFF) == 1
COMMAND_MAGIC = {
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

# Packet codes/classes
COMMAND_SCHEMA = {
    "0001": {"name": "message_0001"},  #
    "0002": {"name": "sensor_weather"},
    "0004": {"name": "zone_name", "exposes_zone": True, "rq_length": 2},
    "0005": {"name": "system_zone", "rq_length": 2},
    "0006": {"name": "schedule_sync"},  # for F9/FA/FC, zone_idx for BDR, F8/FF (all?)
    "0008": {"name": "relay_demand"},
    "0009": {"name": "relay_failsafe", "exposes_zone": None},
    "000A": {"name": "zone_config", "exposes_zone": True},
    "000C": {"name": "zone_actuators", "exposes_zone": None},
    "000E": {"name": "message_000e", "exposes_zone": False},
    "0016": {"name": "rf_check", "rq_length": 2},
    "0100": {"name": "language", "rq_length": 5},
    "0404": {"name": "zone_schedule"},
    "0418": {"name": "system_fault"},
    "042F": {"name": "message_042f", "exposes_zone": False},
    "1030": {"name": "mixvalve_config"},
    "1060": {"name": "device_battery", "exposes_zone": True},
    "10A0": {"name": "dhw_params"},
    "10E0": {"name": "device_info"},
    "1100": {"name": "tpi_params"},  # boiler CH config
    "1260": {"name": "dhw_temp"},
    "1280": {"name": "outdoor_humidity"},
    "1290": {"name": "outdoor_temp"},
    "12A0": {"name": "indoor_humidity"},  # Nuaire ventilation
    "12B0": {"name": "window_state", "exposes_zone": True},  # "device_or_zone": True
    "1F09": {"name": "sync_cycle"},
    "1F41": {"name": "dhw_mode"},
    "1FC9": {"name": "bind_device"},  # aka bind
    "1FD4": {"name": "opentherm_sync"},
    "2249": {"name": "unknown_2249"},  # programmer now/next setpoint (jrosser/honeymon)
    "22C9": {"name": "ufh_setpoint"},
    "22D0": {"name": "message_22d0"},  # used with UFH, ~15min
    "22D9": {"name": "boiler_setpoint"},  # used with OTB
    "22F1": {"name": "vent_switch"},
    "2309": {"name": "setpoint", "exposes_zone": True},  # "device_or_zone": True
    "2349": {"name": "zone_mode", "exposes_zone": True},  # TODO: confirm
    "2389": {"name": "unknown_2389"},  # not real?
    "2D49": {"name": "unknown_2d49"},  # hometronics only?
    "2E04": {"name": "system_mode"},
    "30C9": {"name": "temperature", "exposes_zone": False},  # "device_or_zone": True
    "3120": {"name": "message_3120", "exposes_zone": False},  # From STA
    "313F": {"name": "datetime"},  # aka ping, datetime_req
    "3150": {"name": "heat_demand", "exposes_zone": True},  # "device_or_zone": ????
    "31D9": {"name": "message_31d9"},  # Nuaire ventilation
    "31DA": {"name": "message_31da"},  # from HCE80, also Nuaire: Contains R/humidity??
    "31E0": {"name": "message_31e0"},  # Nuaire ventilation
    "3220": {"name": "opentherm_msg"},  # OTB
    "3B00": {"name": "sync_tpi"},  # was actuator_req - start of TPI cycle
    "3EF0": {"name": "actuator_enabled"},
    "3EF1": {"name": "actuator_state", "rq_length": 2},  # from 12: to (missing) 13:
    #
}

COMMAND_EXPOSES_ZONE = [k for k, v in COMMAND_SCHEMA.items() if v.get("exposes_zone")]

COMMAND_MAP = {k: v["name"] for k, v in COMMAND_SCHEMA.items()}

COMMAND_LOOKUP = {v: k for k, v in COMMAND_MAP.items()}

COMMAND_LENGTH = max([len(k) for k in list(COMMAND_LOOKUP)])

#
# sed -e 's/ 01:/ CTL:/g' -e 's/ 02:/ UFH:/g' -e 's/ 04:/ TRV:/g' -i pkts.out
# sed -e 's/ 07:/ DHW:/g' -e 's/ 10:/ OTB:/g' -e 's/ 12:/ THM:/g' -i pkts.out
# sed -e 's/ 13:/ BDR:/g' -e 's/ 18:/ HGI:/g' -e 's/ 22:/ THm:/g' -i pkts.out
# sed -e 's/ 30:/ GWY:/g' -e 's/ 32:/ VNT:/g' -e 's/ 34:/ STA:/g' -i pkts.out
# sed -e 's/ 63:/ ALL:/g' -e 's/ --:/  --:/g' -i pkts.out

# TODO: which device type/config pairs send what packets?
DEVICE_TABLE = {
    "01": {"type": "CTL", "battery": False},  # Evohome Controller
    "02": {"type": "UFH", "battery": False},  # Underfloor heating: HCC80, HCE80
    "04": {"type": "TRV", "battery": True},  # .Radiator valve: HR80, HR91, HR92
    "07": {"type": "DHW", "battery": True},  # .DHW sensor: CS92
    "10": {"type": "OTB", "battery": False},  # OpenTherm bridge: R8810
    "12": {"type": "THm", "battery": True},  # .Thermostat (with schedule?): DTS92E
    "13": {"type": "BDR", "battery": False},  # Wireless relay box: BDR91; HC60NG too?
    "18": {"type": "HGI", "battery": False},  # Honeywell Gwy Interface: HGI80, HGS80
    "20": {"type": "VCE", "battery": None},  # VCE-RF ?ventilation
    "22": {"type": "THM", "battery": True},  # .Thermostat (with schedule?): DTS92E
    "30": {"type": "GWY", "battery": False},  # Gateway: RFG100? ?ventilation
    "32": {"type": "VMS", "battery": True},  # .Ventilation Nuaire VMS-23HB33, -23LMH23
    "34": {"type": "STA", "battery": True},  # .Thermostat (without schedule?): T87RF
    "63": {"type": "NUL", "battery": None},
    "--": {"type": "---", "battery": None},
}  # TODO: Mixing valve: HM80 (no battery)
#   "03": {"type": " 03", "battery": None},  # (Wireless room stat: HCF82, HCW82)??
#   "17": {"type": " 17", "battery": None},  # Dunno - Outside weather sensor?
DEVICE_TYPES = {k: v["type"] for k, v in DEVICE_TABLE.items()}
DEVICE_LOOKUP = {v: k for k, v in DEVICE_TYPES.items()}

# Domains
DOMAIN_MAP = {
    # "21": "Ventilation",
    "F8": "???",
    "F9": "Heating",  # Central Heating
    "FA": "HotWater",  # Stored DHW?
    "FB": "???",  # TODO: bind CS92 with BDRs in both modes
    "FC": "Boiler",  # "Heat Source": BDR (Boiler, District heating), or OTB
    "FF": "System",
}

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
# Zone Valve    - on/off relay (to operate the valve) AND requests heat from the boiler
ZONE_TYPE_MAP = {
    "TRV": "Radiator Valve",
    "BDR": "Electric Heat",  # /Zone Valve",
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
FAULT_TYPE = {"04": "BatteryLow", "06": "CommsFault", "0A": "SensorError"}

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

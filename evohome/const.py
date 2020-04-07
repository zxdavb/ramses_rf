"""Evohome serial."""
import re

NUL_DEV_ID = "63:262142"  # 7FFFFF - send here if not bound?
CTL_DEV_ID = "01:145038"  # 06368E
HGI_DEV_ID = "18:000730"  # default type and address of HGI, 18:013393
TPI_DEV_ID = "13:237335"  # Boiler relay
NON_DEV_ID = "--:------"

# Domains
DOMAIN_MAP = {"FA": "Hot Water", "FC": "Heat Demand"}
# FC - Heat Demand
# FF


# Test devices
# BDR:106039 (359E37)
# STA:064023 (88FA17)
# HGI:013393 (483451)

# System Information
# App. S/W ver: 02.00.17.03
# Wifi S/W ver: 02.00.17.00
# Device ID: 06368E (01:145038)

# https://github.com/domoticz/domoticz/blob/development/hardware/EvohomeRadio.cpp
# https://github.com/Evsdd/Evohome_Controller/blob/master/Evohome_Controller.py
# https://github.com/jrosser/honeymon/blob/master/decoder.cpp
# https://github.com/smar000/evohome-Listener
# https://github.com/Evsdd/Evohome_Schedule_Restore
# https://www.domoticz.com/forum/viewtopic.php?f=34&t=16742&p=216168#p216168

HARVEST_PKTS = {
    "061 RQ --- 04:189082 01:145038 --:------ 0004 002 0400",
    "045 RP --- 01:145038 04:189082 --:------ 0004 022 04004265616E7320526F6F6D00000000000000000000"  # noqa: E501
    "045 RQ --- 34:092243 01:145038 --:------ 000A 001 01",
    "045 RP --- 01:145038 34:092243 --:------ 000A 006 011001F40DAC",
    "063  I --- 04:189080 --:------ 01:145038 1060 003 056401",
    "045  I --- 04:056059 --:------ 01:145038 12B0 003 010000",
    "045  I --- 04:056057 --:------ 01:145038 2309 003 03073A",
    "063  I --- 01:145038 --:------ 01:145038 2309 003 0105DC",
    "069 RQ --- 34:092243 01:145038 --:------ 2309 001 01",
    "072 RP --- 01:145038 34:092243 --:------ 2309 003 0107D0",
    "049  W --- 34:092243 01:145038 --:------ 2309 003 0105DC",
    "064  I --- 01:145038 34:092243 --:------ 2309 003 0105DC",
    "000  I --- 01:145038 --:------ 01:145038 2349 013 03079E04FFFFFF1E15100207E4",
    "000  I --- 01:145038 --:------ 01:145038 2349 007 03079E00FFFFFF",
    "045  I --- 04:056059 --:------ 01:145038 3150 002 0120",
}

x = {f"{p[4:6]}{p[41:45]}": "" for p in HARVEST_PKTS}


COMMAND_SCHEMA = {
    "0001": {"name": "message_0001"},  #
    "0002": {"name": "sensor_weather"},
    "0004": {"name": "zone_name", "exposes_zone": True, "rq_length": 2},
    "0005": {"name": "system_zone", "rq_length": 2},
    "0006": {"name": "schedule_sync"},  # for F9/FA/FC, zone_idx for BDR, F8/FF (all?)
    "0008": {"name": "relay_demand"},
    "0009": {"name": "relay_failsafe", "exposes_zone": None},
    "000A": {"name": "zone_config", "exposes_zone": True},
    "000C": {"name": "zone_actuators", "exposes_zone": None},  # special case
    "000E": {"name": "message_000E", "exposes_zone": False},
    "0016": {"name": "rf_check", "rq_length": 2},
    "0100": {"name": "localisation", "rq_length": 5},
    "0404": {"name": "zone_schedule"},
    "0418": {"name": "system_fault"},
    "042F": {"name": "message_042F", "exposes_zone": False},
    "1030": {"name": "mixvalve_config"},
    "1060": {"name": "device_battery", "exposes_zone": True},
    "10A0": {"name": "dhw_params"},
    "10E0": {"name": "device_info"},
    "1100": {"name": "boiler_params"},  # boiler CH config
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
    "22D9": {"name": "boiler_setpoint"},  # used with OTB
    "22F1": {"name": "message_22f1"},
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

# TODO: what devices send what packets
DEVICE_MAP = {
    "01": "CTL",  # Controller
    "02": "UFH",  # Underfloor heating (HCC80, HCE80)
    "03": " 30",  # HCW82??
    "04": "TRV",  # Thermostatic radiator valve (HR80, HR91, HR92)
    "07": "DHW",  # DHW sensor (CS92)
    "10": "OTB",  # OpenTherm bridge (R8810)
    "12": "THm",  # Thermostat with setpoint schedule control (DTS92E)
    "13": "BDR",  # Wireless relay box (BDR91)  # 3EF0=relay/TPI; 3B00=TPI (HC60NG too?)
    "17": " 17",  # Dunno - Outside weather sensor?
    "18": "HGI",  # Honeywell Gateway Interface (HGI80, HGS80)
    "22": "THM",  # Thermostat with setpoint schedule control (DTS92E)
    "30": "GWY",  # Gateway (e.g. RFG100?)
    "32": "VNT",  # (HCE80) Ventilation (Nuaire VMS-23HB33, VMN-23LMH23)
    "34": "STA",  # Thermostat (T87RF)  # 1060, 10E0, 30C9
    "63": "NUL",  # is sent: 10E0, 1FC9
    "--": " --",
}  # Mixing valve (HM80)
DEVICE_LOOKUP = {v: k for k, v in DEVICE_MAP.items()}

DOMAIN_MAP = {"F9": "Heating", "FA": "HotWater", "FC": "Boiler"}

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
    "ZON": "Zone Valve",
}

a = r"(-{3}|\d{3})"
b = r"( I|RP|RQ| W)"
c = r"(-{2}:-{6}|\d{2}:\d{6})"
d = r"[0-9A-F]{4}"
e = r"\d{3}"
f = r"([0-9A-F]{2})+"

COMMAND_REGEX = re.compile(f"^{b} {a} {c} {c} {c} {d} {e} {f}$")
MESSAGE_REGEX = re.compile(f"^{a} {b} {a} {c} {c} {c} {d} {e} {f}$")

COMMAND_FORMAT = "{:<2} --- {} {} --:------ {} {:03.0f} {}"
MESSAGE_FORMAT = "|| {:18s} | {:18s} | {:2s} | {:16s} | {:10s} || {}"

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
    INSERT INTO packets(dt, rssi, verb, seq, dev_1, dev_2, dev_3, code, len, payload)
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

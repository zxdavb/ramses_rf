"""Evohome serial."""

import re

ALL_DEV_ID = "63:262142"  # 7FFFFF - send here if not bound?
CTL_DEV_ID = "01:145038"  # 06368E
HGI_DEV_ID = "18:730"  # default type and address of HGI
NO_DEV_ID = "--:------"

# Domains
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

# https://github.com/Evsdd/Evohome_Schedule_Restore/blob/e5c5f8ee52d8117804edcc220e474191bae287ae/Evohome_Schedule_Restore_v0.3.py#L53
# https://www.domoticz.com/forum/viewtopic.php?f=34&t=16742&p=216168#p216168

# use: cat packets.log | grep -v " 18:" | grep -E ' [0-9]{3} [0-9][1-9A-F]' | grep -v ' \-\-\- 01' > test.log
COMMAND_SCHEMA = {
    "0002": {"name": "sensor_outside"},
    "0004": {"name": "zone_name", "exposes_zone": True},
    "0005": {"name": "system_zone"},
    "0006": {"name": "schedule_sync"},
    "0008": {"name": "relay_demand"},  # for CH/DHW/Boiler (F9/FA/FC), also zone_idx for BDR, F8/FF (for all)
    "0009": {"name": "relay_failsafe", "exposes_zone": None},
    "000A": {"name": "zone_config", "exposes_zone": True},
    "0016": {"name": "rf_check"},
    "0100": {"name": "localisation"},
    "0404": {"name": "zone_schedule"},
    "0418": {"name": "message_0418"},  # ticker
    # 1030": {"name": "unknown_1030"},  # seen when a BDR91 lost its binding
    "1060": {"name": "device_battery", "exposes_zone": None},
    "10A0": {"name": "dhw_params"},
    "10E0": {"name": "device_info"},
    "1100": {"name": "boiler_params"},  # boiler CH config
    "1260": {"name": "dhw_temp"},
    "12B0": {"name": "window_state", "exposes_zone": True},  # "device_or_zone": True
    "1F09": {"name": "sync_cycle"},
    "1F41": {"name": "dhw_mode"},
    "1FC9": {"name": "bind_device"},  # aka bind
    # 2249": {"name": "unknown"},  # programmer now/next setpoint (jrosser/honeymon)
    "22C9": {"name": "ufh_setpoint"},
    "2309": {"name": "setpoint", "exposes_zone": True},  # "device_or_zone": True
    "2349": {"name": "zone_mode"},
    "2E04": {"name": "system_mode"},
    "30C9": {"name": "temperature", "exposes_zone": False},  # "device_or_zone": True
    # 3120": {"name": "message_unknown", "exposes_zone": False},  # STA, every ~3:45:00
    "313F": {"name": "sync_datetime"},  # aka ping, datetime_req
    "3150": {"name": "heat_demand", "exposes_zone": True},
    "3B00": {"name": "actuator_check"},  # was_req - start of TPI cycle
    "3EF0": {"name": "device_actuator"},
    #
    # ######################################################
    # cat pkts.log | grep 'GWY:' | grep VNT | grep -v 004
    # VNT:206250 // VNT:168090 // GWY:082155
    #
    # cat pkts.log | grep -E '(206250|168090|082155)'
    # shared: | grep -v 1060 | grep -v 10E0 | grep -v 1F09
    # excl.:  | grep -v 12A0 | grep -v 22F1 | grep -v 31D9 | grep -v 31DA | grep -v 31E0
    #
    # These are only ever from 32:206250 (the 4-way switch), or 32:206250 (the CO2 monitor?)
    "12A0": {"name": "sensor_humidity", "non_evohome": True},
    "22F1": {"name": "message_22f1", "non_evohome": True},
    "31D9": {"name": "message_31d9", "non_evohome": True},
    "31DA": {"name": "message_31da", "non_evohome": True},  # Contains R/humidity??
    "31E0": {"name": "message_31e0", "non_evohome": True},
}

COMMAND_EXPOSES_ZONE = [k for k, v in COMMAND_SCHEMA.items() if v.get("exposes_zone")]

COMMAND_MAP = {k: v["name"] for k, v in COMMAND_SCHEMA.items()}

COMMAND_LOOKUP = {v: k for k, v in COMMAND_MAP.items()}

COMMAND_LENGTH = max([len(k) for k in list(COMMAND_LOOKUP)])

# #
# sed -e 's/ 01:/ CTL:/g' -e 's/ 04:/ TRV:/g' -e 's/ 07:/ DHW:/g' -i pkts.log
# sed -e 's/ 12:/  12:/g' -e 's/ 13:/ BDR:/g' -e 's/ 18:/ HGI:/g' -i pkts.log
# sed -e 's/ 30:/ GWY:/g' -e 's/ 32:/ VNT:/g' -e 's/ 34:/ STA:/g' -i pkts.log
# sed -e 's/ 63:/ ALL:/g' -e 's/ --:/  --:/g' -i pkts.log

DEVICE_MAP = {
    "01": "CTL",  # Controller
    "02": "UFH",  # Underfloor heating (HCC80, HCE80)
    "04": "TRV",  # Thermostatic radiator valve (HR80, HR91, HR92)
    "07": "DHW",  # DHW sensor (CS92)
    "12": " 12",  # 0008, 0009, 1030, 1100, 2309, 313F // 12:249582, 12:227486, 12:259810
    "13": "BDR",  # Wireless relay box (BDR91)
    "18": "HGI",  # Honeywell Gateway Interface (HGI80, HGS80)
    "30": "GWY",  # Gateway (e.g. ???)
    "32": "VNT",  # (Nuaire PIV) ventilation (VMS-23HB33)
    "34": "STA",  # Thermostat (T87RF)
    "63": "ALL",  # 10E0, 1FC9
    "--": " --",
}  # Mixing valve (HM80)
DEVICE_LOOKUP = {v: k for k, v in DEVICE_MAP.items()}

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
    "UFH": "Underfloor Heating",
    "BDR": "Electric Heat/Zone Valve",
    "???": "Mixing Valve",
}

a = "(-{3}|\d{3})"  # #          noqa: W605; pylint: disable=invalid-name, W1401
b = "( I|RP|RQ| W)"  # #                     pylint: disable=invalid-name
c = "(-{2}:-{6}|\d{2}:\d{6})"  # noqa: W605; pylint: disable=invalid-name, W1401
d = "[0-9A-F]{4}"  # #                       pylint: disable=invalid-name
e = "[0-9]{3}"  # #                          pylint: disable=invalid-name
f = "([0-9A-F]{2})+"  # #                    pylint: disable=invalid-name

COMMAND_REGEX = re.compile(f"^{b} {a} {c} {c} {c} {d} {e} {f}$")
MESSAGE_REGEX = re.compile(f"^{a} {b} {a} {c} {c} {c} {d} {e} {f}$")

COMMAND_FORMAT = "RQ --- {} {} --:------ {} {:03.0f} {}"
MESSAGE_FORMAT = "|| {} | {} | {} | {:<10} | {:<10} | {:<10} | {:<15} | {} | {:<8} ||"

LOGGING_FILE = "message.log"
PACKETS_FILE = "packets.log"

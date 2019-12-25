"""Evohome serial."""

import re

ALL_DEV_ID = "63:262142"  # 7FFFFF - send here if not bound?
CTL_DEV_ID = "01:145038"  # 06368E
HGI_DEV_ID = "18:000730"  # default type and address of HGI, 18:013393
NO_DEV_ID = "--:------"

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

# https://github.com/Evsdd/Evohome_Schedule_Restore/blob/e5c5f8ee52d8117804edcc220e474191bae287ae/Evohome_Schedule_Restore_v0.3.py#L53
# https://www.domoticz.com/forum/viewtopic.php?f=34&t=16742&p=216168#p216168

# use: cat packets.log | grep -v " 18:" | grep -E ' [0-9]{3} [0-9][1-9A-F]' | grep -v ' \-\-\- 01' > test.log
COMMAND_SCHEMA = {
    "0001": {"name": "message_0001"},  #
    "0002": {"name": "sensor_weather"},
    "0004": {"name": "zone_name", "exposes_zone": True, "rq_length": 2},
    "0005": {"name": "system_zone", "rq_length": 2},
    "0006": {"name": "schedule_sync"},
    # for CH/DHW/Boiler (F9/FA/FC), also zone_idx for BDR, F8/FF (for all)
    "0008": {"name": "relay_demand"},
    "0009": {"name": "relay_failsafe", "exposes_zone": None},
    "000A": {"name": "zone_config", "exposes_zone": True},
    "000C": {"name": "zone_devices", "exposes_zone": True},
    "000E": {"name": "message_000E", "exposes_zone": False},
    "0016": {"name": "rf_check", "rq_length": 2},
    "0100": {"name": "localisation", "rq_length": 5},
    "0404": {"name": "zone_schedule"},
    "0418": {"name": "system_fault"},
    "042F": {"name": "message_042F", "exposes_zone": False},
    "1030": {"name": "mixvalve_config"},
    "1060": {"name": "device_battery", "exposes_zone": None},
    "10A0": {"name": "dhw_params"},
    "10E0": {"name": "device_info"},
    "1100": {"name": "boiler_params"},  # boiler CH config
    "1260": {"name": "dhw_temp"},
    # 1260: {"name": "outdoor_humidity"},
    "1290": {"name": "outdoor_temp"},
    "12A0": {"name": "indoor_humidity"},  # Nuaire ventilation
    "12B0": {"name": "window_state", "exposes_zone": True},  # "device_or_zone": True
    "1F09": {"name": "sync_cycle"},
    "1F41": {"name": "dhw_mode"},
    "1FC9": {"name": "bind_device"},  # aka bind
    "1FD4": {"name": "otb_ticker"},
    # 2249: {"name": "unknown"},  # programmer now/next setpoint (jrosser/honeymon)
    "22C9": {"name": "ufh_setpoint"},
    "22D9": {"name": "otherm_setpoint"},  # OTB
    "22F1": {"name": "message_22f1"},
    "2309": {"name": "setpoint", "exposes_zone": True},  # "device_or_zone": True
    "2349": {"name": "zone_mode"},
    "2E04": {"name": "system_mode"},
    "30C9": {"name": "temperature", "exposes_zone": False},  # "device_or_zone": True
    "3120": {"name": "message_3120", "exposes_zone": False},
    "313F": {"name": "datetime"},  # aka ping, datetime_req
    "3150": {"name": "heat_demand", "exposes_zone": True},  # "device_or_zone": ????
    "31DA": {"name": "message_31da"},  # from HCE80, also Nuaire: Contains R/humidity??
    "31D9": {"name": "message_31d9"},  # Nuaire ventilation
    "31E0": {"name": "message_31e0"},  # Nuaire ventilation
    "3220": {"name": "otherm_message"},  # OTB?
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
# sed -e 's/ 01:/ CTL:/g' -e 's/ 02:/ UFH:/g' -e 's/ 04:/ TRV:/g' -e 's/ 07:/ DHW:/g' -i pkts.out
# sed -e 's/ 10:/ OTB:/g' -e 's/ 12:/ THM:/g' -e 's/ 13:/ BDR:/g' -e 's/ 18:/ HGI:/g' -i pkts.out
# sed -e 's/ 22:/ THm:/g' -e 's/ 30:/ GWY:/g' -e 's/ 32:/ VNT:/g' -e 's/ 34:/ STA:/g' -i pkts.out
# sed -e 's/ 63:/ ALL:/g' -e 's/ --:/  --:/g' -i pkts.out

DEVICE_MAP = {
    "01": "CTL",  # Controller
    "02": "UFH",  # Underfloor heating (HCC80, HCE80)
    "03": " 30",  # HCW82??
    "04": "TRV",  # Thermostatic radiator valve (HR80, HR91, HR92)  # 0100, 1060, 12B0, 2309, 30C9, 3150
    "07": "DHW",  # DHW sensor (CS92)
    "10": "OTB",  # OpenTherm bridge (R8810)
    "12": "THM",  # Thermostat with setpoint schedule control (DTS92E)
    "13": "BDR",  # Wireless relay box (BDR91)  # 3EF0=relay/TPI; 3B00=TPI (also: HC60NG?)
    "17": " 17",  # Dunno - Outside weather sensor?
    "18": "HGI",  # Honeywell Gateway Interface (HGI80, HGS80)
    "22": "THm",  # Thermostat with setpoint schedule control (DTS92E)
    "30": "GWY",  # Gateway (e.g. RFG100?)
    "32": "VNT",  # (HCE80) Ventilation (Nuaire VMS-23HB33, VMN-23LMH23)
    "34": "STA",  # Thermostat (T87RF)  # 1060, 10E0, 30C9
    "63": "ALL",  # is sent: 10E0, 1FC9
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
    "BDR": "Electric Heat",  # /Zone Valve",
    "UFH": "Underfloor Heating",
    "MIX": "Mixing Valve",
    "ZON": "Zone Valve",
}

a = "(-{3}|\d{3})"  # #          noqa: W605; pylint: disable=invalid-name, W1401
b = "( I|RP|RQ| W)"  # #                     pylint: disable=invalid-name
c = "(-{2}:-{6}|\d{2}:\d{6})"  # noqa: W605; pylint: disable=invalid-name, W1401
d = "[0-9A-F]{4}"  # #                       pylint: disable=invalid-name
e = "\d{3}"  # #                          pylint: disable=invalid-name
f = "([0-9A-F]{2})+"  # #                    pylint: disable=invalid-name

COMMAND_REGEX = re.compile(f"^{b} {a} {c} {c} {c} {d} {e} {f}$")
MESSAGE_REGEX = re.compile(f"^{a} {b} {a} {c} {c} {c} {d} {e} {f}$")

COMMAND_FORMAT = "{:<2} --- {} {} --:------ {} {:03.0f} {}"
MESSAGE_FORMAT = "|| {} | {} | {} | {:<10} | {:<10} | {:<10} | {:<16} | {} | {:<8} ||"

LOGGING_FILE = "message.log"
PACKETS_FILE = "packets.log"

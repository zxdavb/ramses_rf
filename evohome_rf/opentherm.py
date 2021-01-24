#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome RF - Opentherm processor."""

import logging
import struct
from typing import Any

from .const import _dev_mode_

DEV_MODE = _dev_mode_

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)

# Data structure shamelessy copied, with thanks to @nlrb, from:
# github.com/nlrb/com.tclcode.otgw (ot_msg.js),

# Other code shamelessy copied, with thanks to @mvn23, from:
# github.com/mvn23/pyotgw (protocol.py),

OPENTHERM_MSG_TYPE = {
    0: "Read-Data",
    16: "Write-Data",
    32: "Invalid-Data",
    48: "-reserved-",
    64: "Read-Ack",
    80: "Write-Ack",
    96: "Data-Invalid",
    112: "Unknown-DataId",
}

OPENTHERM_MESSAGES = {
    # OpenTherm status flags [ID 0: Master status (HB) & Slave status (LB)]
    "status_flags": {
        "0x0100": {
            "en": "Central heating enable",
            "nl": "Centrale verwarming aan",
            "var": "StatusCHEnabled",
        },
        "0x0200": {"en": "DHW enable", "nl": "Tapwater aan", "var": "StatusDHWEnabled"},
        "0x0400": {
            "en": "Cooling enable",
            "nl": "Koeling aan",
            "var": "StatusCoolEnabled",
        },
        "0x0800": {
            "en": "Outside temp. comp. active",
            "nl": "Compenseren buitentemp.",
            "var": "StatusOTCActive",
        },
        "0x1000": {
            "en": "Central heating 2 enable",
            "nl": "Centrale verwarming 2 aan",
            "var": "StatusCH2Enabled",
        },
        "0x2000": {
            "en": "Summer/winter mode",
            "nl": "Zomer/winter mode",
            "var": "StatusSummerWinter",
        },
        "0x4000": {
            "en": "DHW blocking",
            "nl": "Tapwater blokkade",
            "var": "StatusDHWBlocked",
        },
        "0x0001": {
            "en": "Fault indication",
            "nl": "Fout indicatie",
            "var": "StatusFault",
        },  # no fault/fault
        "0x0002": {
            "en": "Central heating mode",
            "nl": "Centrale verwarming mode",
            "var": "StatusCHMode",
        },  # not active/active
        "0x0004": {
            "en": "DHW mode",
            "nl": "Tapwater mode",
            "var": "StatusDHWMode",
        },  # not active/active
        "0x0008": {
            "en": "Flame status",
            "nl": "Vlam status",
            "var": "StatusFlame",
        },  # flame off/on
        "0x0010": {
            "en": "Cooling status",
            "nl": "Status koelen",
            "var": "StatusCooling",
        },  # not active/active
        "0x0020": {
            "en": "Central heating 2 mode",
            "nl": "Centrale verwarming 2 mode",
            "var": "StatusCH2Mode",
        },  # not active/active
        "0x0040": {
            "en": "Diagnostic indication",
            "nl": "Diagnose indicatie",
            "var": "StatusDiagnostic",
        },  # no diagnostics/diagnostics event
    },
    # OpenTherm Master configuration flags [ID 2: master config flags (HB)]
    "Master_config_flags": {"0x0100": {"en": "Smart Power", "var": "ConfigSmartPower"}},
    # OpenTherm Slave configuration flags [ID 3: slave config flags (HB)]
    "Slave_Config_flags": {
        "0x0100": {"en": "DHW present", "var": "ConfigDHWpresent"},
        "0x0200": {
            "en": "Control type (modulating on/off)",
            "var": "ConfigControlType",
        },
        "0x0400": {"en": "Cooling supported", "var": "ConfigCooling"},
        "0x0800": {"en": "DHW storage tank", "var": "ConfigDHW"},
        "0x1000": {
            "en": "Master low-off & pump control allowed",
            "var": "ConfigMasterPump",
        },
        "0x2000": {"en": "Central heating 2 present", "var": "ConfigCH2"},
    },
    # OpenTherm fault flags [ID 5: Application-specific fault flags (HB)]
    "fault_flags": {
        "0x0100": {
            "en": "Service request",
            "nl": "Onderhoudsvraag",
            "var": "FaultServiceRequest",
        },
        "0x0200": {
            "en": "Lockout-reset",
            "nl": "Geen reset op afstand",
            "var": "FaultLockoutReset",
        },
        "0x0400": {
            "en": "Low water pressure",
            "nl": "Waterdruk te laag",
            "var": "FaultLowWaterPressure",
        },
        "0x0800": {
            "en": "Gas/flame fault",
            "nl": "Gas/vlam fout",
            "var": "FaultGasFlame",
        },
        "0x1000": {
            "en": "Air pressure fault",
            "nl": "Luchtdruk fout",
            "var": "FaultAirPressure",
        },
        "0x2000": {
            "en": "Water over-temperature",
            "nl": "Water te heet",
            "var": "FaultOverTemperature",
        },
    },
    # OpenTherm remote flags [ID 6: Remote parameter flags (HB)]
    "Remote_flags": {
        "0x0100": {"en": "DHW setpoint enable", "var": "RemoteDHWEnabled"},
        "0x0200": {"en": "Max. CH setpoint enable", "var": "RemoteMaxCHEnabled"},
        "0x0001": {"en": "DHW setpoint read/write", "var": "RemoteDHWReadWrite"},
        "0x0002": {"en": "Max. CH setpoint read/write", "var": "RemoteMaxCHReadWrite"},
    },
    # OpenTherm messages
    "messages": {
        "0": {"en": "Status", "dir": "R-", "val": "flag8", "flags": "StatusFlags"},
        "1": {
            "en": "Control setpoint",
            "nl": "Ketel doeltemperatuur",
            "dir": "-W",
            "val": "f8.8",
            "var": "ControlSetpoint",
            "sensor": "temperature",
        },
        "2": {
            "en": "Master configuration",
            "dir": "-W",
            "val": {"hb": "flag8", "lb": "u8"},
            "flags": "MasterConfigFlags",
            "var": {"lb": "MasterMemberId"},
        },
        "3": {
            "en": "Slave configuration",
            "dir": "R-",
            "val": {"hb": "flag8", "lb": "u8"},
            "flags": "SlaveConfigFlags",
            "var": {"lb": "SlaveMemberId"},
        },
        "4": {"en": "Remote command", "dir": "-W", "val": "u8", "var": "RemoteCommand"},
        "5": {
            "en": "Fault flags & OEM fault code",
            "dir": "R-",
            "val": {"hb": "flag8", "lb": "u8"},
            "var": {"lb": "OEMFaultCode"},
            "flags": "FaultFlags",
        },
        "6": {
            "en": "Remote parameter flags",
            "dir": "R-",
            "val": "flag8",
            "flags": "RemoteFlags",
        },
        "7": {
            "en": "Cooling control signal",
            "dir": "-W",
            "val": "f8.8",
            "var": "CoolingControlSignal",
            "sensor": "percentage",
        },
        "8": {
            "en": "Control setpoint central heating 2",
            "dir": "-W",
            "val": "f8.8",
            "var": "CH2ControlSetpoint",
            "sensor": "temperature",
        },
        "9": {
            "en": "Remote override room setpoint",
            "nl": "Overschreven kamer doeltemperatuur",
            "dir": "R-",
            "val": "f8.8",
            "var": "RemoteOverrideRoomSetpoint",
            "sensor": "temperature",
        },
        "10": {
            "en": "Number of transparent slave parameters (TSP) supported by slave",
            "dir": "R-",
            "val": "u8",
            "var": {"hb": "TSPNumber"},
        },
        "11": {
            "en": "Index number/value of referred-to transparent slave parameter (TSP)",
            "dir": "RW",
            "val": "u8",
            "var": {"hb": "TSPIndex", "lb": "TSPValue"},
        },
        "12": {
            "en": "Size of fault history buffer (FHB) supported by slave",
            "dir": "R-",
            "val": "u8",
            "var": {"hb": "FHBSize"},
        },
        "13": {
            "en": "Index number/value of referred-to fault history buffer (FHB) entry",
            "dir": "R-",
            "val": "u8",
            "var": {"hb": "FHBIndex", "lb": "FHBValue"},
        },
        "14": {
            "en": "Max. relative modulation level",
            "nl": "Max. relatief modulatie-niveau",
            "dir": "-W",
            "val": "f8.8",
            "var": "MaxRelativeModulationLevel",
            "sensor": "percentage",
        },
        "15": {
            "en": "Max. boiler capacity (kW) and modulation level setting (%)",
            "dir": "R-",
            "val": "u8",
            "var": {"hb": "MaxBoilerCapacity", "lb": "MinModulationLevel"},
        },
        "16": {
            "en": "Room setpoint",
            "nl": "Kamer doeltemperatuur",
            "dir": "-W",
            "val": "f8.8",
            "var": "CurrentSetpoint",
            "sensor": "temperature",
        },
        "17": {
            "en": "Relative modulation level",
            "nl": "Relatief modulatie-niveau",
            "dir": "R-",
            "val": "f8.8",
            "var": "RelativeModulationLevel",
            "sensor": "percentage",
        },
        "18": {
            "en": "Central heating water pressure",
            "nl": "Keteldruk",
            "dir": "R-",
            "val": "f8.8",
            "var": "CHWaterPressure",
            "sensor": "pressure",
        },
        "19": {
            "en": "DHW flow rate (litres/minute)",
            "dir": "R-",
            "val": "f8.8",
            "var": "DHWFlowRate",
            "sensor": "flow",
        },
        "20": {"en": "Day of week & time of day", "dir": "RW", "var": "DayTime"},
        "21": {"en": "Date", "dir": "RW", "val": "u8", "var": "Date"},
        "22": {"en": "Year", "dir": "RW", "val": "u16", "var": "Year"},
        "23": {
            "en": "Room setpoint central heating 2",
            "dir": "-W",
            "val": "f8.8",
            "var": "CH2CurrentSetpoint",
            "sensor": "temperature",
        },
        "24": {
            "en": "Room temperature",
            "nl": "Kamertemperatuur",
            "dir": "-W",
            "val": "f8.8",
            "var": "CurrentTemperature",
            "sensor": "temperature",
        },
        "25": {
            "en": "Boiler water temperature",
            "nl": "Ketelwatertemperatuur",
            "dir": "R-",
            "val": "f8.8",
            "var": "BoilerWaterTemperature",
            "sensor": "temperature",
        },
        "26": {
            "en": "DHW temperature",
            "nl": "Tapwatertemperatuur",
            "dir": "R-",
            "val": "f8.8",
            "var": "DHWTemperature",
            "sensor": "temperature",
        },
        "27": {
            "en": "Outside temperature",
            "nl": "Buitentemperatuur",
            "dir": "R-",
            "val": "f8.8",
            "var": "OutsideTemperature",
            "sensor": "temperature",
        },
        "28": {
            "en": "Return water temperature",
            "nl": "Retourtemperatuur",
            "dir": "R-",
            "val": "f8.8",
            "var": "ReturnWaterTemperature",
            "sensor": "temperature",
        },
        "29": {
            "en": "Solar storage temperature",
            "dir": "R-",
            "val": "f8.8",
            "var": "SolarStorageTemperature",
            "sensor": "temperature",
        },
        "30": {
            "en": "Solar collector temperature",
            "dir": "R-",
            "val": "f8.8",
            "var": "SolarCollectorTemperature",
            "sensor": "temperature",
        },
        "31": {
            "en": "Flow temperature central heating 2",
            "dir": "R-",
            "val": "f8.8",
            "var": "CH2FlowTemperature",
            "sensor": "temperature",
        },
        "32": {
            "en": "DHW 2 temperature",
            "dir": "R-",
            "val": "f8.8",
            "var": "DHW2Temperature",
            "sensor": "temperature",
        },
        "33": {
            "en": "Boiler exhaust temperature",
            "dir": "R-",
            "val": "s16",
            "var": "BoilerExhaustTemperature",
            "sensor": "temperature",
        },
        "48": {
            "en": "DHW setpoint boundaries",
            "dir": "R-",
            "val": "s8",
            "var": "DHWBounadries",
            "sensor": "temperature",
        },
        "49": {
            "en": "Max. central heating setpoint boundaries",
            "dir": "R-",
            "val": "s8",
            "var": "CHBoundaries",
            "sensor": "temperature",
        },
        "50": {
            "en": "OTC heat curve ratio upper & lower bounds",
            "dir": "R-",
            "val": "s8",
            "var": "OTCBoundaries",
        },
        "56": {
            "en": "DHW setpoint",
            "nl": "Tapwater doeltemperatuur",
            "dir": "RW",
            "val": "f8.8",
            "var": "DHWSetpoint",
            "sensor": "temperature",
        },
        "57": {
            "en": "Max. central heating water setpoint",
            "nl": "Max. ketel doeltemperatuur",
            "dir": "RW",
            "val": "f8.8",
            "var": "MaxCHWaterSetpoint",
            "sensor": "temperature",
        },
        "58": {
            "en": "OTC heat curve ratio",
            "dir": "RW",
            "val": "f8.8",
            "var": "OTCHeatCurveRatio",
            "sensor": "temperature",
        },
        # OpenTherm 2.3 IDs (70-91) for ventilation/heat-recovery applications
        "70": {
            "en": "Status ventilation/heat-recovery",
            "dir": "R-",
            "val": "flag8",
            "var": "VHStatus",
        },
        "71": {
            "en": "Control setpoint ventilation/heat-recovery",
            "dir": "-W",
            "val": "u8",
            "var": {"hb": "VHControlSetpoint"},
        },
        "72": {
            "en": "Fault flags/code ventilation/heat-recovery",
            "dir": "R-",
            "val": {"hb": "flag", "lb": "u8"},
            "var": {"lb": "VHFaultCode"},
        },
        "73": {
            "en": "Diagnostic code ventilation/heat-recovery",
            "dir": "R-",
            "val": "u16",
            "var": "VHDiagnosticCode",
        },
        "74": {
            "en": "Config/memberID ventilation/heat-recovery",
            "dir": "R-",
            "val": {"hb": "flag", "lb": "u8"},
            "var": {"lb": "VHMemberId"},
        },
        "75": {
            "en": "OpenTherm version ventilation/heat-recovery",
            "dir": "R-",
            "val": "f8.8",
            "var": "VHOpenThermVersion",
        },
        "76": {
            "en": "Version & type ventilation/heat-recovery",
            "dir": "R-",
            "val": "u8",
            "var": {"hb": "VHProductType", "lb": "VHProductVersion"},
        },
        "77": {
            "en": "Relative ventilation",
            "dir": "R-",
            "val": "u8",
            "var": {"hb": "RelativeVentilation"},
        },
        "78": {
            "en": "Relative humidity",
            "nl": "Luchtvochtigheid",
            "dir": "RW",
            "val": "u8",
            "var": {"hb": "RelativeHumidity"},
            "sensor": "humidity",
        },
        "79": {
            "en": "CO2 level",
            "nl": "CO2 niveau",
            "dir": "RW",
            "val": "u16",
            "var": "CO2Level",
            "sensor": "co2",
        },
        "80": {
            "en": "Supply inlet temperature",
            "dir": "R-",
            "val": "f8.8",
            "var": "SupplyInletTemperature",
            "sensor": "temperature",
        },
        "81": {
            "en": "Supply outlet temperature",
            "dir": "R-",
            "val": "f8.8",
            "var": "SupplyOutletTemperature",
            "sensor": "temperature",
        },
        "82": {
            "en": "Exhaust inlet temperature",
            "dir": "R-",
            "val": "f8.8",
            "var": "ExhaustInletTemperature",
            "sensor": "temperature",
        },
        "83": {
            "en": "Exhaust outlet temperature",
            "dir": "R-",
            "val": "f8.8",
            "var": "ExhaustOutletTemperature",
            "sensor": "temperature",
        },
        "84": {
            "en": "Actual exhaust fan speed",
            "dir": "R-",
            "val": "u16",
            "var": "ExhaustFanSpeed",
        },
        "85": {
            "en": "Actual inlet fan speed",
            "dir": "R-",
            "val": "u16",
            "var": "InletFanSpeed",
        },
        "86": {
            "en": "Remote parameter settings ventilation/heat-recovery",
            "dir": "R-",
            "val": "flag8",
            "var": "VHRemoteParameter",
        },
        "87": {
            "en": "Nominal ventilation value",
            "dir": "RW",
            "val": "u8",
            "var": "NominalVentilation",
        },
        "88": {
            "en": "TSP number ventilation/heat-recovery",
            "dir": "R-",
            "val": "u8",
            "var": {"hb": "VHTSPSize"},
        },
        "89": {
            "en": "TSP entry ventilation/heat-recovery",
            "dir": "RW",
            "val": "u8",
            "var": {"hb": "VHTSPIndex", "lb": "VHTSPValue"},
        },
        "90": {
            "en": "Fault buffer size ventilation/heat-recovery",
            "dir": "R-",
            "val": "u8",
            "var": {"hb": "VHFHBSize"},
        },
        "91": {
            "en": "Fault buffer entry ventilation/heat-recovery",
            "dir": "R-",
            "val": "u8",
            "var": {"hb": "VHFHBIndex", "lb": "VHFHBValue"},
        },
        # OpenTherm 2.2 IDs
        "100": {
            "en": "Remote override function",
            "dir": "R-",
            "val": {"hb": "flag8", "lb": "u8"},
            "var": {"hb": "RemoteOverrideFunction"},
        },
        "115": {
            "en": "OEM diagnostic code",
            "dir": "R-",
            "val": "u16",
            "var": "OEMDiagnosticCode",
        },
        "116": {
            "en": "Number of starts burner",
            "dir": "RW",
            "val": "u16",
            "var": "StartsBurner",
            "sensor": "counter",
        },
        "117": {
            "en": "Number of starts central heating pump",
            "dir": "RW",
            "val": "u16",
            "var": "StartsCHPump",
            "sensor": "counter",
        },
        "118": {
            "en": "Number of starts DHW pump/valve",
            "dir": "RW",
            "val": "u16",
            "var": "StartsHDWPump",
            "sensor": "counter",
        },
        "119": {
            "en": "Number of starts burner during DHW mode",
            "dir": "RW",
            "val": "u16",
            "var": "StartsBurnerDHW",
            "sensor": "counter",
        },
        "120": {
            "en": "Number of hours burner is in operation (i.e. flame on)",
            "dir": "RW",
            "val": "u16",
            "var": "HoursBurner",
            "sensor": "counter",
        },
        "121": {
            "en": "Number of hours central heating pump has been running",
            "dir": "RW",
            "val": "u16",
            "var": "HoursCHPump",
            "sensor": "counter",
        },
        "122": {
            "en": "Number of hours DHW pump has been running/valve has been opened",
            "dir": "RW",
            "val": "u16",
            "var": "HoursDHWPump",
            "sensor": "counter",
        },
        "123": {
            "en": "Number of hours DHW burner is in operation during DHW mode",
            "dir": "RW",
            "val": "u16",
            "var": "HoursDHWBurner",
            "sensor": "counter",
        },
        "124": {
            "en": "Opentherm version Master",
            "dir": "-W",
            "val": "f8.8",
            "var": "MasterOpenThermVersion",
        },
        "125": {
            "en": "Opentherm version Slave",
            "dir": "R-",
            "val": "f8.8",
            "var": "SlaveOpenThermVersion",
        },
        "126": {
            "en": "Master product version and type",
            "dir": "-W",
            "val": "u8",
            "var": {"hb": "MasterProductType", "lb": "MasterProductVersion"},
        },
        "127": {
            "en": "Slave product version and type",
            "dir": "R-",
            "val": "u8",
            "var": {"hb": "SlaveProductType", "lb": "SlaveProductVersion"},
        },
        # ZX-DAVB extras
        "113": {
            "en": "Number of un-successful burner starts",
            "dir": "RW",
            "val": "u16",
            "var": "BadStartsBurner?",
            "sensor": "counter",
        },
        "114": {
            "en": "Number of times flame signal was too low",
            "dir": "RW",
            "val": "u16",
            "var": "LowSignalsFlame?",
            "sensor": "counter",
        },
    },
}


def parity(x: int) -> int:
    """Make this the docstring."""
    shiftamount = 1
    while x >> shiftamount:
        x ^= x >> shiftamount
        shiftamount <<= 1
    return x & 1


def ot_msg_value(val_seqx, val_type) -> Any:
    """Make this the docstring."""

    def _get_flag8(byte, *args) -> list:
        """Split a byte (as a str) into a list of 8 bits (1/0)."""
        ret = [0] * 8
        byte = bytes.fromhex(byte)[0]
        for i in range(0, 8):
            ret[i] = byte & 1
            byte = byte >> 1
        return ret

    def _get_u8(byte, *args) -> int:
        """Convert a byte (as a str) into an unsigned int."""
        return struct.unpack(">B", bytes.fromhex(byte))[0]

    def _get_s8(byte, *args) -> int:
        """Convert a byte (as a str) into a signed int."""
        return struct.unpack(">b", bytes.fromhex(byte))[0]

    def _get_f8_8(msb, lsb) -> float:
        """Convert 2 bytes (as strs) into an OpenTherm f8_8 (float) value."""
        return float(_get_s16(msb, lsb) / 256)

    def _get_u16(msb, lsb) -> int:
        """Convert 2 bytes (as strs) into an unsigned int."""
        buf = struct.pack(">BB", _get_u8(msb), _get_u8(lsb))
        return int(struct.unpack(">H", buf)[0])

    def _get_s16(msb, lsb) -> int:
        """Convert 2 bytes (as strs) into a signed int."""
        buf = struct.pack(">bB", _get_s8(msb), _get_u8(lsb))
        return int(struct.unpack(">h", buf)[0])

    DATA_TYPES = {
        "flag8": _get_flag8,
        "u8": _get_u8,
        "s8": _get_s8,
        "f8.8": _get_f8_8,
        "u16": _get_u16,
        "s16": _get_s16,
    }

    if val_type in DATA_TYPES:
        return DATA_TYPES[val_type](val_seqx[:2], val_seqx[2:])
    return val_seqx


# See: https://www.opentherm.eu/request-details/?post_ids=2944
#
# ID0:HB0: Master status: CH enable
# ID0:HB1: Master status: DHW enable
# ID0:HB2: Master status: Cooling enable
# ID0:HB3: Master status: OTC active
# ID0:HB5: Master status: Summer/winter mode
# ID0:HB6: Master status: DHW blocking

# ID0:LB0: Slave Status: Fault indication
# ID0:LB1: Slave Status: CH mode
# ID0:LB2: Slave Status: DHW mode
# ID0:LB3: Slave Status: Flame status

# ID1: Control Setpoint i.e. CH water temperature Setpoint (°C)

# ID2:HB0: Master configuration: Smart power
# ID2:LB: Master MemberID Code

# ID3:HB0: Slave configuration: DHW present
# ID3:HB1: Slave configuration: Control type
# ID3:HB4: Slave configuration: Master low-off&pump control

# ID5:HB0: Service request
# ID5:HB1: Lockout-reset
# ID5:HB2: Low water pressure
# ID5:HB3: Gas/flame fault
# ID5:HB4: Air pressure fault
# ID5:HB5: Water over-temperature
# ID5:LB: OEM fault code

# ID6:HB0: Remote boiler parameter transfer-enable: DHW setpoint
# ID6:HB1: Remote boiler parameter transfer-enable: max. CH setpoint
# ID6:LB0: Remote boiler parameter read/write: DHW setpoint
# ID6:LB1: Remote boiler parameter read/write: max. CH setpoint

# ID9: Remote override room Setpoint
# ID10: Number of Transparent-Slave-Parameters supported by slave
# ID12: Size of Fault-History-Buffer supported by slave
# ID14: Maximum relative modulation level setting (%)
# ID16: Room Setpoint (°C)
# ID17: Relative Modulation Level (%)
# ID18: Water pressure in CH circuit (bar)
# ID19: Water flow rate in DHW circuit. (litres/minute)
# ID24: Room temperature (°C)
# ID25: Boiler flow water temperature (°C)
# ID26: DHW temperature (°C)
# ID27: Outside temperature (°C)
# ID28: Return water temperature (°C)
# ID48: DHW Setpoint upper & lower bounds for adjustment (°C)
# ID49: Max CH water Setpoint upper & lower bounds for adjustment (°C)
# ID56: DHW Setpoint (°C) (Remote parameter 1)
# ID57: Max CH water Setpoint (°C) (Remote parameters 2)

# ID126: Master product version number and type
# ID127: Slave product version number and type

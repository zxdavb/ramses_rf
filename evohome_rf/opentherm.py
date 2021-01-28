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

READ_WRITE = "RW"
READ_ONLY = "R-"
WRITE_ONLY = "-W"

EN = "en"
FLAGS = "flags"
DIR = "dir"
NL = "nl"
SENSOR = "sensor"
VAL = "val"
VAR = "var"

FLAG8 = "flag8"
FLAG = "flag"
U8 = "u8"
S8 = "s8"
F8_8 = "f8.8"
U16 = "u16"
S16 = "s16"

HB = "hb"
LB = "lb"

COUNTER = "counter"
HUMIDITY = "humidity"
PERCENTAGE = "percentage"
PRESSURE = "pressure"
TEMPERATURE = "temperature"

OPENTHERM_MSG_TYPE = {
    0b000: "Read-Data",
    0b001: "Write-Data",
    0b010: "Invalid-Data",
    0b011: "-reserved-",
    0b100: "Read-Ack",
    0b101: "Write-Ack",
    0b110: "Data-Invalid",
    0b111: "Unknown-DataId",
}

# These must have either a FLAGS (preferred) or a VAR for their message name
OPENTHERM_MESSAGES = {
    # OpenTherm status flags [ID 0: Master status (HB) & Slave status (LB)]
    "status_flags": {
        "0x0100": {
            EN: "Central heating enable",
            NL: "Centrale verwarming aan",
            VAR: "StatusCHEnabled",
        },
        "0x0200": {
            EN: "DHW enable",
            NL: "Tapwater aan",
            VAR: "StatusDHWEnabled",
        },
        "0x0400": {
            EN: "Cooling enable",
            NL: "Koeling aan",
            VAR: "StatusCoolEnabled",
        },
        "0x0800": {
            EN: "Outside temp. comp. active",
            NL: "Compenseren buitentemp.",
            VAR: "StatusOTCActive",
        },
        "0x1000": {
            EN: "Central heating 2 enable",
            NL: "Centrale verwarming 2 aan",
            VAR: "StatusCH2Enabled",
        },
        "0x2000": {
            EN: "Summer/winter mode",
            NL: "Zomer/winter mode",
            VAR: "StatusSummerWinter",
        },
        "0x4000": {
            EN: "DHW blocking",
            NL: "Tapwater blokkade",
            VAR: "StatusDHWBlocked",
        },
        "0x0001": {
            EN: "Fault indication",
            NL: "Fout indicatie",
            VAR: "StatusFault",
        },  # no fault/fault
        "0x0002": {
            EN: "Central heating mode",
            NL: "Centrale verwarming mode",
            VAR: "StatusCHMode",
        },  # not active/active
        "0x0004": {
            EN: "DHW mode",
            NL: "Tapwater mode",
            VAR: "StatusDHWMode",
        },  # not active/active
        "0x0008": {
            EN: "Flame status",
            NL: "Vlam status",
            VAR: "StatusFlame",
        },  # flame off/on
        "0x0010": {
            EN: "Cooling status",
            NL: "Status koelen",
            VAR: "StatusCooling",
        },  # not active/active
        "0x0020": {
            EN: "Central heating 2 mode",
            NL: "Centrale verwarming 2 mode",
            VAR: "StatusCH2Mode",
        },  # not active/active
        "0x0040": {
            EN: "Diagnostic indication",
            NL: "Diagnose indicatie",
            VAR: "StatusDiagnostic",
        },  # no diagnostics/diagnostics event
    },
    # OpenTherm Master configuration flags [ID 2: master config flags (HB)]
    "Master_config_flags": {
        "0x0100": {
            EN: "Smart Power",
            VAR: "ConfigSmartPower",
        },
    },
    # OpenTherm Slave configuration flags [ID 3: slave config flags (HB)]
    "Slave_Config_flags": {
        "0x0100": {
            EN: "DHW present",
            VAR: "ConfigDHWpresent",
        },
        "0x0200": {
            EN: "Control type (modulating on/off)",
            VAR: "ConfigControlType",
        },
        "0x0400": {
            EN: "Cooling supported",
            VAR: "ConfigCooling",
        },
        "0x0800": {
            EN: "DHW storage tank",
            VAR: "ConfigDHW",
        },
        "0x1000": {
            EN: "Master low-off & pump control allowed",
            VAR: "ConfigMasterPump",
        },
        "0x2000": {
            EN: "Central heating 2 present",
            VAR: "ConfigCH2",
        },
    },
    # OpenTherm fault flags [ID 5: Application-specific fault flags (HB)]
    "fault_flags": {
        "0x0100": {
            EN: "Service request",
            NL: "Onderhoudsvraag",
            VAR: "FaultServiceRequest",
        },
        "0x0200": {
            EN: "Lockout-reset",
            NL: "Geen reset op afstand",
            VAR: "FaultLockoutReset",
        },
        "0x0400": {
            EN: "Low water pressure",
            NL: "Waterdruk te laag",
            VAR: "FaultLowWaterPressure",
        },
        "0x0800": {
            EN: "Gas/flame fault",
            NL: "Gas/vlam fout",
            VAR: "FaultGasFlame",
        },
        "0x1000": {
            EN: "Air pressure fault",
            NL: "Luchtdruk fout",
            VAR: "FaultAirPressure",
        },
        "0x2000": {
            EN: "Water over-temperature",
            NL: "Water te heet",
            VAR: "FaultOverTemperature",
        },
    },
    # OpenTherm remote flags [ID 6: Remote parameter flags (HB)]
    "Remote_flags": {
        "0x0100": {
            EN: "DHW setpoint enable",
            VAR: "RemoteDHWEnabled",
        },
        "0x0200": {
            EN: "Max. CH setpoint enable",
            VAR: "RemoteMaxCHEnabled",
        },
        "0x0001": {
            EN: "DHW setpoint read/write",
            VAR: "RemoteDHWReadWrite",
        },
        "0x0002": {
            EN: "Max. CH setpoint read/write",
            VAR: "RemoteMaxCHReadWrite",
        },
    },
    # OpenTherm messages
    "messages": {
        0: {
            EN: "Status",
            DIR: READ_ONLY,
            VAL: FLAG8,
            FLAGS: "StatusFlags",
        },
        1: {
            EN: "Control setpoint",
            NL: "Ketel doeltemperatuur",
            DIR: WRITE_ONLY,
            VAL: F8_8,
            VAR: "ControlSetpoint",
            SENSOR: TEMPERATURE,
        },
        2: {
            EN: "Master configuration",
            DIR: WRITE_ONLY,
            VAL: {HB: FLAG8, LB: U8},
            FLAGS: "MasterConfigFlags",
            VAR: {LB: "MasterMemberId"},
        },
        3: {
            EN: "Slave configuration",
            DIR: READ_ONLY,
            VAL: {HB: FLAG8, LB: U8},
            FLAGS: "SlaveConfigFlags",
            VAR: {LB: "SlaveMemberId"},
        },
        4: {
            EN: "Remote command",
            DIR: WRITE_ONLY,
            VAL: U8,
            VAR: "RemoteCommand",
        },
        5: {
            EN: "Fault flags & OEM fault code",
            DIR: READ_ONLY,
            VAL: {HB: FLAG8, LB: U8},
            VAR: {LB: "OEMFaultCode"},
            FLAGS: "FaultFlags",
        },
        6: {
            EN: "Remote parameter flags",
            DIR: READ_ONLY,
            VAL: FLAG8,
            FLAGS: "RemoteFlags",
        },
        7: {
            EN: "Cooling control signal",
            DIR: WRITE_ONLY,
            VAL: F8_8,
            VAR: "CoolingControlSignal",
            SENSOR: PERCENTAGE,
        },
        8: {
            EN: "Control setpoint central heating 2",
            DIR: WRITE_ONLY,
            VAL: F8_8,
            VAR: "CH2ControlSetpoint",
            SENSOR: TEMPERATURE,
        },
        9: {
            EN: "Remote override room setpoint",
            NL: "Overschreven kamer doeltemperatuur",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "RemoteOverrideRoomSetpoint",
            SENSOR: TEMPERATURE,
        },
        10: {
            EN: "Number of transparent slave parameters (TSP) supported by slave",
            DIR: READ_ONLY,
            VAL: U8,
            VAR: {HB: "TSPNumber"},
        },
        11: {
            EN: "Index number/value of referred-to transparent slave parameter (TSP)",
            DIR: READ_WRITE,
            VAL: U8,
            VAR: {HB: "TSPIndex", LB: "TSPValue"},
        },
        12: {
            EN: "Size of fault history buffer (FHB) supported by slave",
            DIR: READ_ONLY,
            VAL: U8,
            VAR: {HB: "FHBSize"},
        },
        13: {
            EN: "Index number/value of referred-to fault history buffer (FHB) entry",
            DIR: READ_ONLY,
            VAL: U8,
            VAR: {HB: "FHBIndex", LB: "FHBValue"},
        },
        14: {
            EN: "Max. relative modulation level",
            NL: "Max. relatief modulatie-niveau",
            DIR: WRITE_ONLY,
            VAL: F8_8,
            VAR: "MaxRelativeModulationLevel",
            SENSOR: PERCENTAGE,
        },
        15: {
            EN: "Max. boiler capacity (kW) and modulation level setting (%)",
            DIR: READ_ONLY,
            VAL: U8,
            VAR: {HB: "MaxBoilerCapacity", LB: "MinModulationLevel"},
        },
        16: {
            EN: "Room setpoint",
            NL: "Kamer doeltemperatuur",
            DIR: WRITE_ONLY,
            VAL: F8_8,
            VAR: "CurrentSetpoint",
            SENSOR: TEMPERATURE,
        },
        17: {
            EN: "Relative modulation level",
            NL: "Relatief modulatie-niveau",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "RelativeModulationLevel",
            SENSOR: PERCENTAGE,
        },
        18: {
            EN: "Central heating water pressure",
            NL: "Keteldruk",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "CHWaterPressure",
            SENSOR: PRESSURE,
        },
        19: {
            EN: "DHW flow rate (litres/minute)",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "DHWFlowRate",
            SENSOR: "flow",
        },
        20: {
            EN: "Day of week & time of day",
            DIR: READ_WRITE,
            VAR: "DayTime",
        },
        21: {
            EN: "Date",
            DIR: READ_WRITE,
            VAL: U8,
            VAR: "Date",
        },
        22: {
            EN: "Year",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "Year",
        },
        23: {
            EN: "Room setpoint central heating 2",
            DIR: WRITE_ONLY,
            VAL: F8_8,
            VAR: "CH2CurrentSetpoint",
            SENSOR: TEMPERATURE,
        },
        24: {
            EN: "Room temperature",
            NL: "Kamertemperatuur",
            DIR: WRITE_ONLY,
            VAL: F8_8,
            VAR: "CurrentTemperature",
            SENSOR: TEMPERATURE,
        },
        25: {
            EN: "Boiler water temperature",
            NL: "Ketelwatertemperatuur",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "BoilerWaterTemperature",
            SENSOR: TEMPERATURE,
        },
        26: {
            EN: "DHW temperature",
            NL: "Tapwatertemperatuur",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "DHWTemperature",
            SENSOR: TEMPERATURE,
        },
        27: {
            EN: "Outside temperature",
            NL: "Buitentemperatuur",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "OutsideTemperature",
            SENSOR: TEMPERATURE,
        },
        28: {
            EN: "Return water temperature",
            NL: "Retourtemperatuur",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "ReturnWaterTemperature",
            SENSOR: TEMPERATURE,
        },
        29: {
            EN: "Solar storage temperature",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "SolarStorageTemperature",
            SENSOR: TEMPERATURE,
        },
        30: {
            EN: "Solar collector temperature",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "SolarCollectorTemperature",
            SENSOR: TEMPERATURE,
        },
        31: {
            EN: "Flow temperature central heating 2",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "CH2FlowTemperature",
            SENSOR: TEMPERATURE,
        },
        32: {
            EN: "DHW 2 temperature",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "DHW2Temperature",
            SENSOR: TEMPERATURE,
        },
        33: {
            EN: "Boiler exhaust temperature",
            DIR: READ_ONLY,
            VAL: S16,
            VAR: "BoilerExhaustTemperature",
            SENSOR: TEMPERATURE,
        },
        48: {
            EN: "DHW setpoint boundaries",
            DIR: READ_ONLY,
            VAL: S8,
            VAR: "DHWBounadries",
            SENSOR: TEMPERATURE,
        },
        49: {
            EN: "Max. central heating setpoint boundaries",
            DIR: READ_ONLY,
            VAL: S8,
            VAR: "CHBoundaries",
            SENSOR: TEMPERATURE,
        },
        50: {
            EN: "OTC heat curve ratio upper & lower bounds",
            DIR: READ_ONLY,
            VAL: S8,
            VAR: "OTCBoundaries",
        },
        56: {
            EN: "DHW setpoint",
            NL: "Tapwater doeltemperatuur",
            DIR: READ_WRITE,
            VAL: F8_8,
            VAR: "DHWSetpoint",
            SENSOR: TEMPERATURE,
        },
        57: {
            EN: "Max. central heating water setpoint",
            NL: "Max. ketel doeltemperatuur",
            DIR: READ_WRITE,
            VAL: F8_8,
            VAR: "MaxCHWaterSetpoint",
            SENSOR: TEMPERATURE,
        },
        58: {
            EN: "OTC heat curve ratio",
            DIR: READ_WRITE,
            VAL: F8_8,
            VAR: "OTCHeatCurveRatio",
            SENSOR: TEMPERATURE,
        },
        # OpenTherm 2.3 IDs (70-91) for ventilation/heat-recovery applications
        70: {
            EN: "Status ventilation/heat-recovery",
            DIR: READ_ONLY,
            VAL: FLAG8,
            VAR: "VHStatus",
        },
        71: {
            EN: "Control setpoint ventilation/heat-recovery",
            DIR: WRITE_ONLY,
            VAL: U8,
            VAR: {HB: "VHControlSetpoint"},
        },
        72: {
            EN: "Fault flags/code ventilation/heat-recovery",
            DIR: READ_ONLY,
            VAL: {HB: FLAG, LB: U8},
            VAR: {LB: "VHFaultCode"},
        },
        73: {
            EN: "Diagnostic code ventilation/heat-recovery",
            DIR: READ_ONLY,
            VAL: U16,
            VAR: "VHDiagnosticCode",
        },
        74: {
            EN: "Config/memberID ventilation/heat-recovery",
            DIR: READ_ONLY,
            VAL: {HB: FLAG, LB: U8},
            VAR: {LB: "VHMemberId"},
        },
        75: {
            EN: "OpenTherm version ventilation/heat-recovery",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "VHOpenThermVersion",
        },
        76: {
            EN: "Version & type ventilation/heat-recovery",
            DIR: READ_ONLY,
            VAL: U8,
            VAR: {HB: "VHProductType", LB: "VHProductVersion"},
        },
        77: {
            EN: "Relative ventilation",
            DIR: READ_ONLY,
            VAL: U8,
            VAR: {HB: "RelativeVentilation"},
        },
        78: {
            EN: "Relative humidity",
            NL: "Luchtvochtigheid",
            DIR: READ_WRITE,
            VAL: U8,
            VAR: {HB: "RelativeHumidity"},
            SENSOR: HUMIDITY,
        },
        79: {
            EN: "CO2 level",
            NL: "CO2 niveau",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "CO2Level",
            SENSOR: "co2",
        },
        80: {
            EN: "Supply inlet temperature",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "SupplyInletTemperature",
            SENSOR: TEMPERATURE,
        },
        81: {
            EN: "Supply outlet temperature",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "SupplyOutletTemperature",
            SENSOR: TEMPERATURE,
        },
        82: {
            EN: "Exhaust inlet temperature",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "ExhaustInletTemperature",
            SENSOR: TEMPERATURE,
        },
        83: {
            EN: "Exhaust outlet temperature",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "ExhaustOutletTemperature",
            SENSOR: TEMPERATURE,
        },
        84: {
            EN: "Actual exhaust fan speed",
            DIR: READ_ONLY,
            VAL: U16,
            VAR: "ExhaustFanSpeed",
        },
        85: {
            EN: "Actual inlet fan speed",
            DIR: READ_ONLY,
            VAL: U16,
            VAR: "InletFanSpeed",
        },
        86: {
            EN: "Remote parameter settings ventilation/heat-recovery",
            DIR: READ_ONLY,
            VAL: FLAG8,
            VAR: "VHRemoteParameter",
        },
        87: {
            EN: "Nominal ventilation value",
            DIR: READ_WRITE,
            VAL: U8,
            VAR: "NominalVentilation",
        },
        88: {
            EN: "TSP number ventilation/heat-recovery",
            DIR: READ_ONLY,
            VAL: U8,
            VAR: {HB: "VHTSPSize"},
        },
        89: {
            EN: "TSP entry ventilation/heat-recovery",
            DIR: READ_WRITE,
            VAL: U8,
            VAR: {HB: "VHTSPIndex", LB: "VHTSPValue"},
        },
        90: {
            EN: "Fault buffer size ventilation/heat-recovery",
            DIR: READ_ONLY,
            VAL: U8,
            VAR: {HB: "VHFHBSize"},
        },
        91: {
            EN: "Fault buffer entry ventilation/heat-recovery",
            DIR: READ_ONLY,
            VAL: U8,
            VAR: {HB: "VHFHBIndex", LB: "VHFHBValue"},
        },
        # OpenTherm 2.2 IDs
        100: {
            EN: "Remote override function",
            DIR: READ_ONLY,
            VAL: {HB: FLAG8, LB: U8},
            VAR: {HB: "RemoteOverrideFunction"},
        },
        115: {
            EN: "OEM diagnostic code",
            DIR: READ_ONLY,
            VAL: U16,
            VAR: "OEMDiagnosticCode",
        },
        116: {
            EN: "Number of starts burner",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "StartsBurner",
            SENSOR: COUNTER,
        },
        117: {
            EN: "Number of starts central heating pump",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "StartsCHPump",
            SENSOR: COUNTER,
        },
        118: {
            EN: "Number of starts DHW pump/valve",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "StartsHDWPump",
            SENSOR: COUNTER,
        },
        119: {
            EN: "Number of starts burner during DHW mode",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "StartsBurnerDHW",
            SENSOR: COUNTER,
        },
        120: {
            EN: "Number of hours burner is in operation (i.e. flame on)",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "HoursBurner",
            SENSOR: COUNTER,
        },
        121: {
            EN: "Number of hours central heating pump has been running",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "HoursCHPump",
            SENSOR: COUNTER,
        },
        122: {
            EN: "Number of hours DHW pump has been running/valve has been opened",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "HoursDHWPump",
            SENSOR: COUNTER,
        },
        123: {
            EN: "Number of hours DHW burner is in operation during DHW mode",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "HoursDHWBurner",
            SENSOR: COUNTER,
        },
        124: {
            EN: "Opentherm version Master",
            DIR: WRITE_ONLY,
            VAL: F8_8,
            VAR: "MasterOpenThermVersion",
        },
        125: {
            EN: "Opentherm version Slave",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "SlaveOpenThermVersion",
        },
        126: {
            EN: "Master product version and type",
            DIR: WRITE_ONLY,
            VAL: U8,
            VAR: {HB: "MasterProductType", LB: "MasterProductVersion"},
        },
        127: {
            EN: "Slave product version and type",
            DIR: READ_ONLY,
            VAL: U8,
            VAR: {HB: "SlaveProductType", LB: "SlaveProductVersion"},
        },
        # ZX-DAVB extras
        113: {
            EN: "Number of un-successful burner starts",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "BadStartsBurner?",
            SENSOR: COUNTER,
        },
        114: {
            EN: "Number of times flame signal was too low",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "LowSignalsFlame?",
            SENSOR: COUNTER,
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
        FLAG8: _get_flag8,
        U8: _get_u8,
        S8: _get_s8,
        F8_8: _get_f8_8,
        U16: _get_u16,
        S16: _get_s16,
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

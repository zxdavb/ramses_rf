#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome RF - Opentherm processor."""

import logging
import struct
from typing import Any

from .const import __dev_mode__

DEV_MODE = __dev_mode__

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)

# Data structure shamelessy copied, with thanks to @nlrb, from:
# github.com/nlrb/com.tclcode.otgw (node_modules/otg-api/lib/ot_msg.js),

# Other code shamelessy copied, with thanks to @mvn23, from:
# github.com/mvn23/pyotgw (pyotgw/protocol.py),

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

VALUE = "value"

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
        0x00: {  # 0, Status
            EN: "Status",
            DIR: READ_ONLY,
            VAL: FLAG8,
            FLAGS: "StatusFlags",
        },
        0x01: {  # 1, Control Setpoint
            EN: "Control setpoint",
            NL: "Ketel doeltemperatuur",
            DIR: WRITE_ONLY,
            VAL: F8_8,
            VAR: "ControlSetpoint",
            SENSOR: TEMPERATURE,
        },
        0x02: {  # 2, Master Member ID
            EN: "Master configuration",
            DIR: WRITE_ONLY,
            VAL: {HB: FLAG8, LB: U8},
            FLAGS: "MasterConfigFlags",
            VAR: {LB: "MasterMemberId"},
        },
        0x03: {  # 3, Slave Member ID
            EN: "Slave configuration",
            DIR: READ_ONLY,
            VAL: {HB: FLAG8, LB: U8},
            FLAGS: "SlaveConfigFlags",
            VAR: {LB: "SlaveMemberId"},
        },
        0x04: {  # 4, Remote Command
            EN: "Remote command",
            DIR: WRITE_ONLY,
            VAL: U8,
            VAR: "RemoteCommand",
        },
        0x05: {  # 5, OEM Fault Code
            EN: "Fault flags & OEM fault code",
            DIR: READ_ONLY,
            VAL: {HB: FLAG8, LB: U8},
            VAR: {LB: "OEMFaultCode"},
            FLAGS: "FaultFlags",
        },
        0x06: {  # 6, Remote Flags
            EN: "Remote parameter flags",
            DIR: READ_ONLY,
            VAL: FLAG8,
            FLAGS: "RemoteFlags",
        },
        0x07: {  # 7, Cooling Control Signal
            EN: "Cooling control signal",
            DIR: WRITE_ONLY,
            VAL: F8_8,
            VAR: "CoolingControlSignal",
            SENSOR: PERCENTAGE,
        },
        0x08: {  # 8, CH2 Control Setpoint
            EN: "Control setpoint for 2nd CH circuit",
            DIR: WRITE_ONLY,
            VAL: F8_8,
            VAR: "CH2ControlSetpoint",
            SENSOR: TEMPERATURE,
        },
        0x09: {  # 9, Remote Override Room Setpoint
            EN: "Remote override room setpoint",
            NL: "Overschreven kamer doeltemperatuur",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "RemoteOverrideRoomSetpoint",
            SENSOR: TEMPERATURE,
        },
        0x0A: {  # 10, TSP Number
            EN: "Number of transparent slave parameters supported by slave",
            DIR: READ_ONLY,
            VAL: U8,
            VAR: {HB: "TSPNumber"},
        },
        0x0B: {  # 11, TSP Entry
            EN: "Index number/value of referred-to transparent slave parameter",
            DIR: READ_WRITE,
            VAL: U8,
            VAR: {HB: "TSPIndex", LB: "TSPValue"},
        },
        0x0C: {  # 12, FHB Size
            EN: "Size of fault history buffer supported by slave",
            DIR: READ_ONLY,
            VAL: U8,
            VAR: {HB: "FHBSize"},
        },
        0x0D: {  # 13, FHB Entry
            EN: "Index number/value of referred-to fault history buffer entry",
            DIR: READ_ONLY,
            VAL: U8,
            VAR: {HB: "FHBIndex", LB: "FHBValue"},
        },
        0x0E: {  # 14, Max Relative Modulation Level
            EN: "Max. relative modulation level",
            NL: "Max. relatief modulatie-niveau",
            DIR: WRITE_ONLY,
            VAL: F8_8,
            VAR: "MaxRelativeModulationLevel",
            SENSOR: PERCENTAGE,
        },
        0x0F: {  # 15, Max Boiler Capacity & Min Modulation Level
            EN: "Max. boiler capacity (kW) and modulation level setting (%)",
            DIR: READ_ONLY,
            VAL: U8,
            VAR: {HB: "MaxBoilerCapacity", LB: "MinModulationLevel"},
        },
        0x10: {  # 16, Current Setpoint
            EN: "Room setpoint",
            NL: "Kamer doeltemperatuur",
            DIR: WRITE_ONLY,
            VAL: F8_8,
            VAR: "CurrentSetpoint",
            SENSOR: TEMPERATURE,
        },
        0x11: {  # 17, Relative Modulation Level
            EN: "Relative modulation level",
            NL: "Relatief modulatie-niveau",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "RelativeModulationLevel",
            SENSOR: PERCENTAGE,
        },
        0x12: {  # 18, CH Water Pressure
            EN: "Central heating water pressure",
            NL: "Keteldruk",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "CHWaterPressure",
            SENSOR: PRESSURE,
        },
        0x13: {  # 19, DHW Flow Rate
            EN: "DHW flow rate (litres/minute)",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "DHWFlowRate",
            SENSOR: "flow",
        },
        0x14: {  # 20, Day/Time
            EN: "Day of week & time of day",
            DIR: READ_WRITE,
            VAR: "DayTime",
        },
        0x15: {  # 21, Date
            EN: "Date",
            DIR: READ_WRITE,
            VAL: U8,
            VAR: "Date",
        },
        0x16: {  # 22, Year
            EN: "Year",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "Year",
        },
        0x17: {  # 23, CH2 Current Setpoint
            EN: "Room setpoint for 2nd CH circuit",
            DIR: WRITE_ONLY,
            VAL: F8_8,
            VAR: "CH2CurrentSetpoint",
            SENSOR: TEMPERATURE,
        },
        0x18: {  # 24, Current Room Temperature
            EN: "Room temperature",
            NL: "Kamertemperatuur",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "CurrentTemperature",
            SENSOR: TEMPERATURE,
        },
        0x19: {  # 25, Boiler Water Temperature
            EN: "Boiler water temperature",
            NL: "Ketelwatertemperatuur",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "BoilerWaterTemperature",
            SENSOR: TEMPERATURE,
        },
        0x1A: {  # 26, DHW Temperature
            EN: "DHW temperature",
            NL: "Tapwatertemperatuur",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "DHWTemperature",
            SENSOR: TEMPERATURE,
        },
        0x1B: {  # 27, Outside Temperature
            EN: "Outside temperature",
            NL: "Buitentemperatuur",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "OutsideTemperature",
            SENSOR: TEMPERATURE,
        },
        0x1C: {  # 28, Return Water Temperature
            EN: "Return water temperature",
            NL: "Retourtemperatuur",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "ReturnWaterTemperature",
            SENSOR: TEMPERATURE,
        },
        0x1D: {  # 29, Solar Storage Temperature
            EN: "Solar storage temperature",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "SolarStorageTemperature",
            SENSOR: TEMPERATURE,
        },
        0x1E: {  # 30, Solar Collector Temperature
            EN: "Solar collector temperature",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "SolarCollectorTemperature",
            SENSOR: TEMPERATURE,
        },
        0x1F: {  # 31, CH2 Flow Temperature
            EN: "Flow temperature for 2nd CH circuit",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "CH2FlowTemperature",
            SENSOR: TEMPERATURE,
        },
        0x20: {  # 32, DHW2 Temperature
            EN: "DHW 2 temperature",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "DHW2Temperature",
            SENSOR: TEMPERATURE,
        },
        0x21: {  # 33, Boiler Exhaust Temperature
            EN: "Boiler exhaust temperature",
            DIR: READ_ONLY,
            VAL: S16,
            VAR: "BoilerExhaustTemperature",
            SENSOR: TEMPERATURE,
        },
        0x30: {  # 48, DHW Boundaries
            EN: "DHW setpoint boundaries",
            DIR: READ_ONLY,
            VAL: S8,
            VAR: "DHWBoundaries",
            SENSOR: TEMPERATURE,
        },
        0x31: {  # 49, CH Boundaries
            EN: "Max. central heating setpoint boundaries",
            DIR: READ_ONLY,
            VAL: S8,
            VAR: "CHBoundaries",
            SENSOR: TEMPERATURE,
        },
        0x32: {  # 50, OTC Boundaries
            EN: "OTC heat curve ratio upper & lower bounds",
            DIR: READ_ONLY,
            VAL: S8,
            VAR: "OTCBoundaries",
        },
        0x38: {  # 56, DHW Setpoint
            EN: "DHW setpoint",
            NL: "Tapwater doeltemperatuur",
            DIR: READ_WRITE,
            VAL: F8_8,
            VAR: "DHWSetpoint",
            SENSOR: TEMPERATURE,
        },
        0x39: {  # 57, Max CH Water Setpoint
            EN: "Max. central heating water setpoint",
            NL: "Max. ketel doeltemperatuur",
            DIR: READ_WRITE,
            VAL: F8_8,
            VAR: "MaxCHWaterSetpoint",
            SENSOR: TEMPERATURE,
        },
        0x3A: {  # 58, OTC Heat Curve Ratio
            EN: "OTC heat curve ratio",
            DIR: READ_WRITE,
            VAL: F8_8,
            VAR: "OTCHeatCurveRatio",
            SENSOR: TEMPERATURE,
        },
        # OpenTherm 2.3 IDs (70-91) for ventilation/heat-recovery applications
        0x46: {  # 70, VH Status
            EN: "Status ventilation/heat-recovery",
            DIR: READ_ONLY,
            VAL: FLAG8,
            VAR: "VHStatus",
        },
        0x47: {  # 71, VH Control Setpoint
            EN: "Control setpoint ventilation/heat-recovery",
            DIR: WRITE_ONLY,
            VAL: U8,
            VAR: {HB: "VHControlSetpoint"},
        },
        0x48: {  # 72, VH Fault Code
            EN: "Fault flags/code ventilation/heat-recovery",
            DIR: READ_ONLY,
            VAL: {HB: FLAG, LB: U8},
            VAR: {LB: "VHFaultCode"},
        },
        0x49: {  # 73, VH Diagnostic Code
            EN: "Diagnostic code ventilation/heat-recovery",
            DIR: READ_ONLY,
            VAL: U16,
            VAR: "VHDiagnosticCode",
        },
        0x4A: {  # 74, VH Member ID
            EN: "Config/memberID ventilation/heat-recovery",
            DIR: READ_ONLY,
            VAL: {HB: FLAG, LB: U8},
            VAR: {LB: "VHMemberId"},
        },
        0x4B: {  # 75, VH OpenTherm Version
            EN: "OpenTherm version ventilation/heat-recovery",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "VHOpenThermVersion",
        },
        0x4C: {  # 76, VH Product Type/Version
            EN: "Version & type ventilation/heat-recovery",
            DIR: READ_ONLY,
            VAL: U8,
            VAR: {HB: "VHProductType", LB: "VHProductVersion"},
        },
        0x4D: {  # 77, Relative Ventilation
            EN: "Relative ventilation",
            DIR: READ_ONLY,
            VAL: U8,
            VAR: {HB: "RelativeVentilation"},
        },
        0x4E: {  # 78, Relative Humidity
            EN: "Relative humidity",
            NL: "Luchtvochtigheid",
            DIR: READ_WRITE,
            VAL: U8,
            VAR: {HB: "RelativeHumidity"},
            SENSOR: HUMIDITY,
        },
        0x4F: {  # 79, CO2 Level
            EN: "CO2 level",
            NL: "CO2 niveau",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "CO2Level",
            SENSOR: "co2",
        },
        0x50: {  # 80, Supply Inlet Temperature
            EN: "Supply inlet temperature",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "SupplyInletTemperature",
            SENSOR: TEMPERATURE,
        },
        0x51: {  # 81, Supply Outlet Temperature
            EN: "Supply outlet temperature",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "SupplyOutletTemperature",
            SENSOR: TEMPERATURE,
        },
        0x52: {  # 82, Exhaust Inlet Temperature
            EN: "Exhaust inlet temperature",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "ExhaustInletTemperature",
            SENSOR: TEMPERATURE,
        },
        0x53: {  # 83, Exhaust Outlet Temperature
            EN: "Exhaust outlet temperature",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "ExhaustOutletTemperature",
            SENSOR: TEMPERATURE,
        },
        0x54: {  # 84, Exhaust Fan Speed
            EN: "Actual exhaust fan speed",
            DIR: READ_ONLY,
            VAL: U16,
            VAR: "ExhaustFanSpeed",
        },
        0x55: {  # 85, Inlet Fan Speed
            EN: "Actual inlet fan speed",
            DIR: READ_ONLY,
            VAL: U16,
            VAR: "InletFanSpeed",
        },
        0x56: {  # 86, VH Remote Parameter
            EN: "Remote parameter settings ventilation/heat-recovery",
            DIR: READ_ONLY,
            VAL: FLAG8,
            VAR: "VHRemoteParameter",
        },
        0x57: {  # 87, Nominal Ventilation
            EN: "Nominal ventilation value",
            DIR: READ_WRITE,
            VAL: U8,
            VAR: "NominalVentilation",
        },
        0x58: {  # 88, VH TSP Size
            EN: "TSP number ventilation/heat-recovery",
            DIR: READ_ONLY,
            VAL: U8,
            VAR: {HB: "VHTSPSize"},
        },
        0x59: {  # 89, VH TSP Entry
            EN: "TSP entry ventilation/heat-recovery",
            DIR: READ_WRITE,
            VAL: U8,
            VAR: {HB: "VHTSPIndex", LB: "VHTSPValue"},
        },
        0x5A: {  # 90, VH FHB Size
            EN: "Fault buffer size ventilation/heat-recovery",
            DIR: READ_ONLY,
            VAL: U8,
            VAR: {HB: "VHFHBSize"},
        },
        0x5B: {  # 91, VH FHB Entry
            EN: "Fault buffer entry ventilation/heat-recovery",
            DIR: READ_ONLY,
            VAL: U8,
            VAR: {HB: "VHFHBIndex", LB: "VHFHBValue"},
        },
        # OpenTherm 2.2 IDs
        0x64: {  # 100, Remote Override Function
            EN: "Remote override function",
            DIR: READ_ONLY,
            VAL: {HB: FLAG8, LB: U8},
            VAR: {HB: "RemoteOverrideFunction"},
        },
        0x73: {  # 115, OEM Diagnostic Code
            EN: "OEM diagnostic code",
            DIR: READ_ONLY,
            VAL: U16,
            VAR: "OEMDiagnosticCode",
        },
        0x74: {  # 116, Starts Burner
            EN: "Number of starts burner",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "StartsBurner",
            SENSOR: COUNTER,
        },
        0x75: {  # 117, Starts CH Pump
            EN: "Number of starts central heating pump",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "StartsCHPump",
            SENSOR: COUNTER,
        },
        0x76: {  # 118, Starts DHW Pump
            EN: "Number of starts DHW pump/valve",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "StartsDHWPump",
            SENSOR: COUNTER,
        },
        0x77: {  # 119, Starts Burner DHW
            EN: "Number of starts burner during DHW mode",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "StartsBurnerDHW",
            SENSOR: COUNTER,
        },
        0x78: {  # 120, Hours Burner
            EN: "Number of hours burner is in operation (i.e. flame on)",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "HoursBurner",
            SENSOR: COUNTER,
        },
        0x79: {  # 121, Hours CH Pump
            EN: "Number of hours central heating pump has been running",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "HoursCHPump",
            SENSOR: COUNTER,
        },
        0x7A: {  # 122, Hours DHW Pump
            EN: "Number of hours DHW pump has been running/valve has been opened",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "HoursDHWPump",
            SENSOR: COUNTER,
        },
        0x7B: {  # 123, Hours DHW Burner
            EN: "Number of hours DHW burner is in operation during DHW mode",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "HoursDHWBurner",
            SENSOR: COUNTER,
        },
        0x7C: {  # 124, Master OpenTherm Version
            EN: "Opentherm version Master",
            DIR: WRITE_ONLY,
            VAL: F8_8,
            VAR: "MasterOpenThermVersion",
        },
        0x7D: {  # 125, Slave OpenTherm Version
            EN: "Opentherm version Slave",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "SlaveOpenThermVersion",
        },
        0x7E: {  # 126, Master Product Type/Version
            EN: "Master product version and type",
            DIR: WRITE_ONLY,
            VAL: U8,
            VAR: {HB: "MasterProductType", LB: "MasterProductVersion"},
        },
        0x7F: {  # 127, Slave Product Type/Version
            EN: "Slave product version and type",
            DIR: READ_ONLY,
            VAL: U8,
            VAR: {HB: "SlaveProductType", LB: "SlaveProductVersion"},
        },
        # ZX-DAVB extras
        0x71: {  # 113, Bad Starts Burner
            EN: "Number of un-successful burner starts",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "BadStartsBurner?",
            SENSOR: COUNTER,
        },
        0x72: {  # 114, Low Signals Flame
            EN: "Number of times flame signal was too low",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "LowSignalsFlame?",
            SENSOR: COUNTER,
        },
        # https://www.domoticaforum.eu/viewtopic.php?f=70&t=10893
        # 0x23: {  # 35, Boiler Fan Speed (rpm/60?)?
        # },
        0x24: {  # 36, Electrical current through burner flame (µA)
            EN: "Electrical current through burner flame (µA)",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "BurnerCurrent",
        },
        0x25: {  # 37, CH2 Room Temperature
            EN: "Room temperature for 2nd CH circuit",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "CH2CurrentTemperature",
            SENSOR: TEMPERATURE,
        },
        0x26: {  # 38, Relative Humidity, c.f. 0x4E
            EN: "Relative humidity",
            DIR: READ_ONLY,
            VAL: U8,
            VAR: {HB: "RelativeHumidity"},  # TODO: or LB?
            SENSOR: HUMIDITY,
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
# ID2:LB:  Master MemberID Code

# ID3:HB0: Slave configuration: DHW present
# ID3:HB1: Slave configuration: Control type
# ID3:HB4: Slave configuration: Master low-off&pump control

# ID5:HB0: Service request
# ID5:HB1: Lockout-reset
# ID5:HB2: Low water pressure
# ID5:HB3: Gas/flame fault
# ID5:HB4: Air pressure fault
# ID5:HB5: Water over-temperature
# ID5:LB:  OEM fault code

# ID6:HB0: Remote boiler parameter transfer-enable: DHW setpoint
# ID6:HB1: Remote boiler parameter transfer-enable: max. CH setpoint
# ID6:LB0: Remote boiler parameter read/write: DHW setpoint
# ID6:LB1: Remote boiler parameter read/write: max. CH setpoint

# ID9:  Remote override room Setpoint
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


# https://github.com/rvdbreemen/OTGW-firmware/blob/main/Specification/New%20OT%20data-ids.txt  # noqa
"""
New OT Data-ID's - Found two new ID's at this device description:
http://www.opentherm.eu/product/view/18/feeling-d201-ot
    ID 98: For a specific RF sensor the RF strength and battery level is written
    ID 99: Operating Mode HC1, HC2/ Operating Mode DHW

Found new data-id's at this page:
https://www.opentherm.eu/request-details/?post_ids=1833
    ID 109: Electricity producer starts
    ID 110: Electricity producer hours
    ID 111: Electricity production
    ID 112: Cumulative Electricity production

Found new Data-ID's at this page:
https://www.opentherm.eu/request-details/?post_ids=1833
    ID 36:   {f8.8}   "Electrical current through burner flame" (µA)
    ID 37:   {f8.8}   "Room temperature for 2nd CH circuit"
    ID 38:   {u8 u8}  "Relative Humidity"

For Data-ID's 37 and 38 I assumed their data types, for Data ID 36 I determined it by
matching qSense value with the correct data-type.

I also analysed OT Remeha qSense <-> Remeha Tzerra communication.
    ID 131:   {u8 u8}   "Remeha dF-/dU-codes"
    ID 132:   {u8 u8}   "Remeha Service message"
    ID 133:   {u8 u8}   "Remeha detection connected SCU’s"

"Remeha dF-/dU-codes": Should match the dF-/dU-codes written on boiler nameplate.
Read-Data Request (0 0) returns the data. Also accepts Write-Data Requests (dF dU),
this returns the boiler to its factory defaults.

"Remeha Service message" Read-Data Request (0 0), boiler returns (0 2) in case of no
boiler service. Write-Data Request (1 255) clears the boiler service message.
    boiler returns (1 1) = next service type is "A"
    boiler returns (1 2) = next service type is "B"
    boiler returns (1 3) = next service type is "C"

"Remeha detection connected SCU’s": Write-Data Request (255 1) enables detection of
connected SCU prints, correct response is (Write-Ack 255 1).

Other Remeha info:
    ID   5: correponds with the Remeha E:xx fault codes
    ID  11: correponds with the Remeha Pxx parameter codes
    ID  35: reported value is fan speed in rpm/60
    ID 115: correponds with the Remeha Status and Sub-status numbers, {u8 u8} data-type
"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - Opentherm processor."""

import logging
import struct
from types import SimpleNamespace
from typing import Any, Tuple

from .const import __dev_mode__

DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)

# Data structure shamelessy copied, with thanks to @nlrb, from:
# github.com/nlrb/com.tclcode.otgw (node_modules/otg-api/lib/ot_msg.js),

# Other code shamelessy copied, with thanks to @mvn23, from:
# github.com/mvn23/pyotgw (pyotgw/protocol.py),

# Also see:
# github.com/rvdbreemen/OTGW-firmware

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
SPECIAL = U8  # used for ID 0x14 (20)

HB = "hb"
LB = "lb"

MESSAGES = "messages"
MSG_DESC = "description"
MSG_ID = "msg_id"
MSG_NAME = "msg_name"
MSG_TYPE = "msg_type"
VALUE = "value"
VALUE_HB = f"{VALUE}_{HB}"
VALUE_LB = f"{VALUE}_{LB}"

Sensor = SimpleNamespace(
    COUNTER="counter",
    RATIO="ratio",
    HUMIDITY="relative humidity (%)",
    PERCENTAGE="percentage (%)",
    PRESSURE="pressure (bar)",
    TEMPERATURE="temperature (°C)",
    CURRENT="current (µA)",
    FLOW_RATE="flow rate (L/min)",
    CO2_LEVEL="CO2 (ppm)",
)  # all are F8_8, except COUNTER, CO2_LEVEL

OPENTHERM_MSG_TYPE = {
    0b000: "Read-Data",
    0b001: "Write-Data",
    0b010: "Invalid-Data",
    0b011: "-reserved-",  # as per Unknown-DataId?
    0b100: "Read-Ack",
    0b101: "Write-Ack",
    0b110: "Data-Invalid",  # e.g. sensor fault
    0b111: "Unknown-DataId",
}

# These must have either a FLAGS (preferred) or a VAR for their message name
OPENTHERM_SCHEMA = {
    # OpenTherm status flags [ID 0: Master status (HB) & Slave status (LB)]
    "status_flags": {
        0x0100: {
            EN: "Central heating enable",
            NL: "Centrale verwarming aan",
            VAR: "StatusCHEnabled",
        },
        0x0200: {
            EN: "DHW enable",
            NL: "Tapwater aan",
            VAR: "StatusDHWEnabled",
        },
        0x0400: {
            EN: "Cooling enable",
            NL: "Koeling aan",
            VAR: "StatusCoolEnabled",
        },
        0x0800: {
            EN: "Outside temp. comp. active",
            NL: "Compenseren buitentemp.",
            VAR: "StatusOTCActive",
        },
        0x1000: {
            EN: "Central heating 2 enable",
            NL: "Centrale verwarming 2 aan",
            VAR: "StatusCH2Enabled",
        },
        0x2000: {
            EN: "Summer/winter mode",
            NL: "Zomer/winter mode",
            VAR: "StatusSummerWinter",
        },
        0x4000: {
            EN: "DHW blocking",
            NL: "Tapwater blokkade",
            VAR: "StatusDHWBlocked",
        },
        0x0001: {
            EN: "Fault indication",
            NL: "Fout indicatie",
            VAR: "StatusFault",
        },  # no fault/fault
        0x0002: {
            EN: "Central heating mode",
            NL: "Centrale verwarming mode",
            VAR: "StatusCHMode",
        },  # not active/active
        0x0004: {
            EN: "DHW mode",
            NL: "Tapwater mode",
            VAR: "StatusDHWMode",
        },  # not active/active
        0x0008: {
            EN: "Flame status",
            NL: "Vlam status",
            VAR: "StatusFlame",
        },  # flame off/on
        0x0010: {
            EN: "Cooling status",
            NL: "Status koelen",
            VAR: "StatusCooling",
        },  # not active/active
        0x0020: {
            EN: "Central heating 2 mode",
            NL: "Centrale verwarming 2 mode",
            VAR: "StatusCH2Mode",
        },  # not active/active
        0x0040: {
            EN: "Diagnostic indication",
            NL: "Diagnose indicatie",
            VAR: "StatusDiagnostic",
        },  # no diagnostics/diagnostics event
    },
    # OpenTherm Master configuration flags [ID 2: master config flags (HB)]
    "master_config_flags": {
        0x0100: {
            EN: "Smart Power",
            VAR: "ConfigSmartPower",
        },
    },
    # OpenTherm Slave configuration flags [ID 3: slave config flags (HB)]
    "slave_config_flags": {
        0x0100: {
            EN: "DHW present",
            VAR: "ConfigDHWpresent",
        },
        0x0200: {
            EN: "Control type (modulating on/off)",
            VAR: "ConfigControlType",
        },
        0x0400: {
            EN: "Cooling supported",
            VAR: "ConfigCooling",
        },
        0x0800: {
            EN: "DHW storage tank",
            VAR: "ConfigDHW",
        },
        0x1000: {
            EN: "Master low-off & pump control allowed",
            VAR: "ConfigMasterPump",
        },
        0x2000: {
            EN: "Central heating 2 present",
            VAR: "ConfigCH2",
        },
    },
    # OpenTherm fault flags [ID 5: Application-specific fault flags (HB)]
    "fault_flags": {
        0x0100: {
            EN: "Service request",
            NL: "Onderhoudsvraag",
            VAR: "FaultServiceRequest",
        },
        0x0200: {
            EN: "Lockout-reset",
            NL: "Geen reset op afstand",
            VAR: "FaultLockoutReset",
        },
        0x0400: {
            EN: "Low water pressure",
            NL: "Waterdruk te laag",
            VAR: "FaultLowWaterPressure",
        },
        0x0800: {
            EN: "Gas/flame fault",
            NL: "Gas/vlam fout",
            VAR: "FaultGasFlame",
        },
        0x1000: {
            EN: "Air pressure fault",
            NL: "Luchtdruk fout",
            VAR: "FaultAirPressure",
        },
        0x2000: {
            EN: "Water over-temperature",
            NL: "Water te heet",
            VAR: "FaultOverTemperature",
        },
    },
    # OpenTherm remote flags [ID 6: Remote parameter flags (HB)]
    "remote_flags": {
        0x0100: {
            EN: "DHW setpoint enable",
            VAR: "RemoteDHWEnabled",
        },
        0x0200: {
            EN: "Max. CH setpoint enable",
            VAR: "RemoteMaxCHEnabled",
        },
        0x0001: {
            EN: "DHW setpoint read/write",
            VAR: "RemoteDHWReadWrite",
        },
        0x0002: {
            EN: "Max. CH setpoint read/write",
            VAR: "RemoteMaxCHReadWrite",
        },
    },
    # OpenTherm messages
    MESSAGES: {
        0x00: {  # 0, Status
            EN: "Status",
            DIR: READ_ONLY,
            VAL: FLAG8,
            FLAGS: "status_flags",
        },
        0x01: {  # 1, Control Setpoint
            EN: "Control setpoint",
            NL: "Ketel doeltemperatuur",
            DIR: WRITE_ONLY,
            VAL: F8_8,
            VAR: "ControlSetpoint",
            SENSOR: Sensor.TEMPERATURE,
        },
        0x02: {  # 2, Master configuration (Member ID)
            EN: "Master configuration",
            DIR: WRITE_ONLY,
            VAL: {HB: FLAG8, LB: U8},
            FLAGS: "master_config_flags",
            VAR: {LB: "MasterMemberId"},
        },
        0x03: {  # 3, Slave configuration (Member ID)
            EN: "Slave configuration",
            DIR: READ_ONLY,
            VAL: {HB: FLAG8, LB: U8},
            FLAGS: "slave_config_flags",
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
            FLAGS: "fault_flags",
        },
        0x06: {  # 6, Remote Flags
            EN: "Remote parameter flags",
            DIR: READ_ONLY,
            VAL: FLAG8,
            FLAGS: "remote_flags",
        },
        0x07: {  # 7, Cooling Control Signal
            EN: "Cooling control signal",
            DIR: WRITE_ONLY,
            VAL: F8_8,
            VAR: "CoolingControlSignal",
            SENSOR: Sensor.PERCENTAGE,
        },
        0x08: {  # 8, CH2 Control Setpoint
            EN: "Control setpoint for 2nd CH circuit",
            DIR: WRITE_ONLY,
            VAL: F8_8,
            VAR: "CH2ControlSetpoint",
            SENSOR: Sensor.TEMPERATURE,
        },
        0x09: {  # 9, Remote Override Room Setpoint
            EN: "Remote override room setpoint",
            NL: "Overschreven kamer doeltemperatuur",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "RemoteOverrideRoomSetpoint",
            SENSOR: Sensor.TEMPERATURE,
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
            SENSOR: Sensor.PERCENTAGE,
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
            SENSOR: Sensor.TEMPERATURE,
        },
        0x11: {  # 17, Relative Modulation Level
            EN: "Relative modulation level",
            NL: "Relatief modulatie-niveau",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "RelativeModulationLevel",
            SENSOR: Sensor.PERCENTAGE,
        },
        0x12: {  # 18, CH Water Pressure
            EN: "Central heating water pressure (bar)",
            NL: "Keteldruk",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "CHWaterPressure",
            SENSOR: Sensor.PRESSURE,
        },
        0x13: {  # 19, DHW Flow Rate
            EN: "DHW flow rate (litres/minute)",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "DHWFlowRate",
            SENSOR: Sensor.FLOW_RATE,
        },
        0x14: {  # 20, Day/Time
            EN: "Day of week & Time of day",
            DIR: READ_WRITE,
            VAL: {HB: SPECIAL, LB: U8},  # 1..7/0..23, 0..59
            VAR: {HB: "DayHour", LB: "Minutes"},  # HB7-5: Day, HB4-0: Hour
        },
        0x15: {  # 21, Date
            EN: "Date",
            DIR: READ_WRITE,
            VAL: U8,  # 1..12, 1..31
            VAR: {HB: "Month", LB: "DayOfMonth"},
        },
        0x16: {  # 22, Year
            EN: "Year",
            DIR: READ_WRITE,
            VAL: U16,  # 1999-2099
            VAR: "Year",
        },
        0x17: {  # 23, CH2 Current Setpoint
            EN: "Room setpoint for 2nd CH circuit",
            DIR: WRITE_ONLY,
            VAL: F8_8,
            VAR: "CH2CurrentSetpoint",
            SENSOR: Sensor.TEMPERATURE,
        },
        0x18: {  # 24, Current Room Temperature
            EN: "Room temperature",
            NL: "Kamertemperatuur",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "CurrentTemperature",
            SENSOR: Sensor.TEMPERATURE,
        },
        0x19: {  # 25, Boiler Water Temperature
            EN: "Boiler water temperature",
            NL: "Ketelwatertemperatuur",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "BoilerWaterTemperature",
            SENSOR: Sensor.TEMPERATURE,
        },
        0x1A: {  # 26, DHW Temperature
            EN: "DHW temperature",
            NL: "Tapwatertemperatuur",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "DHWTemperature",
            SENSOR: Sensor.TEMPERATURE,
        },
        0x1B: {  # 27, Outside Temperature
            EN: "Outside temperature",
            NL: "Buitentemperatuur",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "OutsideTemperature",
            SENSOR: Sensor.TEMPERATURE,
        },
        0x1C: {  # 28, Return Water Temperature
            EN: "Return water temperature",
            NL: "Retourtemperatuur",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "ReturnWaterTemperature",
            SENSOR: Sensor.TEMPERATURE,
        },
        0x1D: {  # 29, Solar Storage Temperature
            EN: "Solar storage temperature",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "SolarStorageTemperature",
            SENSOR: Sensor.TEMPERATURE,
        },
        0x1E: {  # 30, Solar Collector Temperature
            EN: "Solar collector temperature",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "SolarCollectorTemperature",
            SENSOR: Sensor.TEMPERATURE,
        },
        0x1F: {  # 31, CH2 Flow Temperature
            EN: "Flow temperature for 2nd CH circuit",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "CH2FlowTemperature",
            SENSOR: Sensor.TEMPERATURE,
        },
        0x20: {  # 32, DHW2 Temperature
            EN: "DHW 2 temperature",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "DHW2Temperature",
            SENSOR: Sensor.TEMPERATURE,
        },
        0x21: {  # 33, Boiler Exhaust Temperature
            EN: "Boiler exhaust temperature",
            DIR: READ_ONLY,
            VAL: S16,
            VAR: "BoilerExhaustTemperature",
            SENSOR: Sensor.TEMPERATURE,
        },
        0x30: {  # 48, DHW Boundaries
            EN: "DHW setpoint boundaries",
            DIR: READ_ONLY,
            VAL: S8,
            VAR: {HB: "DHWUpperBound", LB: "DHWLowerBound"},
            SENSOR: Sensor.TEMPERATURE,
        },
        0x31: {  # 49, CH Boundaries
            EN: "Max. central heating setpoint boundaries",
            DIR: READ_ONLY,
            VAL: S8,
            VAR: {HB: "CHUpperBound", LB: "CHLowerBound"},
            SENSOR: Sensor.TEMPERATURE,
        },
        0x32: {  # 50, OTC Boundaries
            EN: "OTC heat curve ratio upper & lower bounds",
            DIR: READ_ONLY,
            VAL: S8,
            VAR: {HB: "OTCUpperBound", LB: "OTCLowerBound"},
        },
        0x38: {  # 56, DHW Setpoint
            EN: "DHW setpoint",
            NL: "Tapwater doeltemperatuur",
            DIR: READ_WRITE,
            VAL: F8_8,
            VAR: "DHWSetpoint",
            SENSOR: Sensor.TEMPERATURE,
        },
        0x39: {  # 57, Max CH Water Setpoint
            EN: "Max. central heating water setpoint",
            NL: "Max. ketel doeltemperatuur",
            DIR: READ_WRITE,
            VAL: F8_8,
            VAR: "MaxCHWaterSetpoint",
            SENSOR: Sensor.TEMPERATURE,
        },
        0x3A: {  # 58, OTC Heat Curve Ratio
            EN: "OTC heat curve ratio",
            DIR: READ_WRITE,
            VAL: F8_8,
            VAR: "OTCHeatCurveRatio",
            SENSOR: Sensor.RATIO,
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
            SENSOR: Sensor.HUMIDITY,
        },
        0x4F: {  # 79, CO2 Level
            EN: "CO2 level",
            NL: "CO2 niveau",
            DIR: READ_WRITE,
            VAL: U16,  # 0-2000 ppm
            VAR: "CO2Level",
            SENSOR: Sensor.CO2_LEVEL,
        },
        0x50: {  # 80, Supply Inlet Temperature
            EN: "Supply inlet temperature",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "SupplyInletTemperature",
            SENSOR: Sensor.TEMPERATURE,
        },
        0x51: {  # 81, Supply Outlet Temperature
            EN: "Supply outlet temperature",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "SupplyOutletTemperature",
            SENSOR: Sensor.TEMPERATURE,
        },
        0x52: {  # 82, Exhaust Inlet Temperature
            EN: "Exhaust inlet temperature",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "ExhaustInletTemperature",
            SENSOR: Sensor.TEMPERATURE,
        },
        0x53: {  # 83, Exhaust Outlet Temperature
            EN: "Exhaust outlet temperature",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "ExhaustOutletTemperature",
            SENSOR: Sensor.TEMPERATURE,
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
            SENSOR: Sensor.COUNTER,
        },
        0x75: {  # 117, Starts CH Pump
            EN: "Number of starts central heating pump",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "StartsCHPump",
            SENSOR: Sensor.COUNTER,
        },
        0x76: {  # 118, Starts DHW Pump
            EN: "Number of starts DHW pump/valve",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "StartsDHWPump",
            SENSOR: Sensor.COUNTER,
        },
        0x77: {  # 119, Starts Burner DHW
            EN: "Number of starts burner during DHW mode",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "StartsBurnerDHW",
            SENSOR: Sensor.COUNTER,
        },
        0x78: {  # 120, Hours Burner
            EN: "Number of hours burner is in operation (i.e. flame on)",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "HoursBurner",
            SENSOR: Sensor.COUNTER,
        },
        0x79: {  # 121, Hours CH Pump
            EN: "Number of hours central heating pump has been running",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "HoursCHPump",
            SENSOR: Sensor.COUNTER,
        },
        0x7A: {  # 122, Hours DHW Pump
            EN: "Number of hours DHW pump has been running/valve has been opened",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "HoursDHWPump",
            SENSOR: Sensor.COUNTER,
        },
        0x7B: {  # 123, Hours DHW Burner
            EN: "Number of hours DHW burner is in operation during DHW mode",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "HoursDHWBurner",
            SENSOR: Sensor.COUNTER,
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
            SENSOR: Sensor.COUNTER,
        },
        0x72: {  # 114, Low Signals Flame
            EN: "Number of times flame signal was too low",
            DIR: READ_WRITE,
            VAL: U16,
            VAR: "LowSignalsFlame?",
            SENSOR: Sensor.COUNTER,
        },
        # https://www.domoticaforum.eu/viewtopic.php?f=70&t=10893
        # 0x23: {  # 35, Boiler Fan Speed (rpm/60?)?
        # },
        0x24: {  # 36, Electrical current through burner flame (µA)
            EN: "Electrical current through burner flame (µA)",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "BurnerCurrent",
            SENSOR: Sensor.CURRENT,
        },
        0x25: {  # 37, CH2 Room Temperature
            EN: "Room temperature for 2nd CH circuit",
            DIR: READ_ONLY,
            VAL: F8_8,
            VAR: "CH2CurrentTemperature",
            SENSOR: Sensor.TEMPERATURE,
        },
        0x26: {  # 38, Relative Humidity, c.f. 0x4E
            EN: "Relative humidity",
            DIR: READ_ONLY,
            VAL: U8,
            VAR: {HB: "RelativeHumidity"},  # TODO: or LB?
            SENSOR: Sensor.HUMIDITY,
        },
    },
}
OPENTHERM_MESSAGES = OPENTHERM_SCHEMA[MESSAGES]

# R8810A 1018 v4: https://www.opentherm.eu/request-details/?post_ids=2944
# as at: 2021/06/28

# see also: http://otgw.tclcode.com/matrix.cgi#boilers
# 0,       1,    3,    5,    9,   14,   16-19,   24-28,   56-57,   63,  128,  255
# 0x00, 0x01, 0x03, 0x05, 0x09, 0x0E, 0x10-13, 0x18-1C, 0x38-39, 0x3F, 0x80, 0xFF

# personal testing:
# 0,       1,    3,    5,    6,   12-14,   17-18,   25-26,   28,            56
# 0x00,       0x03, 0x05, 0x06, 0x0C-0D, 0x11-12, 0x19-1A, 0x1C, 0x30-31, 0x38, 0x7D

OTB_MSG_IDS = {
    # These are in the R8810A specification...
    0x00: "Master/Slave status flags",
    # 000:HB0: Master status: CH enable
    # 000:HB1: Master status: DHW enable
    # 000:HB2: Master status: Cooling enable
    # 000:HB3: Master status: OTC active
    # 000:HB5: Master status: Summer/winter mode
    # 000:HB6: Master status: DHW blocking
    # 000:LB0: Slave Status: Fault indication
    # 000:LB1: Slave Status: CH mode
    # 000:LB2: Slave Status: DHW mode
    # 000:LB3: Slave Status: Flame status
    0x01: "CH water temperature Setpoint (°C)",
    # 001: Control Setpoint i.e. CH water temperature Setpoint (°C)
    0x02: "Master configuration",
    # 002:HB0: Master configuration: Smart power
    # 002:LB:  Master MemberID Code
    0x03: "Slave configuration",
    # 003:HB0: Slave configuration: DHW present
    # 003:HB1: Slave configuration: Control type
    # 003:HB4: Slave configuration: Master low-off & pump control
    0x05: "Fault flags & OEM codes",
    # 005:HB0: Service request
    # 005:HB1: Lockout-reset
    # 005:HB2: Low water pressure
    # 005:HB3: Gas/flame fault
    # 005:HB4: Air pressure fault
    # 005:HB5: Water over-temperature
    # 005:LB:  OEM fault code
    0x06: "Remote boiler parameter flags",
    # 006:HB0: Remote boiler parameter transfer-enable: DHW setpoint
    # 006:HB1: Remote boiler parameter transfer-enable: max. CH setpoint
    # 006:LB0: Remote boiler parameter read/write: DHW setpoint
    # 006:LB1: Remote boiler parameter read/write: max. CH setpoint
    0x09: "Remote override room Setpoint",  # 009: # c.f. 0x64, 100               # TODO
    0x0A: "Number of TSPs supported by slave",  # 010:                            # TODO
    0x0C: "Size of FHB supported by slave",  # 012:                               # TODO
    0x0E: "Maximum relative modulation level setting (%)",  # 014:
    0x10: "Room Setpoint (°C)",  # 016:
    0x11: "Relative Modulation Level (%)",  # 017:
    0x12: "Water pressure in CH circuit (bar)",  # 018:
    0x13: "Water flow rate in DHW circuit. (L/min)",  # 019:
    0x18: "Room temperature (°C)",  # 024:
    0x19: "Boiler flow water temperature (°C)",  # 025:
    0x1A: "DHW temperature (°C)",  # 026:
    0x1B: "Outside temperature (°C)",  # 027:
    0x1C: "Return water temperature (°C)",  # 028:
    0x30: "DHW Setpoint upper & lower bounds for adjustment (°C)",  # 048:
    0x31: "Max CH water Setpoint upper & lower bounds for adjustment (°C)",  # 049:
    0x38: "DHW Setpoint (°C) (Remote parameter 1)",  # 056:
    0x39: "Max CH water Setpoint (°C) (Remote parameters 2)",  # 057:
    0x7E: "Master product version number and type",  # 126:
    0x7F: "Slave product version number and type",  # 127:
    #
    # These are not in the R8810A spec, but are natively RQ'd by 01:/30:...
    # (0[35F]|1[1239AC]|3[89]|7[123456789ABF])
    0x0D: "FHB Entry",  # 013:                                                    # TODO
    0x73: "OEM diagnostic code",  # 115:
    0x7C: "Opentherm version Master",  # 124:
    0x7D: "Opentherm version Slave",  # 125:
    #
    # These also have been seen natively RQ'd by 01:/30...
    0x0F: "Max. boiler capacity (kW) and modulation level setting (%)",  # 15
    0x71: "Number of un-successful burner starts",  # 113
    0x72: "Number of times flame signal was too low",  # 114
    0x74: "Number of starts burner",  # 116
    0x75: "Number of starts central heating pump",  # 117
    0x76: "Number of starts DHW pump/valve",  # 118
    0x77: "Number of starts burner during DHW mode",  # 119
    0x78: "Number of hours burner is in operation (i.e. flame on)",  # 120
    0x79: "Number of hours central heating pump has been running",  # 121
    0x7A: "Number of hours DHW pump has been running/valve has been opened",  # 122
    0x7B: "Number of hours DHW burner is in operation during DHW mode",  # 123
}


def parity(x: int) -> int:
    """Make this the docstring."""
    shiftamount = 1
    while x >> shiftamount:
        x ^= x >> shiftamount
        shiftamount <<= 1
    return x & 1


def msg_value(val_seqx, val_type) -> Any:
    """Make this the docstring."""

    # based upon: https://github.com/mvn23/pyotgw/blob/master/pyotgw/protocol.py

    def flag8(byte, *args) -> list:
        """Split a byte (as a str) into a list of 8 bits (1/0)."""
        ret = [0] * 8
        byte = bytes.fromhex(byte)[0]
        for i in range(8):
            ret[i] = byte & 1
            byte = byte >> 1
        return ret

    def u8(byte, *args) -> int:
        """Convert a byte (as a str) into an unsigned int."""
        return struct.unpack(">B", bytes.fromhex(byte))[0]

    def s8(byte, *args) -> int:
        """Convert a byte (as a str) into a signed int."""
        return struct.unpack(">b", bytes.fromhex(byte))[0]

    def f8_8(msb, lsb) -> float:
        """Convert 2 bytes (as strs) into an OpenTherm f8_8 (float) value."""
        if msb == lsb == "FF":  # TODO: move up to parser?
            return None
        return float(s16(msb, lsb) / 256)

    def u16(msb, lsb) -> int:
        """Convert 2 bytes (as strs) into an unsigned int."""
        if msb == lsb == "FF":  # TODO: move up to parser?
            return None
        buf = struct.pack(">BB", u8(msb), u8(lsb))
        return int(struct.unpack(">H", buf)[0])

    def s16(msb, lsb) -> int:
        """Convert 2 bytes (as strs) into a signed int."""
        if msb == lsb == "FF":  # TODO: move up to parser?
            return None
        buf = struct.pack(">bB", s8(msb), u8(lsb))
        return int(struct.unpack(">h", buf)[0])

    DATA_TYPES = {
        FLAG8: flag8,
        U8: u8,
        S8: s8,
        F8_8: f8_8,
        U16: u16,
        S16: s16,
    }

    if val_type in DATA_TYPES:
        return DATA_TYPES[val_type](val_seqx[:2], val_seqx[2:])
    return val_seqx


def _decode_flags(frame: str, data_id: int) -> dict:
    try:
        flag_schema = OPENTHERM_SCHEMA[OPENTHERM_MESSAGES[data_id][FLAGS]]
    except KeyError:
        raise KeyError(
            f"Invalid data-id: 0x{data_id:02X} ({data_id}): data-id has no flags"
        )

    return flag_schema


def decode_frame(frame: str) -> Tuple[int, int, dict, str]:
    assert (
        isinstance(frame, str) and len(frame) == 8
    ), f"Invalid frame (type or length): {frame}"

    if int(frame[:2], 16) // 0x80 != parity(int(frame, 16) & 0x7FFFFFFF):
        raise ValueError(f"Invalid parity bit: 0b{int(frame[:2], 16) // 0x80}")

    if int(frame[:2], 16) & 0x0F != 0x00:
        raise ValueError(f"Invalid spare bits: 0b{int(frame[:2], 16) & 0x0F:04b}")

    msg_type = (int(frame[:2], 16) & 0x70) >> 4

    # if msg_type == 0b011:  # NOTE: this msg-type may no longer be reserved (R8820?)
    #     raise ValueError(f"Reserved msg-type (0b{msg_type:03b})")

    data_id = int(frame[2:4], 16)
    msg_schema = OPENTHERM_MESSAGES.get(data_id, {})

    # There are five msg_id with FLAGS - the following is not 100% correct...
    data_value = {MSG_NAME: msg_schema.get(FLAGS, msg_schema.get(VAR))}

    if msg_type in (0b000, 0b010, 0b011, 0b110, 0b111):
        # if frame[4:] != "0000":  # NOTE: this is not a hard rule, even for 0b000
        #     raise ValueError(f"Invalid data-value for msg-type: 0x{frame[4:]}")
        return OPENTHERM_MSG_TYPE[msg_type], data_id, data_value, msg_schema

    if not msg_schema:  # may be a corrupt payload
        data_value[VALUE] = msg_value(frame[4:8], U16)

    elif isinstance(msg_schema[VAL], dict):
        data_value[VALUE_HB] = msg_value(
            frame[4:6], msg_schema[VAL].get(HB, msg_schema[VAL])
        )
        data_value[VALUE_LB] = msg_value(
            frame[6:8], msg_schema[VAL].get(LB, msg_schema[VAL])
        )

    elif isinstance(msg_schema.get(VAR), dict):
        data_value[VALUE_HB] = msg_value(frame[4:6], msg_schema[VAL])
        data_value[VALUE_LB] = msg_value(frame[6:8], msg_schema[VAL])

    elif msg_schema[VAL] in (FLAG8, U8, S8):
        data_value[VALUE] = msg_value(frame[4:6], msg_schema[VAL])

    elif msg_schema[VAL] == F8_8:
        result = msg_value(frame[4:8], msg_schema[VAL])
        if result is None or msg_schema.get(SENSOR) not in (
            Sensor.PERCENTAGE,
            Sensor.TEMPERATURE,
        ):
            data_value[VALUE] = result
        elif msg_schema.get(SENSOR) == Sensor.PERCENTAGE:
            # NOTE: OT defines % as 0.0-100.0, but (this) ramses uses 0.0-1.0 elsewhere
            data_value[VALUE] = int(result * 2) / 200  # seems precision of 1%
        else:  # if msg_schema.get(SENSOR) == Sensor.TEMPERATURE:
            data_value[VALUE] = int(result * 100) / 100
        # else:  # Sensor.PRESSURE:  Sensor.HUMIDITY, "flow", "current"
        #     data_value[VALUE] = result

    elif msg_schema[VAL] in (S16, U16):
        data_value[VALUE] = msg_value(frame[4:8], msg_schema[VAL])

    else:  # shouldn't reach here
        data_value[VALUE] = msg_value(frame[4:8], U16)

    return OPENTHERM_MSG_TYPE[msg_type], data_id, data_value, msg_schema


# assert not [
#     k
#     for k, v in OPENTHERM_MESSAGES.items()
#     if not isinstance(v[VAL], dict)
#     and not isinstance(v.get(VAR), dict)
#     and v[VAL] not in msg_value.DATA_TYPES
# ], "Corrupt OPENTHERM_MESSAGES schema"


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

    For Data-ID's 37 and 38 I assumed their data types, for Data ID 36 I determined
    it by matching qSense value with the correct data-type.

    I also analysed OT Remeha qSense <-> Remeha Tzerra communication.
        ID 131:   {u8 u8}   "Remeha dF-/dU-codes"
        ID 132:   {u8 u8}   "Remeha Service message"
        ID 133:   {u8 u8}   "Remeha detection connected SCU’s"

    "Remeha dF-/dU-codes": Should match the dF-/dU-codes written on boiler nameplate.
    Read-Data Request (0 0) returns the data. Also accepts Write-Data Requests (dF
    dU),this returns the boiler to its factory defaults.

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
        ID 115: correponds with Remeha Status & Sub-status numbers, {u8 u8} data-type
"""

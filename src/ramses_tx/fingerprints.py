#!/usr/bin/env python3
"""RAMSES RF - RAMSES-II compatible Packet processor."""

from __future__ import annotations

__all__ = ["check_signature"]

# incl. date_1. NB: date_2 can vary (firmware date), and _unknown_1 can vary for R8810A
# fmt: off
__DEVICE_INFO_RAW: dict[str, tuple[str, str, str, str]] = {
    # Heating (device type implies a slug only for these)...
    "0002FF0119FFFFFFFF": ("CTL", "01", "2014-01-16", "EvoTouch Colour"),  # .              ATC928-G3-0xx Evo Mk3 - EvoTouch Colour (WiFi, 12 zones)
    "0002FF0163FFFFFFFF": ("CTL", "01", "2013-08-01", "Evo Color"),  # .                    ATP928-G2-080 Evo Mk2 - Color (no WiFi)
    "0002FFFF17FFFFFFFF": ("CTL", "01", "2012-05-11", "IONA RAI Prototype"),  # .           ATC928-G1-000 Evo Mk1 - Monochrone (?prototype, 8 zones)
    "0003FF0203FFFF0001": ("UFC", "02", "2017-11-06", "HCE80 V3.10 061117"),
    "0001C89D6E0600FEFF": ("UFC", "02", "2022-12-01", "HCE100-RADIO"),
    "0002FF0412FFFFFFFF": ("TRV", "04", "2014-03-13", "HR92 Radiator Ctrl."),
    "0002FF050BFFFFFFFF": ("TRV", "04", "2017-03-07", "HR91 Radiator Ctrl."),
    "0001C8810B0700FEFF": ("OTB", "10", "2019-08-20", "R8820"),
    "0002FF0A0CFFFFFFFF": ("OTB", "10", "2014-07-31", "R8810A Bridge"),
    "0002FF1F00FFFFFFFF": ("DTS", "22", "0000-00-00", "DT4 22"),
    "0002FF1E01FFFFFFFF": ("RFG", "30", "2013-12-04", "Internet Gateway"),
    "0002FF1E02FFFFFFFF": ("RFG", "30", "2014-10-17", "Internet Gateway"),
    "0002FF1E03FFFFFFFF": ("RFG", "30", "2017-04-21", "Internet Gateway"),
    "0001C8380A0100F1FF": ("RND", "34", "2014-11-03", "T87RF2025"),  # .                    Round
    "0001C8380F0100F1FF": ("RND", "34", "2017-05-03", "T87RF2025"),  # .                    Round
    # Odd - Vasco CTL/RFG
    "0001C848260066FEFE": ("CTL", "30", "2019-11-28", "BRDG-02EM23"),  # .                  Vasco Gateway (CTL/RFG/RFS?)
    # Odd - Jasper kit (device type implies a slug here too)
    "0002FF0801FFFFFFFE": ("JIM", "08", "2016-11-28", "Jasper EIM"),
    "0002FF0802FFFFFFFE": ("JIM", "08", "2017-11-10", "Jasper EIM"),
    "0002FF1F02FFFFFFFF": ("JST", "31", "2016-08-04", "Jasper Stat TXXX"),
    # FAN - some are HRUs, others extraction only
    "000100140C06010000": ("FAN", "20", "0000-00-00", ""),  # .                             31D9
    "000100140D06130000": ("FAN", "20", "0000-00-00", ""),  # .                             31D9
    "0001001B190B010000": ("FAN", "20", "0000-00-00", ""),  # .                             31D9
    "0001001B221201FEFF": ("FAN", "20", "2015-05-12", "CVE-RF"),  # .                       31D9, 31DA
    "0001001B271501FEFF": ("FAN", "20", "2016-11-03", "CVE-RF"),  # .                       31D9, 31DA (RP|12A0, RP|3120, both N/A)
    "0001001B281501FEFF": ("FAN", "20", "2016-11-11", "CVE-RF"),  # .                       31D9, 31DA
    "0001001B2E1901FEFF": ("FAN", "37", "2017-11-29", "CVE-RF"),  # .                       31D9, 31DA
    "0001001B311901FEFF": ("FAN", "37", "2018-05-14", "CVE-RF"),  # .                       31D9, 31DA
    "0001001B361B01FEFF": ("FAN", "37", "2019-04-11", "CVE-RF"),  # .                       31D9, 31DA, and 12C8
    "0001001B371B01FEFF": ("FAN", "37", "2019-08-29", "CVE-RF"),  # .                       31D9, 31DA
    "0001001B381B01FEFF": ("FAN", "37", "2020-02-14", "CVE-RF"),  # .                       31D9, 31DA (and I|042F, I|3120)
    "0001001B391B01FEFF": ("FAN", "37", "2021-11-04", "CVE-RF"),
    "0001C81C090466FEFF": ("FAN", "29", "0000-00-00", "VMC-17RP01"),  # .                   appears to be an EXT
    "0001C8260A0367FFFF": ("FAN", "29", "0000-00-00", "VMC-15RP01"),
    "0001C8260D0467FFFF": ("FAN", "29", "0000-00-00", "VMC-15RP01"),  # .                   31D9
    "0001C83A0F0866FFFF": ("FAN", "32", "0000-00-00", "VMD-17RPS01"),  # .                  31D9, 31DA
    "0001C85F0E0267FFFF": ("FAN", "32", "0000-00-00", "VMC-15RPS34"),  # .                  Orcon MVS-15
    "0001C87D130D67FEFF": ("FAN", "32", "2019-02-28", "VMD-15RMS64"),  # .                  Orcon HRC-300-EcoMax
    "0001C87D140D67FEFF": ("FAN", "32", "2019-12-23", "VMD-15RMS64"),  # .                  31D9, 31DA (and I|042F)
    "0001C895050567FEFF": ("FAN", "32", "2020-07-01", "VMD-15RMS86"),  # .                  31DA, 12A0, 22F7, 2411 (and I|042F, I|313F, I|3120)
    "0001C8950B0A67FEFF": ("FAN", "32", "2021-01-21", "VMD-15RMS86"),  # .                  31D9, 31DA, 12A0, 313F (and I|042F, I|3120)
    # PIV - usu. Nuaire
    "0001C90011006CFEFF": ("FAN", "30", "2016-09-09", "BRDG-02JAS01"),  # .      NOTE: 30:  31D9, 31DA, 1F09 (a PIV)
    "0001C9001D006CFEFE": ("FAN", "30", "2019-07-18", "BRDG-02JAS01"),  # .                             31D9
    # CO2 - some have PIR
    "00010028080101FEFF": ("CO2", "37", "2019-04-29", "VMS-12C39"),  # .                    1298, 31E0, 2E10, 3120, and I|22F1!
    "00010028090101FEFF": ("CO2", "37", "2021-01-20", "VMS-12C39"),  # .                    1298, 31E0, 2E10, 3120 (and I|042F)
    "0001C822030166FEFF": ("CO2", "29", "2015-05-07", "VMS-17C01"),  # .                    1298, 31E0
    "0001C822060166FEFF": ("CO2", "37", "2016-12-22", "VMS-17C01"),  # .                    1298, 31E0
    "0001C8500B0167FEFF": ("CO2", "29", "2017-03-09", "VMS-15C16"),  # .         CO2 sensor (no remote)
    "0001C85701016CFFFF": ("CO2", "32", "2016-06-17", "VMS-23C33"),  # .                    1298, 31E0 (and I|042F)
    # HUM
    "0001C825050266FFFF": ("HUM", "29", "2017-04-19", "VMS-17HB01"),  # .                   12A0, 31E0, 1060
    "0001C85802016CFFFF": ("HUM", "32", "2016-07-12", "VMS-23HB33"),  # .                   12A0, 31E0, 1060 (and I|042F)
    "0001C85803016CFFFF": ("HUM", "32", "2016-09-12", "VMS-23HB33"),  # .                   12A0, 31E0, 1060 (and I|042F)
    # REM
    "0001C827050167FFFF": ("REM", "29", "0000-00-00", "VMN-15LF01"),  # .                   22F1, 22F3
    "0001C827070167FFFF": ("REM", "29", "0000-00-00", "VMN-15LF01"),  # .                   22F1, 22F3
    "0001C827090167FFFF": ("REM", "29", "2019-02-13", "VMN-15LF01"),  # .                   22F1, 22F3 (and I|042F)
    "0001C85901016CFFFF": ("REM", "32", "2016-05-31", "VMN-23LMH23"),  # .        zxdavb    22F1, 1060, 4-way?
    "0001C85A01016CFFFF": ("REM", "32", "2016-06-01", "VMN-23LMH23"),  # .        zxdavb    22F1, 1060, 4-way?
    # REM (display, or with CO2 sensor)
    "0001C88D020167FEFF": ("CO2", "37", "2020-04-21", "VMI-15MC01"),  # .                   1298, 31E0
    "0001C88D030167FEFF": ("REM", "37", "2021-07-28", "VMI-15MC01"),   # .       1298/31E0, 22F1, 22F3  (with integrated CO2 sensor)
    "0001C894030167FFFF": ("REM", "37", "2020-08-27", "VMI-15WSJ53"),  # .                  22F1, 22F3? (HRC Display recessed 15RF)
    # RFS...
    "000100220B0001FEFF": ("RFS", "21", "2015-01-20", "CCU-12T20"),  # .      Itho spIDer   1060,       12C0, 22C9,       30C9, 3110, 3120, 3EF0, 01FF
    "000100222B0001FEFF": ("RFS", "21", "2019-07-10", "CCU-12T20"),  # .      Itho spIDer   1060,       12C0, 22C9, 2E10, 30C9, 3110, 3120, 3EF0
    "00010022340001FEFF": ("RFS", "21", "2020-08-05", "CCU-12T20"),  # .           spIDer   1060,       12C0, 22C9, 22F1, 22F3, 2E10, 30C9, 3110, 3120, 3EF0
    "00010022370101F1FB": ("RFS", "21", "2021-05-21", "CCU-12T20"),  # .           spIDer   1060,       12C0, 22C9,       30C9, 3110, 3120, 3EF0
    "00010022370101FEFF": ("RFS", "21", "2021-05-21", "CCU-12T20"),  # .           spIDer   1060, 1290, 12C0, 22C9,       30C9, 3110, 3120  (maybe incomplete)

    # TBA - broken as 18:...
    "0001FA100A0001FEFE": ("FAN", "18", "2019-04-11", "BRDG-02A55"),  # .        NOTE: 18:  31D9, 31DA, 1F09
    "0001FA100B0001FEFE": ("FAN", "18", "2019-07-22", "BRDG-02A55"),  # .        NOTE: 18:  31D9, 31DA, 1F09
    "0001C8820C006AFEFF": ("FAN", "18", "2019-08-20", "HRA82"),  # .             NOTE: 18:  (only I|042F, I|10E0)
    #
    "00010021030200FFFF": ("CO2", "37", "0000-00-00", "VMS-02J52"),  # .                                1298, 22F3, 31E0
    "0001C8930A0967FEFF": ("FAN", "32", "2020-10-06", "VMZ-15V13"),  # .          *Zone Valve*          1298, 22F3, 31E0
    "0001C893090867FEFF": ("FAN", "32", "2020-06-19", "VMZ-15V13"),  # .          *Zone Valve*          1298, 22F3, 31E0
}
# fmt: on

__DEVICE_INFO: dict[str, list[str]] = {
    t: [k for k, v in __DEVICE_INFO_RAW.items() if v[1] == t]
    for t in sorted(dict.fromkeys(v[1] for v in __DEVICE_INFO_RAW.values()))
}  # convert to {dev_type: [signature, ...]}


def check_signature(dev_type: str, signature: str) -> None:
    """Raise ValueError if the device type is not known to have the signature.

    e.g. '01' can imply '0002FF0119FFFFFFFF', but not '0001C8820C006AFEFF'
    """
    if not (sigs := __DEVICE_INFO.get(dev_type)) or signature not in sigs:
        raise ValueError(
            f"device type {dev_type} not known to have signature: {signature}"
        )


########################################################################################
# from: https://www.airios.eu/products

# BRDG - RF interface to RS485/Ethernet: for heating and ventilation.
# VMD - Heat recovery unit
# VMC - Mechanical extraction: To integrate in a single fan system
# VMI - User interface with display
# VMN -
# VMS - Sensors platform: CO2, humidity and temperature (and PIR?)

# BRDG-02A55   - Fan of some description
# BRDG-02EM23  - Vasco
# BRDG-02JAS01 - PIV - Nuaire DriMaster PIV
# BRDG-02M11   - Itho Honeywell RF-repeater

# CCU-12T20    - RFS - RF gateway (spIDer, Fifthplay Home Area Manager)
# CVE-RF       - FAN -
# HRA82        -
# VMC-15RPS34  -
# VMC-15RP01   - Orcon unit (senseair.com)
# VMC-17RP01   - Vasco C400RF (fan)

# VMD-15RMS64  - FAN - Orcon HRC-350 (Ventiline) / Orcon MVS 15RHB
# VMD-15RMS86  -
# VMD-17RPS01  -

# VMI-15WSJ53  - REM - Orcon HRC Interactive/Display 15RF
# VMI-15MC01   - REM - Orcon 15RF with integrated CO2

# VMN-15LF01   - REM - Orcon 15RF 6 button remote
# VMN-23LM33   - REM?
# VMN-23LMH23  - REM - 4 button RF Switch

# VMS-02J52    - ???
# VMS-02MC05   - CO2 -
# VMS-15C16    - CO2 - CO2 Sensor (no remote)
# VMS-12C39    - CO2 - CO2 Sensor, incl. integrated control, PIR?
# VMS-15CM17   - CO2 - CO2 Sensor
# VMS-17C01    -
# VMS-17HB01   -
# VMS-23C33    - CO2 - CO2 Sensor (no PIR) (e.g. Nuaire DRI-ECO-CO2)
# VMS-23HB33   - HUM - RH/Temp Sensor      (e.g. Nuaire DRI-ECO-RH)

# VMZ-15V13    - Itho Zone Valve (like a FAN?)

# MVS-15RHB    - FAN - Orcon Smartline FAN (incl. Moisture sensor and transmitter)


# CVD coupled ventilation system (device)
# CVE coupled ventilation system (equipment)
# DCV demand controlled ventilation
# IAQ indoor air quality
# HRA
# RFT - RF
# HRU heat recovery unit (MVHR), aka WTW (in. dutch)


# manufacturer group:  0001
# manufacturer sub_id: C8
# product id:          95/7D/50/51/8D/etc.
__ORCON_WIP = {
    "0001C84F": ("VMD-02RPS54", ""),
    "0001C850": ("VMS-15C16  ", "CO2 Room sensor"),
    "0001C851": ("VMS-15CM17 ", "CO2 Control sensor"),
    "0001C87D": ("VMD-15RMS64", "HRC-EcoMax/Comfort (2018-2019)"),
    "0001C88C": ("VMD-02RPS14", ""),
    "0001C88D": ("           ", "CO2 Built-in control sensor"),
    "0001C88E": ("VMD-02RPS66", ""),
    "0001C88F": ("VMD-02RPS07", ""),
    "0001C892": ("VMD-02RPS78", ""),
    "0001C895": ("VMD-15RMS86", "HRC-EcoSmart/Comfort, HRC-EcoMax/Comfort (from 2021)"),
    "0001C897": ("VMD-02RMS37", ""),
}

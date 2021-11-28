#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - RAMSES-II compatible Packet processor."""

# incl. date_1. NB: date_2 can vary, and _unknown_1 can vary for R8810A
DEVICE_INFO = {
    "0002FF0119FFFFFFFF": ("EVO", "01", "2014-01-16", "EvoTouch Colour"),
    "0002FF0163FFFFFFFF": ("EVO", "01", "2013-08-01", "Evo Color"),
    "0002FFFF17FFFFFFFF": ("EVO", "01", "2012-05-11", "IONA RAI Prototype"),
    "0003FF0203FFFF0001": ("UFC", "02", "2017-11-06", "HCE80 V3.10 061117"),
    "0002FF0412FFFFFFFF": ("TRV", "04", "2014-03-13", "HR92 Radiator Ctrl."),
    "0002FF050BFFFFFFFF": ("TRV", "04", "2017-03-07", "HR91 Radiator Ctrl."),
    "0001C8810B0700FEFF": ("OTB", "10", "2019-08-20", "R8820"),
    "0002FF0A0CFFFFFFFF": ("OTB", "10", "2014-07-31", "R8810A Bridge"),
    "0002FF1E01FFFFFFFF": ("RFG", "30", "2013-12-04", "Internet Gateway"),
    "0002FF1E03FFFFFFFF": ("RFG", "30", "2017-04-21", "Internet Gateway"),
    "0001C8380A0100F1FF": ("RND", "34", "2014-11-03", "T87RF2025"),
    "0001C8380F0100F1FF": ("RND", "34", "2017-05-03", "T87RF2025"),
    #
    "0002FF0802FFFFFFFE": ("JIM", "08", "2017-11-10", "Jasper EIM"),
    "0002FF1F02FFFFFFFF": ("JST", "31", "2016-08-04", "Jasper Stat TXXX"),
    #
    "0001001B221201FEFF": ("HVC", "20", "2015-05-12", "CVE-RF"),
    "0001001B271501FEFF": ("HVC", "20", "2016-11-03", "CVE-RF"),
    "0001001B281501FEFF": ("HVC", "20", "2016-11-11", "CVE-RF"),
    "0001001B2E1901FEFF": ("HVC", "37", "2017-11-29", "CVE-RF"),
    "0001001B311901FEFF": ("HVC", "37", "2018-05-14", "CVE-RF"),
    "0001001B361B01FEFF": ("HVC", "37", "2019-04-11", "CVE-RF"),
    "0001001B381B01FEFF": ("HVC", "37", "2020-02-14", "CVE-RF"),
    "0001C83A0F0866FFFF": ("HVC", "32", "0000-00-00", "VMD-17RPS01"),  # 31D9, 31DA
    "0001C8820C006AFEFF": ("HVC", "18", "2019-08-20", "HRA82"),  # NOTE: is 18:
    "0001C8950B0A67FEFF": ("HVC", "32", "2021-01-21", "VMD-15RMS86"),
    "0001C90011006CFEFF": ("HVC", "30", "2016-09-09", "BRDG-02JAS01"),  # NOTE: is: 30:
    #
    "000100140C06010000": ("VCE", "20", "0000-00-00", ""),  # 31D9 only?
    "0001001B190B010000": ("VCE", "20", "0000-00-00", ""),  # 31D9 only?
    "0001C8260D0467FFFF": ("xxx", "29", "0000-00-00", "VMC-15RP01"),  # 31D9 only?
    "0001C827070167FFFF": ("xxx", "29", "0000-00-00", "VMN-15LF01"),  # 10E0 only!
    #
    "00010028080101FEFF": ("C02", "37", "2019-04-29", "VMS-12C39"),  # 1298
    "0001C822060166FEFF": ("C02", "37", "2016-12-22", "VMS-17C01"),  # 1298, 31E0
    "0001C825050266FFFF": ("HUM", "29", "2017-04-19", "VMS-17HB01"),  # 12A0, 31E0
    "0001C85701016CFFFF": ("C02", "32", "2016-06-17", "VMS-23C33"),  # 1298, 31E0
    "0001C85802016CFFFF": ("HUM", "32", "2016-07-12", "VMS-23HB33"),  # 12A0, 31E0
    "0001C85803016CFFFF": ("HUM", "32", "2016-09-12", "VMS-23HB33"),  # 12A0, 31E0
}

# VMN-23LMH23 - 4 button RF Switch
# VMS-23C33   - CO2 Sensor
# VMS-23HB33  - RH/Temp Sensor
# VMS-15CM17  - CO2 Sensor
# VMC-15RP01  - Orcon unit (senseair.com)

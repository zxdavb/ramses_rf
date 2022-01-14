#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - RAMSES-II compatible Packet processor."""

# incl. date_1. NB: date_2 can vary, and _unknown_1 can vary for R8810A
_DEVICE_INFO = {
    "0002FF0119FFFFFFFF": ("EVO", "01", "2014-01-16", "EvoTouch Colour"),
    # ATC928-G3-0xx Evo Mk3 - EvoTouch Colour (WiFi, 12 zones)
    "0002FF0163FFFFFFFF": ("EVO", "01", "2013-08-01", "Evo Color"),
    # ATP928-G2-080 Evo Mk2 - Color (no WiFi)
    "0002FFFF17FFFFFFFF": ("EVO", "01", "2012-05-11", "IONA RAI Prototype"),
    # ATC928-G1-000 Evo Mk1 - Monochrone (?prototype, 8 zones)
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
    "000100140C06010000": ("VCE", "20", "0000-00-00", ""),  # 31D9 only?
    "0001001B190B010000": ("VCE", "20", "0000-00-00", ""),  # 31D9 only?
    "0001001B221201FEFF": ("HVC", "20", "2015-05-12", "CVE-RF"),
    "0001001B271501FEFF": ("FAN", "20", "2016-11-03", "CVE-RF"),
    "0001001B281501FEFF": ("FAN", "20", "2016-11-11", "CVE-RF"),
    "0001001B2E1901FEFF": ("FAN", "37", "2017-11-29", "CVE-RF"),
    "0001001B311901FEFF": ("FAN", "37", "2018-05-14", "CVE-RF"),
    "0001001B361B01FEFF": ("FAN", "37", "2019-04-11", "CVE-RF"),
    "0001001B381B01FEFF": ("FAN", "37", "2020-02-14", "CVE-RF"),
    "00010028080101FEFF": ("CO2", "37", "2019-04-29", "VMS-12C39"),  # 1298
    "0001C822060166FEFF": ("CO2", "37", "2016-12-22", "VMS-17C01"),  # 1298, 31E0
    "0001C825050266FFFF": ("HUM", "29", "2017-04-19", "VMS-17HB01"),  # 12A0, 31E0
    "0001C8260D0467FFFF": ("FAN", "29", "0000-00-00", "VMC-15RP01"),  # 31D9 only?
    "0001C827050167FFFF": ("SWI", "29", "0000-00-00", "VMN-15LF01"),
    "0001C827070167FFFF": ("SWI", "29", "0000-00-00", "VMN-15LF01"),
    "0001C827090167FFFF": ("SWI", "29", "2019-02-13", "VMN-15LF01"),
    "0001C83A0F0866FFFF": ("FAN", "32", "0000-00-00", "VMD-17RPS01"),  # 31D9, 31DA
    "0001C85701016CFFFF": ("CO2", "32", "2016-06-17", "VMS-23C33"),  # 1298, 31E0
    "0001C85802016CFFFF": ("HUM", "32", "2016-07-12", "VMS-23HB33"),  # 12A0, 31E0
    "0001C85803016CFFFF": ("HUM", "32", "2016-09-12", "VMS-23HB33"),  # 12A0, 31E0
    "0001C8820C006AFEFF": ("FAN", "18", "2019-08-20", "HRA82"),  # NOTE: is 18:!!
    "0001C8950B0A67FEFF": ("FAN", "32", "2021-01-21", "VMD-15RMS86"),
    "0001C90011006CFEFF": ("FAN", "30", "2016-09-09", "BRDG-02JAS01"),  # NOTE: is 30:!
}

_DEVICE_INFO = {
    t: [k for k, v in _DEVICE_INFO.items() if v[1] == t]
    for t in sorted(dict.fromkeys(v[1] for v in _DEVICE_INFO.values()))
}


def check_signature(dev_type, signature) -> None:
    if signatures := _DEVICE_INFO.get(dev_type):
        assert signature in signatures, f"{dev_type}: {signature}"
    else:
        assert False, f"{dev_type}: {signature}"


# VMN-23LMH23 - 4 button RF Switch
# VMS-23C33   - CO2 Sensor
# VMS-23HB33  - RH/Temp Sensor
# VMS-15CM17  - CO2 Sensor
# VMC-15RP01  - Orcon unit (senseair.com)


# if msg.src.type == "01":
#     assert payload[2:20] in (
#         "0002FF0119FFFFFFFF",  # ATC928-G3-0xx Evo Mk3 - EvoTouch Colour (WiFi, 12 zones)
#         "0002FF0163FFFFFFFF",  # ATP928-G2-080 Evo Mk2 - Color (no WiFi)
#         "0002FFFF17FFFFFFFF",  # ATC928-G1-000 Evo Mk1 - Monochrone (?prototype, 8 zones)
#     ), f"01: {payload[2:20]}"
# elif msg.src.type == "02":
#     assert payload[2:20] in (
#         "0003FF0203FFFF0001",  # HCE80 V3.10 061117
#     ), f"02: {payload[2:20]}"
# elif msg.src.type == "04":
#     assert payload[2:20] in (
#         "0002FF0412FFFFFFFF",  # HR92 Radiator Ctrl.
#         "0002FF050BFFFFFFFF",  # HR91 Radiator Ctrl.
#     ), f"04: {payload[2:20]}"
# elif msg.src.type == "08":
#     assert payload[2:20] in (
#         "0002FF0802FFFFFFFE",  # Jasper EIM (non-evohome)
#     ), f"08: {payload[2:20]}"
# elif msg.src.type == "10":
#     assert payload[2:20] in (
#         "0001C8810B0700FEFF",  # R8820A
#         "0002FF0A0CFFFFFFFF",  # R8810A
#     ), f"10: {payload[2:20]}"
# elif msg.src.type == "18":
#     assert payload[2:20] in (
#         "0001C8820C006AFEFF",  # HRA82 (Orcon MVHR?)
#     ), f"18: {payload[2:20]}"
# elif msg.src.type == "20":
#     assert payload[2:20] in (
#         "000100140C06010000",  # n/a
#         "0001001B190B010000",  # n/a
#         "0001001B221201FEFF",  # CVE-RF
#         "0001001B271501FEFF",  # CVE-RF
#         "0001001B281501FEFF",  # CVE-RF
#     ), f"20: {payload[2:20]}"
# elif msg.src.type == "29":
#     assert payload[2:20] in (
#         "0001C825050266FFFF",  # VMS-17HB01
#         "0001C8260D0467FFFF",  # VMC-15RP01
#         "0001C827050167FFFF",  # VMN-15LF01  # TODO: a corrupt packet?
#         "0001C827070167FFFF",  # VMN-15LF01  # TODO: a corrupt packet?
#     ), f"29: {payload[2:20]}"
# elif msg.src.type == "30":
#     assert payload[2:20] in (
#         "0001C90011006CFEFF",  # BRDG-02JAS01 (fan, PIV)
#         "0002FF1E01FFFFFFFF",  # Internet Gateway
#         "0002FF1E03FFFFFFFF",  # Internet Gateway
#     ), f"30: {payload[2:20]}"
# elif msg.src.type == "31":
#     assert payload[2:20] in (
#         "0002FF1F02FFFFFFFF",  # Jasper Stat TXXX
#     ), f"31: {payload[2:20]}"
# elif msg.src.type == "32":
#     # VMN-23LMH23 (switch, 4-button)
#     assert payload[2:20] in (
#         "0001C83A0F0866FFFF",  # VMD-17RPS01
#         "0001C85701016CFFFF",  # VMS-23C33   (sensor, CO2)
#         "0001C85802016CFFFF",  # VMS-23HB33  (sensor, RH/temp)
#         "0001C85803016CFFFF",  # VMS-23HB33  (sensor, RH/temp)
#         "0001C8950B0A67FEFF",  # VMD-15RMS86 (fan, Orcon HRC 500)
#     ), f"32: {payload[2:20]}"
# elif msg.src.type == "34":
#     assert payload[2:20] in (
#         "0001C8380A0100F1FF",  # T87RF2025
#         "0001C8380F0100F1FF",  # T87RF2025
#     ), f"34: {payload[2:20]}"
# elif msg.src.type == "37":
#     assert payload[2:20] in (
#         "0001001B2E1901FEFF",  # CVE-RF
#         "0001001B311901FEFF",  # CVE-RF
#         "0001001B361B01FEFF",  # CVE-RF
#         "0001001B381B01FEFF",  # CVE-RF
#         "00010028080101FEFF",  # VMS-12C39
#         "0001C822060166FEFF",  # VMS-17C01
#     ), f"37: {payload[2:20]}"
# else:
#     assert False, f"xx: {payload[2:20]}"

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

HVAC devices.
"""

import logging
from symtable import Class
from typing import Optional

from .const import (
    DEV_TYPE,
    FAN_MODE,
    SZ_AIR_QUALITY,
    SZ_AIR_QUALITY_BASE,
    SZ_BOOST_TIMER,
    SZ_BYPASS_POSITION,
    SZ_CO2_LEVEL,
    SZ_EXHAUST_FAN_SPEED,
    SZ_EXHAUST_FLOW,
    SZ_EXHAUST_TEMPERATURE,
    SZ_FAN_INFO,
    SZ_INDOOR_HUMIDITY,
    SZ_INDOOR_TEMPERATURE,
    SZ_OUTDOOR_HUMIDITY,
    SZ_OUTDOOR_TEMPERATURE,
    SZ_POST_HEAT,
    SZ_PRE_HEAT,
    SZ_REMAINING_TIME,
    SZ_SPEED_CAP,
    SZ_SUPPLY_FAN_SPEED,
    SZ_SUPPLY_FLOW,
    SZ_SUPPLY_TEMPERATURE,
    SZ_TEMPERATURE,
    __dev_mode__,
)
from .devices_base import BatteryState, DeviceHvac, Fakeable
from .entity_base import class_by_attr
from .protocol import Address, Message
from .protocol.command import Command
from .protocol.ramses import CODES_HVAC_ONLY

# skipcq: PY-W2000
from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
)

# skipcq: PY-W2000
from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    _0001,
    _0002,
    _0004,
    _0005,
    _0006,
    _0008,
    _0009,
    _000A,
    _000C,
    _000E,
    _0016,
    _0100,
    _0150,
    _01D0,
    _01E9,
    _0404,
    _0418,
    _042F,
    _0B04,
    _1030,
    _1060,
    _1081,
    _1090,
    _1098,
    _10A0,
    _10B0,
    _10E0,
    _10E1,
    _1100,
    _11F0,
    _1260,
    _1280,
    _1290,
    _1298,
    _12A0,
    _12B0,
    _12C0,
    _12C8,
    _12F0,
    _1300,
    _1F09,
    _1F41,
    _1FC9,
    _1FCA,
    _1FD0,
    _1FD4,
    _2249,
    _22C9,
    _22D0,
    _22D9,
    _22F1,
    _22F3,
    _2309,
    _2349,
    _2389,
    _2400,
    _2401,
    _2410,
    _2420,
    _2D49,
    _2E04,
    _2E10,
    _30C9,
    _3110,
    _3120,
    _313F,
    _3150,
    _31D9,
    _31DA,
    _31E0,
    _3200,
    _3210,
    _3220,
    _3221,
    _3223,
    _3B00,
    _3EF0,
    _3EF1,
    _PUZZ,
)

DEV_MODE = __dev_mode__  # and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class RfsGateway(DeviceHvac):  # RFS: (spIDer gateway)
    """The HGI80 base class."""

    _SLUG: str = DEV_TYPE.RFS

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.ctl = None
        self._child_id = "hv"  # NOTE: domain_id
        self.tcs = None


class HvacHumidity(BatteryState, DeviceHvac):  # HUM: I/12A0
    """The Sensor class for a humidity sensor.

    The cardinal code is 12A0.
    """

    _SLUG: str = DEV_TYPE.HUM

    REL_HUMIDITY = "indoor_humidity"  # percentage (0.0-1.0)
    TEMPERATURE = SZ_TEMPERATURE  # celsius
    DEWPOINT_TEMP = "dewpoint_temp"  # celsius

    @property
    def indoor_humidity(self) -> Optional[float]:
        return self._msg_value(_12A0, key=self.REL_HUMIDITY)

    @property
    def temperature(self) -> Optional[float]:
        return self._msg_value(_12A0, key=self.TEMPERATURE)

    @property
    def dewpoint_temp(self) -> Optional[float]:
        return self._msg_value(_12A0, key=self.DEWPOINT_TEMP)

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.REL_HUMIDITY: self.indoor_humidity,
            self.TEMPERATURE: self.temperature,
            self.DEWPOINT_TEMP: self.dewpoint_temp,
        }


class HvacCarbonDioxide(DeviceHvac):  # CO2: I/1298
    """The Sensor class for a CO2 sensor.

    The cardinal code is 1298.
    """

    # 22:42:22.889 050  I --- 37:154011 --:------ 37:154011 1FC9 030 0031E096599B 00129896599B 002E1096599B 0110E096599B 001FC996599B              # CO2, idx|10E0 == 01
    # 22:42:22.995 083  W --- 28:126620 37:154011 --:------ 1FC9 012 0031D949EE9C 0031DA49EE9C                                                     # FAN, BRDG-02A55
    # 22:42:23.014 050  I --- 37:154011 28:126620 --:------ 1FC9 001 00                                                                            # CO2, incl. integrated control, PIR
    # 22:42:23.876 050  I --- 37:154011 63:262142 --:------ 10E0 038 0000010028090101FEFFFFFFFFFF140107E5564D532D31324333390000000000000000000000  # VMS-12C39, oem_code == 01

    _SLUG: str = DEV_TYPE.CO2

    @property
    def co2_level(self) -> Optional[float]:
        return self._msg_value(_1298, key="co2_level")

    @property
    def status(self) -> dict:
        return {
            **super().status,
            "co2_level": self.co2_level,
        }


class HvacSwitch(BatteryState, Fakeable, DeviceHvac):  # SWI: I/22F[13]
    """The FAN (switch) class, such as a 4-way switch.

    The cardinal codes are 22F1, 22F3.
    """

    # 11:19:47.199 074  I --- 29:156898 63:262142 --:------ 1FC9 024 001FC97664E2 0022F17664E2 0022F37664E2 6710E07664E2         # SWI, idx|10E0 == 67
    # 11:19:47.212 059  W --- 32:132125 29:156898 --:------ 1FC9 012 0031D982041D 0031DA82041D                                   # FAN, is: Orcon HRC500
    # 11:19:47.275 074  I --- 29:156898 32:132125 --:------ 1FC9 001 00                                                          # SWI, is: Orcon RF15
    # 11:19:47.348 074  I --- 29:156898 63:262142 --:------ 10E0 029 000001C827050167FFFFFFFFFFFFFFFFFFFF564D4E2D31354C46303100  # VMN-15LF01, oem_code == 67

    # every /15
    # RQ --- 32:166025 30:079129 --:------ 31DA 001 21
    # RP --- 30:079129 32:166025 --:------ 31DA 029 21EF00026036EF7FFF7FFF7FFF7FFF0002EF18FFFF000000EF7FFF7FFF

    _SLUG: str = DEV_TYPE.SWI

    @property
    def fan_rate(self) -> Optional[str]:
        return self._msg_value(_22F1, key="rate")

    @fan_rate.setter
    def fan_rate(self, rate) -> None:
        if not self._faked:
            raise RuntimeError(f"Can't set value for {self} (Faking is not enabled)")
        for _ in range(3):
            self._send_cmd(
                Command.set_fan_rate(self._ctl, int(4 * rate), 4, src_id=self.id)
            )

    @property
    def fan_mode(self) -> Optional[str]:
        return self._msg_value(_22F1, key=FAN_MODE)

    @property
    def boost_timer(self) -> Optional[int]:
        return self._msg_value(_22F3, key=SZ_BOOST_TIMER)

    @property
    def status(self) -> dict:
        return {
            **super().status,
            FAN_MODE: self.fan_mode,
            SZ_BOOST_TIMER: self.boost_timer,
        }


class HvacVentilator(DeviceHvac):  # FAN: RP/31DA, I/31D[9A]
    """The Ventilation class.

    The cardinal code are 31D9, 31DA.  Signature is RP/31DA.
    """

    # Itho Daalderop (NL)
    # Heatrae Sadia (UK)
    # Nuaire (UK), e.g. DRI-ECO-PIV
    # Orcon/Ventiline

    _SLUG: str = DEV_TYPE.FAN

    @property
    def air_quality(self) -> Optional[float]:
        return self._msg_value(_31DA, key=SZ_AIR_QUALITY)

    @property
    def air_quality_base(self) -> Optional[float]:
        return self._msg_value(_31DA, key=SZ_AIR_QUALITY_BASE)

    @property
    def bypass_position(self) -> Optional[int]:
        return self._msg_value(_31DA, key=SZ_BYPASS_POSITION)

    @property
    def co2_level(self) -> Optional[int]:
        return self._msg_value(_31DA, key=SZ_CO2_LEVEL)

    @property
    def exhaust_fan_speed(self) -> Optional[float]:
        # turn self._msg_value((_31D9, _31DA), key=SZ_EXHAUST_FAN_SPEED)
        return self._msg_value((_31DA), key=SZ_EXHAUST_FAN_SPEED)

    @property
    def exhaust_flow(self) -> Optional[float]:
        return self._msg_value(_31DA, key=SZ_EXHAUST_FLOW)

    @property
    def exhaust_temperature(self) -> Optional[float]:
        return self._msg_value(_31DA, key=SZ_EXHAUST_TEMPERATURE)

    @property
    def fan_info(self) -> Optional[str]:
        return self._msg_value(_31DA, key=SZ_FAN_INFO)

    @property
    def indoor_humidity(self) -> Optional[float]:
        return self._msg_value(_31DA, key=SZ_INDOOR_HUMIDITY)

    @property
    def indoor_temperature(self) -> Optional[float]:
        return self._msg_value(_31DA, key=SZ_INDOOR_TEMPERATURE)

    @property
    def outdoor_humidity(self) -> Optional[float]:
        return self._msg_value(_31DA, key=SZ_OUTDOOR_HUMIDITY)

    @property
    def outdoor_temperature(self) -> Optional[float]:
        return self._msg_value(_31DA, key=SZ_OUTDOOR_TEMPERATURE)

    @property
    def post_heat(self) -> Optional[int]:
        return self._msg_value(_31DA, key=SZ_POST_HEAT)

    @property
    def pre_heat(self) -> Optional[int]:
        return self._msg_value(_31DA, key=SZ_PRE_HEAT)

    @property
    def remaining_time(self) -> Optional[int]:
        return self._msg_value(_31DA, key=SZ_REMAINING_TIME)

    @property
    def speed_cap(self) -> Optional[int]:
        return self._msg_value(_31DA, key=SZ_SPEED_CAP)

    @property
    def supply_fan_speed(self) -> Optional[float]:
        return self._msg_value(_31DA, key=SZ_SUPPLY_FAN_SPEED)

    @property
    def supply_flow(self) -> Optional[float]:
        return self._msg_value(_31DA, key=SZ_SUPPLY_FLOW)

    @property
    def supply_temperature(self) -> Optional[float]:
        return self._msg_value(_31DA, key=SZ_SUPPLY_TEMPERATURE)

    @property
    def status(self) -> dict:
        return {
            **super().status,
            SZ_EXHAUST_FAN_SPEED: self.fan_rate,
            **(
                {
                    k: v
                    for k, v in self._msgs[_31D9].payload.items()
                    if k != SZ_EXHAUST_FAN_SPEED
                }
                if _31D9 in self._msgs
                else {}
            ),
            **(
                {
                    k: v
                    for k, v in self._msgs[_31DA].payload.items()
                    if k != SZ_EXHAUST_FAN_SPEED
                }
                if _31DA in self._msgs
                else {}
            ),
        }


HVAC_CLASS_BY_SLUG = class_by_attr(__name__, "_SLUG")  # e.g. HUM: HvacHumidity

_HVAC_VC_PAIR_BY_CLASS = {
    DEV_TYPE.CO2: ((I_, _1298),),
    DEV_TYPE.FAN: ((I_, _31D9), (I_, _31DA), (RP, _31DA)),
    DEV_TYPE.HUM: ((I_, _12A0),),
    DEV_TYPE.SWI: ((I_, _22F1), (I_, _22F3)),
}
_HVAC_KLASS_BY_VC_PAIR = {t: k for k, v in _HVAC_VC_PAIR_BY_CLASS.items() for t in v}


def class_dev_hvac(
    dev_addr: Address, *, msg: Message = None, eavesdrop: bool = False
) -> Class:
    """Return a device class, but only if the device must be from the HVAC group.

    May return a base clase, DeviceHvac, which will need promotion.
    """

    if not eavesdrop:
        raise TypeError(f"No HVAC class for: {dev_addr} (no eavesdropping)")

    if msg is None:
        raise TypeError(f"No HVAC class for: {dev_addr} (no msg)")

    if klass := _HVAC_KLASS_BY_VC_PAIR.get((msg.verb, msg.code)):
        return HVAC_CLASS_BY_SLUG[klass]

    if msg.code in CODES_HVAC_ONLY:
        return DeviceHvac

    raise TypeError(f"No HVAC class for: {dev_addr} (insufficient meta-data)")


if DEV_MODE:
    assert len(_HVAC_KLASS_BY_VC_PAIR) == (
        sum(len(v) for v in _HVAC_VC_PAIR_BY_CLASS.values())
    ), "Coding error: There is a duplicate verb/code pair"

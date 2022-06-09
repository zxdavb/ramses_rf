#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - discovery scripts."""

# Beware, none of this is reliable - it is all subject to random change
# However, these serve as examples how to us eteh other modules

import asyncio
import json
import logging
import re

from .const import SZ_SCHEDULE, SZ_ZONE_IDX, __dev_mode__
from .protocol import CODES_SCHEMA, Command, ExpiredCallbackError, Priority
from .protocol.opentherm import OTB_MSG_IDS

# skipcq: PY-W2000
from .protocol import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
)

# skipcq: PY-W2000
from .protocol import (  # noqa: F401, isort: skip, pylint: disable=unused-import
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

EXEC_CMD = "exec_cmd"
GET_FAULTS = "get_faults"
GET_SCHED = "get_schedule"
SET_SCHED = "set_schedule"

EXEC_SCR = "exec_scr"
SCAN_DISC = "scan_disc"
SCAN_FULL = "scan_full"
SCAN_HARD = "scan_hard"
SCAN_XXXX = "scan_xxxx"

# DEVICE_ID_REGEX = re.compile(DEVICE_ID_REGEX.ANY)

QOS_DEFAULT = {"priority": Priority.LOW, "retries": 0}
QOS_DEFAULT_HIGH = {"priority": Priority.HIGH, "retries": 3}
QOS_DEFAULT_LOW = {"priority": Priority.LOW, "retries": 3}
QOS_DEFAULT_SCAN = {"priority": Priority.LOW, "retries": 0, "disable_backoff": True}

DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


def script_decorator(fnc):
    def wrapper(gwy, *args, **kwargs):

        gwy.send_cmd(Command._puzzle(message="Script begins:", qos=QOS_DEFAULT_HIGH))

        result = fnc(gwy, *args, **kwargs)

        gwy.send_cmd(Command._puzzle(message="Script done.", qos=QOS_DEFAULT_LOW))

        return result

    return wrapper


def spawn_scripts(gwy, **kwargs) -> list[asyncio.Task]:

    tasks = []

    if kwargs.get(EXEC_CMD):
        tasks += [gwy._loop.create_task(exec_cmd(gwy, **kwargs))]

    if kwargs.get(GET_FAULTS):
        tasks += [gwy._loop.create_task(get_faults(gwy, kwargs[GET_FAULTS]))]

    elif kwargs.get(GET_SCHED) and kwargs[GET_SCHED][0]:
        tasks += [gwy._loop.create_task(get_schedule(gwy, *kwargs[GET_SCHED]))]

    elif kwargs.get(SET_SCHED) and kwargs[SET_SCHED][0]:
        tasks += [gwy._loop.create_task(set_schedule(gwy, *kwargs[SET_SCHED]))]

    elif kwargs.get(EXEC_SCR):
        script = SCRIPTS.get(f"{kwargs[EXEC_SCR][0]}")
        if script is None:
            _LOGGER.warning(f"Script: {kwargs[EXEC_SCR][0]}() - unknown script")
        else:
            _LOGGER.info(f"Script: {kwargs[EXEC_SCR][0]}().- starts...")
            tasks += [gwy._loop.create_task(script(gwy, kwargs[EXEC_SCR][1]))]

    gwy._tasks.extend(tasks)
    return tasks


async def exec_cmd(gwy, **kwargs):

    # if not kwargs.get(EXEC_CMD):  # e.g. "RQ 01:145038 1F09 00"
    #     _LOGGER.warning("Execute: Command is invalid: '%s'", kwargs)
    #     return

    cmd = Command.from_str(kwargs[EXEC_CMD], qos=QOS_DEFAULT_HIGH)

    await gwy.async_send_cmd(cmd)


async def periodic(gwy, cmd, count=1, interval=None):
    async def _periodic():
        await asyncio.sleep(interval)
        gwy.send_cmd(cmd)

    if interval is None:
        interval = 0 if count == 1 else 60

    if count <= 0:
        while True:
            await _periodic()
    else:
        for _ in range(count):
            await _periodic()


async def get_faults(gwy, ctl_id: str, start=0, limit=0x3F):
    ctl = gwy.get_device(ctl_id)

    try:
        await ctl.tcs.get_faultlog(start=start, limit=limit)  # 0418
    except ExpiredCallbackError as exc:
        _LOGGER.error("get_faults(): Function timed out: %s", exc)


async def get_schedule(gwy, ctl_id: str, zone_idx: str) -> None:
    zone = gwy.get_device(ctl_id).tcs.get_htg_zone(zone_idx)

    try:
        await zone.get_schedule()
    except ExpiredCallbackError as exc:
        _LOGGER.error("get_schedule(): Function timed out: %s", exc)


async def set_schedule(gwy, ctl_id, schedule) -> None:
    schedule = json.load(schedule)
    zone_idx = schedule[SZ_ZONE_IDX]

    zone = gwy.get_device(ctl_id).tcs.get_htg_zone(zone_idx)

    try:
        await zone.set_schedule(schedule[SZ_SCHEDULE])  # 0404
    except ExpiredCallbackError as exc:
        _LOGGER.error("set_schedule(): Function timed out: %s", exc)


async def script_bind_req(gwy, dev_id: str):
    gwy.get_device(dev_id)._make_fake(bind=True)


async def script_bind_wait(gwy, dev_id: str, code=_2309, idx="00"):
    gwy.get_device(dev_id)._make_fake(bind=True, code=code, idx=idx)


def script_poll_device(gwy, dev_id) -> list:
    _LOGGER.warning("poll_device() invoked...")

    tasks = []

    for code in (_0016, _1FC9):
        cmd = Command(RQ, code, "00", dev_id, **QOS_DEFAULT)
        tasks.append(gwy._loop.create_task(periodic(gwy, cmd, count=0)))

    gwy._tasks.extend(tasks)
    return tasks


@script_decorator
async def script_scan_disc(gwy, dev_id: str):
    _LOGGER.warning("scan_quick() invoked...")

    gwy.get_device(dev_id)._discover()  # discover_flag=Discover.DEFAULT)


@script_decorator
async def script_scan_full(gwy, dev_id: str):
    _LOGGER.warning("scan_full() invoked - expect a lot of Warnings")

    qos = {"priority": Priority.DEFAULT, "retries": 5}
    gwy.send_cmd(Command(RQ, _0016, "0000", dev_id, **qos))

    qos = {"priority": Priority.DEFAULT, "retries": 1}
    for code in sorted(CODES_SCHEMA):
        if code == _0005:
            for zone_type in range(20):  # known up to 18
                gwy.send_cmd(Command(RQ, code, f"00{zone_type:02X}", dev_id, **qos))

        elif code == _000C:
            for zone_idx in range(16):  # also: FA-FF?
                gwy.send_cmd(Command(RQ, code, f"{zone_idx:02X}00", dev_id, **qos))

        elif code == _0016:
            continue

        # elif code in (_01D0, _01E9):
        #     for zone_idx in ("00", "01", "99", FC, FF):
        #         gwy.send_cmd(Command(W_, code, f"{zone_idx}00", dev_id, **qos))
        #         gwy.send_cmd(Command(W_, code, f"{zone_idx}03", dev_id, **qos))

        elif code == _0404:
            gwy.send_cmd(Command.get_schedule_fragment(dev_id, "HW", 0, 0, **qos))
            gwy.send_cmd(Command.get_schedule_fragment(dev_id, "00", 0, 0, **qos))

        elif code == _0418:
            for log_idx in range(2):
                gwy.send_cmd(Command.get_system_log_entry(dev_id, log_idx, **qos))

        elif code == _1100:
            gwy.send_cmd(Command.get_tpi_params(dev_id, **qos))

        elif code == _2E04:
            gwy.send_cmd(Command.get_system_mode(dev_id, **qos))

        elif code == _3220:
            for data_id in (0, 3):  # these are mandatory READ_DATA data_ids
                gwy.send_cmd(Command.get_opentherm_data(dev_id, data_id, **qos))

        elif code == _PUZZ:
            continue

        elif (
            code in CODES_SCHEMA
            and RQ in CODES_SCHEMA[code]
            and re.match(CODES_SCHEMA[code][RQ], "00")
        ):
            gwy.send_cmd(Command(RQ, code, "00", dev_id, **qos))

        else:
            gwy.send_cmd(Command(RQ, code, "0000", dev_id, **qos))

    # these are possible/difficult codes
    qos = {"priority": Priority.DEFAULT, "retries": 2}
    for code in (_0150, _2389):
        gwy.send_cmd(Command(RQ, code, "0000", dev_id, **qos))


@script_decorator
async def script_scan_hard(gwy, dev_id: str):
    _LOGGER.warning("scan_hard() invoked - expect some Warnings")

    # def callback(msg) -> None:
    #     nonlocal code

    #     if (code := code + 1) < 0x4000:
    #         cmd = Command(RQ, f"{code:04X}", "0000", dev_id, **QOS_DEFAULT_SCAN)
    #         # gwy.msg_protocol.send_data(cmd, callback=callback)
    #         gwy.send_cmd(cmd, callback=callback)

    # code = 0x0000
    # callback(None)

    for code in range(0x4000):
        gwy.send_cmd(Command(RQ, f"{code:04X}", "0000", dev_id, **QOS_DEFAULT_SCAN))
        await asyncio.sleep(1)


@script_decorator
async def script_scan_001(gwy, dev_id: str):
    _LOGGER.warning("scan_001() invoked - expect a lot of nonsense")

    qos = {"priority": Priority.LOW, "retries": 3}
    for idx in range(0x10):
        gwy.send_cmd(Command(W_, _000E, f"{idx:02X}0050", dev_id, **qos))
        gwy.send_cmd(Command(RQ, _000E, f"{idx:02X}00C8", dev_id, **qos))


@script_decorator
async def script_scan_002(gwy, dev_id: str):
    _LOGGER.warning("scan_002() invoked - expect a lot of nonsense")

    # Two modes, I & W, and Two contexts, zz & zz00
    message = "0000" + "".join(f"{ord(x):02X}" for x in "Hello there.") + "00"

    [
        gwy.send_cmd(Command(W_, f"{c:04X}", message, dev_id, **QOS_DEFAULT))
        for c in range(0x4000)
        if c not in CODES_SCHEMA
    ]


async def script_scan_004(gwy, dev_id: str):
    _LOGGER.warning("scan_004() invoked - expect a lot of nonsense")

    cmd = Command.get_dhw_mode(dev_id, **QOS_DEFAULT)

    return gwy._loop.create_task(periodic(gwy, cmd, count=0, interval=5))


@script_decorator
async def script_scan_otb(gwy, dev_id: str):
    _LOGGER.warning("script_scan_otb_full invoked - expect a lot of nonsense")

    qos = {"priority": Priority.LOW, "retries": 1}
    for msg_id in OTB_MSG_IDS:
        gwy.send_cmd(Command.get_opentherm_data(dev_id, msg_id, **qos))


@script_decorator
async def script_scan_otb_hard(gwy, dev_id: str):
    _LOGGER.warning("script_scan_otb_hard invoked - expect a lot of nonsense")

    for msg_id in range(0x80):
        gwy.send_cmd(Command.get_opentherm_data(dev_id, msg_id, **QOS_DEFAULT_SCAN))


@script_decorator
async def script_scan_otb_map(gwy, dev_id: str):  # Tested only upon a R8820A
    _LOGGER.warning("script_scan_otb_map invoked - expect a lot of nonsense")

    RAMSES_TO_OPENTHERM = {
        _22D9: "01",  # boiler setpoint        / ControlSetpoint
        _3EF1: "11",  # rel. modulation level  / RelativeModulationLevel
        _1300: "12",  # cv water pressure      / CHWaterPressure
        _12F0: "13",  # dhw_flow_rate          / DHWFlowRate
        _3200: "19",  # boiler output temp     / BoilerWaterTemperature
        _1260: "1A",  # dhw temp               / DHWTemperature
        _1290: "1B",  # outdoor temp           / OutsideTemperature
        _3210: "1C",  # boiler return temp     / ReturnWaterTemperature
        _10A0: "38",  # dhw params[SZ_SETPOINT] / DHWSetpoint
        _1081: "39",  # max ch setpoint        / MaxCHWaterSetpoint
    }

    for code, msg_id in RAMSES_TO_OPENTHERM.items():
        gwy.send_cmd(Command(RQ, code, "00", dev_id, **QOS_DEFAULT))
        gwy.send_cmd(Command.get_opentherm_data(dev_id, msg_id, **QOS_DEFAULT))


@script_decorator
async def script_scan_otb_ramses(gwy, dev_id: str):  # Tested only upon a R8820A
    _LOGGER.warning("script_scan_otb_ramses invoked - expect a lot of nonsense")

    CODES = (
        _042F,
        _10E0,  # device_info
        _10E1,  # device_id
        _1FD0,
        _2400,
        _2401,
        _2410,
        _2420,
        _1300,  # cv water pressure      / CHWaterPressure
        _1081,  # max ch setpoint        / MaxCHWaterSetpoint
        _10A0,  # dhw params[SZ_SETPOINT] / DHWSetpoint
        _22D9,  # boiler setpoint        / ControlSetpoint
        _1260,  # dhw temp               / DHWTemperature
        _1290,  # outdoor temp           / OutsideTemperature
        _3200,  # boiler output temp     / BoilerWaterTemperature
        _3210,  # boiler return temp     / ReturnWaterTemperature
        _0150,
        _12F0,  # dhw flow rate          / DHWFlowRate
        _1098,
        _10B0,
        _3221,
        _3223,
        _3EF0,  # rel. modulation level  / RelativeModulationLevel (also, below)
        _3EF1,  # rel. modulation level  / RelativeModulationLevel
    )  # excl. 3220

    # 3EF0 also includes:
    #  - boiler status        /
    #  - ch setpoint          /
    #  - max. rel. modulation /

    [gwy.send_cmd(Command(RQ, c, "00", dev_id, **QOS_DEFAULT)) for c in CODES]


SCRIPTS = {
    k[7:]: v for k, v in locals().items() if callable(v) and k.startswith("script_")
}

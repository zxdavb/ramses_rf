#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - discovery scripts."""

import asyncio
import json
import logging
import re
from typing import Any, List

from .protocol import RAMSES_CODES, Command, Priority
from .protocol.const import DEV_REGEX_ANY, DEVICE_TABLE, HGI_DEVICE_ID, NON_DEVICE_ID
from .protocol.exceptions import ExpiredCallbackError
from .protocol.opentherm import OTB_MSG_IDS

from .protocol import I_, RP, RQ, W_, __dev_mode__  # noqa: F401, isort: skip
from .protocol import (  # noqa: F401, isort: skip
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
    _01D0,
    _01E9,
    _0404,
    _0418,
    _042F,
    _1030,
    _1060,
    _1090,
    _10A0,
    _10E0,
    _1100,
    _1260,
    _1280,
    _1290,
    _1298,
    _12A0,
    _12B0,
    _12C0,
    _12C8,
    _1F09,
    _1F41,
    _1FC9,
    _1FD4,
    _2249,
    _22C9,
    _22D0,
    _22D9,
    _22F1,
    _22F3,
    _2309,
    _2349,
    _2D49,
    _2E04,
    _30C9,
    _3120,
    _313F,
    _3150,
    _31D9,
    _31DA,
    _31E0,
    _3220,
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

DEVICE_ID_REGEX = re.compile(DEV_REGEX_ANY)

DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


def spawn_scripts(gwy, **kwargs) -> List[asyncio.Task]:

    # this is to ensure the gateway interface has fully woken
    if not kwargs.get(EXEC_CMD) and gwy._include:
        dev_id = next(iter(gwy._include))
        qos = {"priority": Priority.HIGH, "retries": 5}
        gwy.send_cmd(Command(RQ, _0016, "00FF", dev_id, **qos))

    tasks = []

    if kwargs.get(EXEC_CMD):
        spawn_exec_cmd(gwy, **kwargs)  # TODO: wrap in a try?

    if kwargs.get(GET_FAULTS):
        tasks += [gwy._loop.create_task(get_faults(gwy, kwargs[GET_FAULTS]))]

    elif kwargs.get(GET_SCHED) and kwargs[GET_SCHED][0]:
        tasks += [gwy._loop.create_task(get_schedule(gwy, *kwargs[GET_SCHED]))]

    elif kwargs.get(SET_SCHED) and kwargs[SET_SCHED][0]:
        tasks += [gwy._loop.create_task(set_schedule(gwy, *kwargs[SET_SCHED]))]

    elif kwargs[EXEC_SCR]:
        # qos = {"priority": Priority.HIGH, "retries": 3}
        # gwy.send_cmd(Command._puzzle("00", message="Script: starts...", **qos))

        script = SCRIPTS.get(f"{kwargs[EXEC_SCR][0]}")
        if script is None:
            _LOGGER.warning(f"Script: {kwargs[EXEC_SCR][0]}() - unknown script")
        else:
            _LOGGER.info(f"Script: {kwargs[EXEC_SCR][0]}().- starts...")
            tasks += [gwy._loop.create_task(script(gwy, kwargs[EXEC_SCR][1]))]

        qos = {"priority": Priority.LOW, "retries": 3}
        gwy.send_cmd(Command._puzzle("00", message="Script: ended.", **qos))

    gwy._tasks.extend(tasks)
    return tasks


def spawn_exec_cmd(gwy, **kwargs):

    if not kwargs.get(EXEC_CMD):  # e.g. "RQ 01:145038 1F09 00"
        _LOGGER.warning("Execute: Command is invalid: '%s'", kwargs)
        return

    cmd = kwargs[EXEC_CMD].upper().split()
    if len(cmd) < 4:
        _LOGGER.warning("Execute: Command is invalid: '%s'", kwargs)
        return

    verb = cmd.pop(0)
    seqn = "---" if DEVICE_ID_REGEX.match(cmd[0]) else cmd.pop(0)
    payload = cmd.pop()[:48]
    code = cmd.pop()

    if not 0 < len(cmd) < 4:
        _LOGGER.warning("Execute: Command is invalid: '%s'", kwargs)
        return
    elif len(cmd) == 1:
        addrs = (HGI_DEVICE_ID, cmd[0], NON_DEVICE_ID)
    elif len(cmd) == 3:
        addrs = (cmd[0], cmd[1], cmd[2])
    elif cmd[0] == cmd[1]:
        addrs = (cmd[0], NON_DEVICE_ID, cmd[1])
    else:
        addrs = (cmd[0], cmd[1], NON_DEVICE_ID)

    qos = {"priority": Priority.HIGH, "retries": 3}
    try:
        kmd = Command.packet(verb, code, payload, *addrs, seqn=seqn, **qos)
    except ValueError as err:
        _LOGGER.warning("Execute: Command is invalid: '%s' (%s)", kwargs[EXEC_CMD], err)
    else:
        gwy.send_cmd(kmd)


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
    device = gwy._get_device(ctl_id, ctl_id=ctl_id)

    try:
        await device._evo.get_fault_log(start=start, limit=limit)  # 0418
    except ExpiredCallbackError as exc:
        _LOGGER.error("get_faults(): Function timed out: %s", exc)


async def get_schedule(gwy, ctl_id: str, zone_idx: str) -> None:
    zone = gwy._get_device(ctl_id, ctl_id=ctl_id)._evo._get_zone(zone_idx)

    try:
        await zone.get_schedule()
    except ExpiredCallbackError as exc:
        _LOGGER.error("get_schedule(): Function timed out: %s", exc)


async def set_schedule(gwy, ctl_id, schedule) -> None:
    schedule = json.load(schedule)
    zone_idx = schedule["zone_idx"]

    zone = gwy._get_device(ctl_id, ctl_id=ctl_id)._evo._get_zone(zone_idx)

    try:
        await zone.set_schedule(schedule["schedule"])  # 0404
    except ExpiredCallbackError as exc:
        _LOGGER.error("set_schedule(): Function timed out: %s", exc)


async def script_bind_req(gwy, dev_id: str):
    gwy._get_device(dev_id)._make_fake(bind=True)


async def script_bind_wait(gwy, dev_id: str, code=_2309, idx="00"):
    gwy._get_device(dev_id)._make_fake(bind=True, code=code, idx=idx)


def script_poll_device(gwy, dev_id) -> List[Any]:
    _LOGGER.warning("poll_device() invoked...")

    qos = {"priority": Priority.LOW, "retries": 0}
    if "poll_codes" in DEVICE_TABLE.get(dev_id[:2]):
        codes = DEVICE_TABLE[dev_id[:2]]["poll_codes"]
    else:
        codes = [_0016, _1FC9]

    tasks = []

    for code in codes:
        cmd = Command(RQ, code, "00", dev_id, **qos)
        tasks.append(gwy._loop.create_task(periodic(gwy, cmd, count=0)))

        cmd = Command(RQ, code, "0000", dev_id, **qos)
        tasks.append(gwy._loop.create_task(periodic(gwy, cmd, count=0)))

    gwy._tasks.extend(tasks)
    return tasks


async def script_scan_disc(gwy, dev_id: str):
    _LOGGER.warning("scan_quick() invoked...")

    qos = {"priority": Priority.HIGH, "retries": 3}
    gwy.send_cmd(Command._puzzle("00", message="disc scan: begins...", **qos))

    gwy._get_device(dev_id)._discover()  # discover_flag=DISCOVER_ALL)


async def script_scan_full(gwy, dev_id: str):
    _LOGGER.warning("scan_full() invoked - expect a lot of Warnings")

    qos = {"priority": Priority.HIGH, "retries": 3}
    gwy.send_cmd(Command._puzzle("00", message="full scan: begins...", **qos))

    qos = {"priority": Priority.DEFAULT, "retries": 5}
    gwy.send_cmd(Command(RQ, _0016, "0000", dev_id, **qos))

    qos = {"priority": Priority.DEFAULT, "retries": 1}
    for code in sorted(RAMSES_CODES):
        if code == _0005:
            for zone_type in range(20):  # known up to 18
                gwy.send_cmd(Command(RQ, code, f"00{zone_type:02X}", dev_id, **qos))

        elif code == _000C:
            for zone_idx in range(16):  # also: FA-FF?
                gwy.send_cmd(Command(RQ, code, f"{zone_idx:02X}00", dev_id, **qos))

        elif code == _0016:
            continue

        # elif code in (_01D0, _01E9):
        #     for zone_idx in ("00", "01", "99", "FC", "FF"):
        #         gwy.send_cmd(Command(W_, code, f"{zone_idx}00", dev_id, **qos))
        #         gwy.send_cmd(Command(W_, code, f"{zone_idx}03", dev_id, **qos))

        elif code == _0404:
            gwy.send_cmd(Command.get_schedule_fragment(dev_id, "HW", 0, **qos))
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
            code in RAMSES_CODES
            and RQ in RAMSES_CODES[code]
            and re.match(RAMSES_CODES[code][RQ], "00")
        ):
            gwy.send_cmd(Command(RQ, code, "00", dev_id, **qos))

        else:
            gwy.send_cmd(Command(RQ, code, "0000", dev_id, **qos))

    # these are possible/difficult codes
    qos = {"priority": Priority.DEFAULT, "retries": 2}
    for code in ("0150", "2389"):
        gwy.send_cmd(Command(RQ, code, "0000", dev_id, **qos))


async def script_scan_hard(gwy, dev_id: str):
    _LOGGER.warning("scan_hard() invoked - expect some Warnings")

    qos = {"priority": Priority.HIGH, "retries": 3}
    gwy.send_cmd(Command._puzzle("00", message="hard scan: begins...", **qos))

    qos = {"priority": Priority.LOW, "retries": 0}
    for code in range(0x4000):
        gwy.send_cmd(Command(RQ, f"{code:04X}", "0000", dev_id, **qos))
        await asyncio.sleep(1)


async def script_scan_001(gwy, dev_id: str):
    _LOGGER.warning("scan_001() invoked - expect a lot of nonsense")

    qos = {"priority": Priority.LOW, "retries": 3}
    for idx in range(0x10):
        gwy.send_cmd(Command(W_, _000E, f"{idx:02X}0050", dev_id, **qos))
        gwy.send_cmd(Command(RQ, _000E, f"{idx:02X}00C8", dev_id, **qos))


async def script_scan_002(gwy, dev_id: str):
    _LOGGER.warning("scan_002() invoked - expect a lot of nonsense")

    # Two modes, I and W & Two headers zz00 and zz
    message = "0000" + "".join(f"{ord(x):02X}" for x in "Hello there.") + "00"
    qos = {"priority": Priority.LOW, "retries": 0}
    [
        gwy.send_cmd(Command(W_, f"{c:04X}", message, dev_id, **qos))
        for c in range(0x4000)
        if c not in RAMSES_CODES
    ]


async def script_scan_003(gwy, dev_id: str):
    _LOGGER.warning("scan_003() invoked - expect a lot of nonsense")

    qos = {"priority": Priority.LOW, "retries": 0}
    for msg_id in range(0x100):
        gwy.send_cmd(Command.get_opentherm_data(dev_id, msg_id, **qos))


async def script_scan_004(gwy, dev_id: str):
    _LOGGER.warning("scan_004() invoked - expect a lot of nonsense")

    qos = {"priority": Priority.LOW, "retries": 0}

    cmd = Command.get_dhw_mode(dev_id, **qos)

    return gwy._loop.create_task(periodic(gwy, cmd, count=0, interval=5))


async def script_scan_005(gwy, dev_id: str):
    _LOGGER.warning("scan_005(otb, full) invoked - expect a lot of nonsense")

    qos = {"priority": Priority.LOW, "retries": 1}

    for msg_id in OTB_MSG_IDS:
        gwy.send_cmd(Command.get_opentherm_data(dev_id, msg_id, **qos))


async def script_scan_006(gwy, dev_id: str):
    _LOGGER.warning("scan_006(otb, hard) invoked - expect a lot of nonsense")

    qos = {"priority": Priority.LOW, "retries": 0}

    for msg_id in range(0x80):
        gwy.send_cmd(Command.get_opentherm_data(dev_id, msg_id, **qos))


SCRIPTS = {
    k[7:]: v for k, v in locals().items() if callable(v) and k.startswith("script_")
}

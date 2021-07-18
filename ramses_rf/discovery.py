#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - discovery scripts."""

import asyncio
import json
import logging
import re
from typing import Any, List

from .address import HGI_DEV_ADDR, NON_DEV_ADDR, Address
from .command import Command, Priority
from .const import ALL_DEVICE_ID, DEVICE_TABLE, __dev_mode__
from .exceptions import ExpiredCallbackError
from .opentherm import R8810A_MSG_IDS
from .ramses import RAMSES_CODES

from .const import I_, RP, RQ, W_  # noqa: F401, isort: skip
from .const import (  # noqa: F401, isort: skip
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

EXECUTE_CMD = "execute_cmd"
GET_FAULTS = "get_faults"
GET_SCHED = "get_schedule"
SET_SCHED = "set_schedule"

SCAN_DISC = "scan_disc"
SCAN_FULL = "scan_full"
SCAN_HARD = "scan_hard"
SCAN_XXXX = "scan_xxxx"

DEVICE_ID_REGEX = re.compile(ALL_DEVICE_ID)

DEV_MODE = __dev_mode__

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


def spawn_execute_cmd(gwy, **kwargs):
    if not kwargs.get(EXECUTE_CMD):  # e.g. "RQ 01:145038 1F09 00"
        _LOGGER.warning("Execute: Command is invalid: '%s'", kwargs[EXECUTE_CMD])
        return

    cmd = kwargs[EXECUTE_CMD].upper().split()
    if len(cmd) < 4:
        _LOGGER.warning("Execute: Command is invalid: '%s'", kwargs[EXECUTE_CMD])
        return

    verb = cmd.pop(0)
    seqn = "---" if DEVICE_ID_REGEX.match(cmd[0]) else cmd.pop(0)
    payload = cmd.pop()[:48]
    code = cmd.pop()

    if not 0 < len(cmd) < 4:
        _LOGGER.warning("Execute: Command is invalid: '%s'", kwargs[EXECUTE_CMD])
        return
    elif len(cmd) == 1:
        addrs = (HGI_DEV_ADDR.id, cmd[0], NON_DEV_ADDR.id)
    elif len(cmd) == 3:
        addrs = (cmd[0], cmd[1], cmd[2])
    elif cmd[0] == cmd[1]:
        addrs = (cmd[0], NON_DEV_ADDR.id, cmd[1])
    else:
        addrs = (cmd[0], cmd[1], NON_DEV_ADDR.id)

    qos = {"priority": Priority.HIGH, "retries": 3}
    try:
        cmd = Command.packet(verb, code, payload, *addrs, seqn=seqn, **qos)
    except ValueError as err:
        _LOGGER.warning(
            "Execute: Command is invalid: '%s' (%s)", kwargs[EXECUTE_CMD], err
        )
    gwy.send_cmd(cmd)


def spawn_monitor_scripts(gwy, **kwargs) -> List[Any]:
    tasks = []

    if kwargs.get(EXECUTE_CMD):
        spawn_execute_cmd(gwy, **kwargs)  # TODO: wrap in a try?

    if kwargs.get("poll_devices"):
        tasks += [poll_device(gwy, d) for d in kwargs["poll_devices"]]

    gwy._tasks.extend(tasks)
    return tasks


def spawn_execute_scripts(gwy, **kwargs) -> List[Any]:

    # this is to ensure the gateway interface has fully woken
    if not kwargs.get(EXECUTE_CMD) and gwy._include:
        dev_id = next(iter(gwy._include))
        qos = {"priority": Priority.HIGH, "retries": 5}
        gwy.send_cmd(Command(RQ, _0016, "00FF", dev_id, **qos))

    tasks = []

    if kwargs.get(EXECUTE_CMD):  # TODO: wrap in a try?
        spawn_execute_cmd(gwy, **kwargs)

    if kwargs.get(GET_FAULTS):
        tasks += [gwy._loop.create_task(get_faults(gwy, kwargs[GET_FAULTS]))]

    if kwargs.get(GET_SCHED) and kwargs[GET_SCHED][0]:
        tasks += [gwy._loop.create_task(get_schedule(gwy, *kwargs[GET_SCHED]))]

    if kwargs.get(SET_SCHED) and kwargs[SET_SCHED][0]:
        tasks += [gwy._loop.create_task(set_schedule(gwy, *kwargs[SET_SCHED]))]

    if kwargs.get(SCAN_DISC):
        tasks += [gwy._loop.create_task(scan_disc(gwy, d)) for d in kwargs[SCAN_DISC]]

    if kwargs.get(SCAN_FULL):
        tasks += [gwy._loop.create_task(scan_full(gwy, d)) for d in kwargs[SCAN_FULL]]

    if kwargs.get(SCAN_HARD):
        tasks += [gwy._loop.create_task(scan_hard(gwy, d)) for d in kwargs[SCAN_HARD]]

    if kwargs.get(SCAN_XXXX):
        tasks += [gwy._loop.create_task(scan_xxxx(gwy, d)) for d in kwargs[SCAN_XXXX]]

    gwy._tasks.extend(tasks)
    return tasks


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


async def get_faults(gwy, ctl_id: str):
    ctl_addr = Address(id=ctl_id, type=ctl_id[:2])
    device = gwy._get_device(ctl_addr, ctl_addr=ctl_addr)

    try:
        await device._evo.get_fault_log()  # 0418
    except ExpiredCallbackError as exc:
        _LOGGER.error("get_faults(): Function timed out: %s", exc)


async def get_schedule(gwy, ctl_id: str, zone_idx: str) -> None:
    ctl_addr = Address(id=ctl_id, type=ctl_id[:2])
    zone = gwy._get_device(ctl_addr, ctl_addr=ctl_addr)._evo._get_zone(zone_idx)

    try:
        await zone.get_schedule()
    except ExpiredCallbackError as exc:
        _LOGGER.error("get_schedule(): Function timed out: %s", exc)


async def set_schedule(gwy, ctl_id, schedule) -> None:
    schedule = json.load(schedule)
    zone_idx = schedule["zone_idx"]

    ctl_addr = Address(id=ctl_id, type=ctl_id[:2])
    zone = gwy._get_device(ctl_addr, ctl_addr=ctl_addr)._evo._get_zone(zone_idx)

    try:
        await zone.set_schedule(schedule["schedule"])  # 0404
    except ExpiredCallbackError as exc:
        _LOGGER.error("set_schedule(): Function timed out: %s", exc)


def poll_device(gwy, dev_id) -> List[Any]:
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


async def scan_disc(gwy, dev_id: str):
    _LOGGER.warning("scan_quick() invoked...")

    qos = {"priority": Priority.HIGH, "retries": 3}
    gwy.send_cmd(Command._puzzle("00", message="disc scan: begins...", **qos))

    device = gwy._get_device(Address(id=dev_id, type=dev_id[:2]))  # not always a CTL
    device._discover()  # discover_flag=DISCOVER_ALL)

    qos = {"priority": Priority.LOW, "retries": 3}
    gwy.send_cmd(Command._puzzle("00", message="disc scan: ended.", **qos))


async def scan_full(gwy, dev_id: str):
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

        elif code in (_01D0, _01E9):
            for zone_idx in ("00", "01", "99", "FC", "FF"):
                gwy.send_cmd(Command(W_, code, f"{zone_idx:02X}00", dev_id, **qos))

        elif code == _0404:
            gwy.send_cmd(Command.get_dhw_schedule_fragment(dev_id, "00", "00", **qos))
            gwy.send_cmd(
                Command.get_zone_schedule_fragment(dev_id, "00", "00", "00", **qos)
            )

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

    qos = {"priority": Priority.LOW, "retries": 3}
    gwy.send_cmd(Command._puzzle("00", message="full scan: ended.", **qos))


async def scan_hard(gwy, dev_id: str):
    _LOGGER.warning("scan_hard() invoked - expect some Warnings")

    qos = {"priority": Priority.HIGH, "retries": 3}
    gwy.send_cmd(Command._puzzle("00", message="hard scan: begins...", **qos))

    qos = {"priority": Priority.LOW, "retries": 0}
    for code in range(0x4000):
        gwy.send_cmd(Command(RQ, f"{code:04X}", "0000", dev_id, **qos))

    qos = {"priority": Priority.LOW, "retries": 3}
    gwy.send_cmd(Command._puzzle("00", message="hard scan: ended.", **qos))


async def scan_xxxx(gwy, dev_id: str):
    # _LOGGER.warning("scan_xxxx() invoked - expect a lot of nonsense")
    await scan_006(gwy, dev_id)


async def scan_001(gwy, dev_id: str):
    _LOGGER.warning("scan_001() invoked - expect a lot of nonsense")

    qos = {"priority": Priority.LOW, "retries": 3}
    for idx in range(0x10):
        gwy.send_cmd(Command(W_, _000E, f"{idx:02X}0050", dev_id, **qos))
        gwy.send_cmd(Command(RQ, _000E, f"{idx:02X}00C8", dev_id, **qos))


async def scan_002(gwy, dev_id: str):
    _LOGGER.warning("scan_002() invoked - expect a lot of nonsense")

    # Two modes, I and W & Two headers zz00 and zz
    message = "0000" + "".join(f"{ord(x):02X}" for x in "Hello there.") + "00"
    qos = {"priority": Priority.LOW, "retries": 0}
    [
        gwy.send_cmd(Command(W_, f"{c:04X}", message, dev_id, **qos))
        for c in range(0x4000)
        if c not in RAMSES_CODES
    ]


async def scan_003(gwy, dev_id: str):
    _LOGGER.warning("scan_003() invoked - expect a lot of nonsense")

    qos = {"priority": Priority.LOW, "retries": 0}
    for msg_id in range(0x100):
        gwy.send_cmd(Command.get_opentherm_data(dev_id, msg_id, **qos))


async def scan_004(gwy, dev_id: str):
    _LOGGER.warning("scan_004() invoked - expect a lot of nonsense")

    qos = {"priority": Priority.LOW, "retries": 0}

    cmd = Command.get_dhw_mode(dev_id, **qos)

    return gwy._loop.create_task(periodic(gwy, cmd, count=0, interval=5))


async def scan_005(gwy, dev_id: str):
    _LOGGER.warning("scan_005(otb, full) invoked - expect a lot of nonsense")

    qos = {"priority": Priority.LOW, "retries": 1}

    for msg_id in R8810A_MSG_IDS:
        gwy.send_cmd(Command.get_opentherm_data(dev_id, msg_id, **qos))


async def scan_006(gwy, dev_id: str):
    _LOGGER.warning("scan_006(otb, hard) invoked - expect a lot of nonsense")

    qos = {"priority": Priority.LOW, "retries": 0}

    for msg_id in range(0x80):
        gwy.send_cmd(Command.get_opentherm_data(dev_id, msg_id, **qos))

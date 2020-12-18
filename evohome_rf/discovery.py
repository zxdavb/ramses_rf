#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome serial discovery scripts."""

import asyncio
import json
import logging
from typing import Any, List

from .command import Command, Priority
from .const import __dev_mode__, CODE_SCHEMA, DEVICE_TABLE, Address
from .exceptions import ExpiredCallbackError


_LOGGER = logging.getLogger(__name__)
if False and __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)


async def _cmd(gwy, *args, **kwargs) -> None:
    qos = kwargs.pop("qos", {})
    await gwy.msg_protocol.send_data(Command(*args, **kwargs, qos=qos))


async def spawn_monitor_scripts(gwy, **kwargs) -> List[Any]:
    tasks = []

    if kwargs.get("execute_cmd"):  # e.g. "RQ 01:145038 1F09 00"
        cmd = kwargs["execute_cmd"]

        qos = {"priority": Priority.HIGH, "retries": 10}
        cmd = Command(cmd[:2], cmd[3:12], cmd[13:17], cmd[18:], qos=qos)
        await gwy.msg_protocol.send_data(cmd)

    if kwargs.get("poll_devices"):
        tasks += [poll_device(gwy, d) for d in kwargs["poll_devices"]]

    gwy._tasks.extend(tasks)
    return tasks


async def spawn_execute_scripts(gwy, **kwargs) -> List[Any]:

    # this is to ensure the gateway interface has fully woken
    dev_id = next(iter(gwy._include))
    qos = {"priority": Priority.HIGH, "retries": 10}
    await gwy.msg_protocol.send_data(Command("RQ", dev_id, "0016", "00", qos=qos))

    tasks = []

    if kwargs.get("execute_cmd"):  # e.g. "RQ 01:145038 1F09 00"
        cmd = kwargs["execute_cmd"]

        qos = {"priority": Priority.HIGH, "retries": 10}
        cmd = Command(cmd[:2], cmd[3:12], cmd[13:17], cmd[18:], qos=qos)
        await gwy.msg_protocol.send_data(cmd)

    if kwargs.get("get_faults"):
        tasks += [asyncio.create_task(get_faults(gwy, kwargs["get_faults"]))]

    if kwargs.get("get_schedule") and kwargs["get_schedule"][0]:
        tasks += [asyncio.create_task(get_schedule(gwy, *kwargs["get_schedule"]))]

    if kwargs.get("set_schedule") and kwargs["set_schedule"][0]:
        tasks += [asyncio.create_task(set_schedule(gwy, *kwargs["set_schedule"]))]

    if kwargs.get("scan_disc"):
        tasks += [asyncio.create_task(scan_disc(gwy, d)) for d in kwargs["scan_disc"]]

    if kwargs.get("scan_full"):
        tasks += [asyncio.create_task(scan_full(gwy, d)) for d in kwargs["scan_full"]]

    if kwargs.get("scan_hard"):
        tasks += [asyncio.create_task(scan_hard(gwy, d)) for d in kwargs["scan_hard"]]

    if kwargs.get("scan_xxxx"):
        tasks += [asyncio.create_task(scan_xxxx(gwy, d)) for d in kwargs["scan_xxxx"]]

    gwy._tasks.extend(tasks)
    return tasks


async def periodic(gwy, cmd, count=1, interval=None):
    async def _periodic():
        await asyncio.sleep(interval)
        await gwy.msg_protocol.send_data(cmd)

    if interval is None:
        interval = 0 if count == 1 else 60

    if count <= 0:
        while True:
            await _periodic()
    else:
        for _ in range(count):
            await _periodic()


async def schedule_task(delay, func, *args, **kwargs) -> Any:
    """Start a coro after delay seconds."""

    async def scheduled_func(delay, func, *args, **kwargs):
        await asyncio.sleep(delay)
        await func(*args, **kwargs)

    return asyncio.create_task(scheduled_func(delay, func, *args, **kwargs))


async def get_faults(gwy, ctl_id: str):
    ctl_addr = Address(id=ctl_id, type=ctl_id[:2])
    device = gwy._get_device(ctl_addr, ctl_addr=ctl_addr)

    try:
        await device._evo.get_fault_log()  # 0418
    except ExpiredCallbackError as exc:
        _LOGGER.error("get_faults(): Function timed out: %s", exc)

    # await gwy.shutdown("get_faults()")  # print("get_faults", device._evo.fault_log())


async def get_schedule(gwy, ctl_id: str, zone_idx: str) -> None:
    ctl_addr = Address(id=ctl_id, type=ctl_id[:2])
    zone = gwy._get_device(ctl_addr, ctl_addr=ctl_addr)._evo._get_zone(zone_idx)

    try:
        await zone.get_schedule()
    except ExpiredCallbackError as exc:
        _LOGGER.error("get_schedule(): Function timed out: %s", exc)

    # await gwy.shutdown("get_schedule()")  # print("get_schedule", zone.schedule())


async def set_schedule(gwy, ctl_id, schedule) -> None:
    schedule = json.load(schedule)
    zone_idx = schedule["zone_idx"]

    ctl_addr = Address(id=ctl_id, type=ctl_id[:2])
    zone = gwy._get_device(ctl_addr, ctl_addr=ctl_addr)._evo._get_zone(zone_idx)

    try:
        await zone.set_schedule(schedule["schedule"])  # 0404
    except ExpiredCallbackError as exc:
        _LOGGER.error("set_schedule(): Function timed out: %s", exc)

    # await gwy.shutdown("get_schedule()")  # print("get_schedule", zone.schedule())


def poll_device(gwy, dev_id) -> List[Any]:
    _LOGGER.warning("poll_device() invoked...")

    qos = {"priority": Priority.LOW, "retries": 0}
    if "poll_codes" in DEVICE_TABLE.get(dev_id[:2]):
        codes = DEVICE_TABLE[dev_id[:2]]["poll_codes"]
    else:
        codes = ["0016", "1FC9"]

    tasks = []

    for code in codes:
        cmd = Command("RQ", dev_id, code, "00", qos=qos)
        tasks.append(asyncio.create_task(periodic(gwy, cmd, count=0)))

        cmd = Command("RQ", dev_id, code, "0000", qos=qos)
        tasks.append(asyncio.create_task(periodic(gwy, cmd, count=0)))

    gwy._tasks.extend(tasks)
    return tasks


async def scan_disc(gwy, dev_id: str):
    _LOGGER.warning("scan_quick() invoked...")

    device = gwy._get_device(Address(id=dev_id, type=dev_id[:2]))  # not always a CTL
    device._discover()  # discover_flag=DISCOVER_ALL)


async def scan_full(gwy, dev_id: str):
    _LOGGER.warning("scan_full() invoked - expect a lot of Warnings")

    qos = {"priority": Priority.LOW, "retries": 0}
    for code in sorted(CODE_SCHEMA):
        if code == "0005":
            for zone_type in range(20):  # known up to 18
                await _cmd(gwy, "RQ", dev_id, code, f"00{zone_type:02X}", qos=qos)
            continue

        elif code == "000C":
            for zone_idx in range(16):  # also: FA-FF?
                await _cmd(gwy, "RQ", dev_id, code, f"{zone_idx:02X}00", qos=qos)
            continue

        if code == "0016":
            qos_alt = {"priority": Priority.HIGH, "retries": 5}
            await _cmd(gwy, "RQ", dev_id, code, "0000", qos=qos_alt)
            continue

        elif code == "0404":
            await _cmd(gwy, "RQ", dev_id, code, "00200008000100", qos=qos)

        elif code == "0418":
            for log_idx in range(2):
                await _cmd(gwy, "RQ", dev_id, code, f"{log_idx:06X}", qos=qos)
            continue

        elif code == "1100":
            await _cmd(gwy, "RQ", dev_id, code, "FC", qos=qos)

        elif code == "2E04":
            await _cmd(gwy, "RQ", dev_id, code, "FF", qos=qos)

        elif code == "3220":
            for data_id in ("00", "03"):  # these are mandatory READ_DATA data_ids
                await _cmd(gwy, "RQ", dev_id, code, f"0000{data_id}0000", qos=qos)

        elif CODE_SCHEMA[code].get("rq_len"):
            rq_len = CODE_SCHEMA[code].get("rq_len") * 2
            await _cmd(gwy, "RQ", dev_id, code, f"{0:0{rq_len}X}", qos=qos)

        else:
            await _cmd(gwy, "RQ", dev_id, code, "0000", qos=qos)

    # these are possible/difficult codes
    qos = {"priority": Priority.LOW, "retries": 3}
    for code in ("0150", "0B04", "2389"):
        await _cmd(gwy, "RQ", dev_id, code, "0000", qos=qos)


async def scan_hard(gwy, dev_id: str):
    _LOGGER.warning("scan_deep() invoked - expect some Warnings")

    qos = {"priority": Priority.LOW, "retries": 0}
    for code in range(0x4000):
        await _cmd(gwy, "RQ", dev_id, f"{code:04X}", "0000", qos=qos)


async def scan_xxxx(gwy, dev_id: str):
    _LOGGER.warning("scan_xxx() invoked - expect a lot of nonsense")

    qos = {"priority": Priority.LOW, "retries": 3}
    for idx in range(0x10):
        await _cmd(gwy, " W", dev_id, "000E", f"{idx:02X}0050", qos=qos)
        await _cmd(gwy, "RQ", dev_id, "000E", f"{idx:02X}00C8", qos=qos)

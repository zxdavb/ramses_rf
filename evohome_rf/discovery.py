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


_LOGGER = logging.getLogger(__name__)
if False and __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)


async def spawn_monitor_scripts(gwy, **kwargs) -> List[Any]:
    tasks = []

    if kwargs.get("execute_cmd"):  # e.g. "RQ 01:145038 1F09 00"
        cmd = kwargs["execute_cmd"]
        cmd = Command(cmd[:2], cmd[3:12], cmd[13:17], cmd[18:], retries=12)
        await gwy.msg_protocol.send_data(cmd)

    if kwargs.get("poll_devices"):
        tasks += [poll_device(gwy, d) for d in kwargs["poll_devices"]]

    return tasks


async def spawn_execute_scripts(gwy, **kwargs) -> List[Any]:
    tasks = []

    if kwargs.get("get_faults"):
        tasks += [asyncio.create_task(get_faults(gwy, kwargs["get_faults"]))]

    if kwargs.get("get_schedule") and kwargs["get_schedule"][0]:
        tasks += [asyncio.create_task(get_schedule(gwy, *kwargs["get_schedule"]))]

    if kwargs.get("set_schedule") and kwargs["set_schedule"][0]:
        tasks += [asyncio.create_task(set_schedule(gwy, *kwargs["set_schedule"]))]

    if kwargs.get("probe_devices"):  # TODO: probe_quick, probe_deep
        tasks += [
            asyncio.create_task(probe_device(gwy, d)) for d in kwargs["probe_devices"]
        ]

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


async def schedule_task(delay, func, *args, **kwargs):
    """Start a coro after delay seconds."""

    async def scheduled_func(delay, func, *args, **kwargs):
        await asyncio.sleep(delay)
        await func(*args, **kwargs)

    asyncio.create_task(scheduled_func(delay, func, *args, **kwargs))


async def get_faults(gwy, ctl_id: str):
    ctl_addr = Address(id=ctl_id, type=ctl_id[:2])
    device = gwy._get_device(ctl_addr, ctl_addr=ctl_addr)

    await device._evo.get_fault_log()  # 0418
    # await gwy.shutdown("get_faults()")  # print("get_faults", device._evo.fault_log())


async def get_schedule(gwy, ctl_id: str, zone_idx: str) -> None:
    ctl_addr = Address(id=ctl_id, type=ctl_id[:2])
    zone = gwy._get_device(ctl_addr, ctl_addr=ctl_addr)._evo._get_zone(zone_idx)

    await zone.get_schedule()
    # await gwy.shutdown("get_schedule()")  # print("get_schedule", zone.schedule())


async def set_schedule(gwy, ctl_id, schedule) -> None:
    schedule = json.load(schedule)
    zone_idx = schedule["zone_idx"]

    ctl_addr = Address(id=ctl_id, type=ctl_id[:2])
    zone = gwy._get_device(ctl_addr, ctl_addr=ctl_addr)._evo._get_zone(zone_idx)

    await zone.set_schedule(schedule["schedule"])  # 0404
    # await gwy.shutdown("get_schedule()")  # print("get_schedule", zone.schedule())


def poll_device(gwy, device_id):
    qos = {"priority": Priority.LOW, "retries": 0}

    if "poll_codes" in DEVICE_TABLE.get(device_id[:2]):
        codes = DEVICE_TABLE[device_id[:2]]["poll_codes"]
    else:
        codes = ["0016", "1FC9"]

    for code in codes:
        cmd = Command("RQ", device_id, code, "00", qos=qos)
        _ = asyncio.create_task(periodic(gwy, cmd, count=0))
        cmd = Command("RQ", device_id, code, "0000", qos=qos)
        _ = asyncio.create_task(periodic(gwy, cmd, count=0))


async def probe_device(gwy, dev_id: str, probe_type=None):
    dev_addr = Address(id=dev_id, type=dev_id[:2])
    device = gwy._get_device(dev_addr)  # not always a CTL

    if probe_type is not None:
        device._discover()  # discover_flag=DISCOVER_ALL)
        await gwy.shutdown("get_device()")
        return

    # TODO: should we avoid creating entities?
    _LOGGER.warning("probe_device() invoked - expect a lot of Warnings")

    qos = {"priority": Priority.LOW, "retries": 0}

    # for code in range(0x4000):
    for code in sorted(CODE_SCHEMA):
        if code == "0005":
            for zone_type in range(20):  # known up to 18
                cmd = Command("RQ", device.id, code, f"00{zone_type:02X}", qos=qos)
                asyncio.create_task(periodic(gwy, cmd))
            continue

        elif code == "000C":
            # for domain_id in ("F8", "F9", "FA", "FB", "FD", "FE", "FF"):
            #     cmd = Command("RQ", device.id, code, f"{domain_id}00", qos=qos)
            #     asyncio.create_task(periodic(gwy, cmd))

            for zone_idx in range(16):
                cmd = Command("RQ", device.id, code, f"{zone_idx:02X}00", qos=qos)
                asyncio.create_task(periodic(gwy, cmd))
            continue

        if code == "0016":
            qos_alt = {"priority": Priority.HIGH, "retries": 5}
            cmd = Command("RQ", device.id, code, "0000", qos=qos_alt)
            asyncio.create_task(periodic(gwy, cmd))
            continue

        elif code == "0404":
            cmd = Command("RQ", device.id, code, "00200008000100", qos=qos)

        elif code == "0418":
            for log_idx in range(2):
                cmd = Command("RQ", device.id, code, f"{log_idx:06X}", qos=qos)
                asyncio.create_task(periodic(gwy, cmd))
            continue

        elif code == "1100":
            cmd = Command("RQ", device.id, code, "FC", qos=qos)

        elif code == "2E04":
            cmd = Command("RQ", device.id, code, "FF", qos=qos)

        elif code == "3220":
            for data_id in ("00", "03"):  # these are mandatory READ_DATA data_ids
                cmd = Command("RQ", device.id, code, f"0000{data_id}0000", qos=qos)

        elif CODE_SCHEMA[code].get("rq_len"):
            rq_len = CODE_SCHEMA[code].get("rq_len") * 2
            cmd = Command("RQ", device.id, code, f"{0:0{rq_len}X}", qos=qos)

        else:
            cmd = Command("RQ", device.id, code, "0000", qos=qos)

        asyncio.create_task(periodic(gwy, cmd))  # type: ignore


# if self.config.get("evofw_flag") and "evofw3" in raw_pkt.packet:
#     # !V, !T - print the version, or the current mask
#     # !T00   - turn off all mask bits
#     # !T01   - cause raw data for all messages to be printed
#     await manager.put_pkt(self.config["evofw_flag"], _LOGGER)

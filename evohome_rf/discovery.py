#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome serial discovery scripts."""

import asyncio
import logging

from .command import Command
from .const import __dev_mode__


_LOGGER = logging.getLogger(__name__)
if False and __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)
else:
    _LOGGER.setLevel(logging.WARNING)


async def periodic(cmd_que, cmd, interval=60, count=1440):
    for _ in range(count):
        await asyncio.sleep(interval)
        cmd_que.put_nowait(cmd)


def start_tests(cmd_que):
    cmd = Command("RQ", "13:237335", "0008", "00", retry_limit=0)
    _ = asyncio.create_task(periodic(cmd_que, cmd, interval=30))

    cmd = Command("RQ", "13:237335", "3EF1", "00", retry_limit=0)
    _ = asyncio.create_task(periodic(cmd_que, cmd, interval=30))


# if self._execute_cmd:  # e.g. "RQ 01:145038 1F09 00"
#     cmd = self._execute_cmd
#     cmd = Command(cmd[:2], cmd[3:12], cmd[13:17], cmd[18:])
#     await manager.put_pkt(cmd, _LOGGER)


# if self.config.get("evofw_flag") and "evofw3" in raw_pkt.packet:
#     # !V, !T - print the version, or the current mask
#     # !T00   - turn off all mask bits
#     # !T01   - cause raw data for all messages to be printed
#     await manager.put_pkt(self.config["evofw_flag"], _LOGGER)


# # used for development only...
# for code in range(0x4000):
#     # cmd = Command("RQ", "01:145038", f"{code:04X}", "0000")
#     cmd = Command("RQ", "13:035462", f"{code:04X}", "0000")
#     await destination.put_pkt(cmd, _LOGGER)
#     if code % 0x10 == 0:
#         await asyncio.sleep(15)  # 10 too short - 15 seconds works OK


# # used for development only...
# for payload in ("0000", "0100", "F8", "F9", "FA", "FB", "FC", "FF"):
#     cmd = Command("RQ", "01:145038", "11F0", payload)
#     await destination.put_pkt(cmd, _LOGGER)
#     cmd = Command("RQ", "13:035462", "11F0", payload)
#     await destination.put_pkt(cmd, _LOGGER)


# for device_type in ("0D", "0E", "0F"):  # CODE_000C_DEVICE_TYPE:
#     cmd = Command("RQ", "01:145038", "000C", f"00{device_type}")
#     await manager.put_pkt(cmd, _LOGGER)


# for z in range(4):
#     for x in range(12):
#         cmd = Command("RQ", "01:145038", "000C", f"{z:02X}{x:02X}")
#         await manager.put_pkt(cmd, _LOGGER)


# for p in ("00", "01", "FF", "0000", "0100", "FF00"):
#     for c in ("0003", "0007", "000B", "000D", "000F"):
#         cmd = Command("RQ", "01:145038", c, f"0008{p}")
#         print(cmd)
#         await manager.put_pkt(cmd, _LOGGER)

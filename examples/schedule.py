#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""A CLI for the ramses_rf library.

ramses_rf is used to parse Honeywell's RAMSES-II packets, either via RF or from a file.
"""
import asyncio
import json
import sys

import click
from colorama import Fore
from colorama import init as colorama_init

# Ugly hack to allow absolute import from the root folder. Please forgive the heresy.
if __name__ == "__main__" and __package__ is None:
    from os.path import dirname

    sys.path.append(dirname(sys.path[0]))
    __package__ = "examples"

from ramses_rf import Gateway, GracefulExit
from ramses_rf.schema import ATTR_CONTROLLER

DEBUG_ADDR = "0.0.0.0"
DEBUG_PORT = 5678

COLORS = {" I": Fore.GREEN, "RP": Fore.CYAN, "RQ": Fore.BLUE, " W": Fore.MAGENTA}

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


# @click.group(context_settings=CONTEXT_SETTINGS)
@click.command(context_settings=CONTEXT_SETTINGS)
@click.argument("serial-port")
@click.argument("device-id")
@click.option("--get-schedule", is_flag=False, type=click.STRING)
@click.option("--set-schedule", is_flag=False, type=click.File("r"))
@click.option("-z", "--debug-mode", is_flag=True)
def cli(*args, **kwargs):
    """Execute scripts on a device via a serial port."""

    # print(f"args = {args}, kwargs = {kwargs}")

    if kwargs["debug_mode"]:
        import debugpy

        print(f"Debugging is enabled, listening on: {DEBUG_ADDR}:{DEBUG_PORT}.")
        debugpy.listen(address=(DEBUG_ADDR, DEBUG_PORT))
        print(" - execution paused, waiting for debugger to attach...")
        debugpy.wait_for_client()
        print(" - debugger is now attached, continuing execution.")

    serial_port = kwargs.pop("serial_port")
    device_id = kwargs.pop("device_id")

    config_dict = {
        "config": {"enforce_allowlist": True, "disable_discovery": True},
        "schema": {ATTR_CONTROLLER: device_id},
        "allowlist": {device_id: {"name": "Controller"}},
    }

    if kwargs.get("get_schedule") is not None:
        config_dict["schema"]["zones"] = {kwargs["get_schedule"]: {}}

    elif kwargs.get("set_schedule") is not None:
        kwargs["set_schedule"] = json.load(kwargs["set_schedule"])
        config_dict["schema"]["zones"] = {kwargs["set_schedule"][SZ_ZONE_IDX]: {}}

    asyncio.run(main(serial_port, **config_dict, **kwargs))


def process_message(msg) -> None:
    dtm = f"{msg.dtm:%H:%M:%S.%f}"[:-3]
    if msg.src.type == "18" and msg.verb == "RQ":
        print(f"{Fore.YELLOW}{dtm} {msg}")
    else:
        print(f"{COLORS.get(msg.verb)}{dtm} {msg}")

    # {print(k, v) for k, v in msg.payload.items()}


async def main(serial_port, **config):

    # print(f"kwargs = {config}")

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    gwy = Gateway(serial_port, **config)

    colorama_init(autoreset=True)
    protocol, _ = gwy.create_client(process_message)

    schedule = config["set_schedule"] if config.get("set_schedule") else None
    try:
        task = asyncio.create_task(gwy.start())

        if config.get("get_schedule") is not None:
            zone = gwy.evo.zone_by_idx[config["get_schedule"]]
            schedule = await zone.get_schedule()

        elif config.get("set_schedule") is not None:
            zone = gwy.evo.zone_by_idx[schedule[SZ_ZONE_IDX]]
            await zone.set_schedule(schedule["schedule"])

        else:
            gwy.device_by_id[config["device_id"]]

        await gwy.shutdown()
        await task

    except asyncio.CancelledError:
        # print(" - exiting via: CancelledError (this is expected)")
        pass
    except GracefulExit:
        print(" - exiting via: GracefulExit")
    except KeyboardInterrupt:
        print(" - exiting via: KeyboardInterrupt")
    else:  # if no Exceptions raised, e.g. EOF when parsing
        print(" - exiting via: else-block (e.g. EOF when parsing)")

    if config.get("get_schedule") is not None:
        if schedule is None:
            print("Error: Failed to get the schedule.")
        else:
            result = {SZ_ZONE_IDX: config["get_schedule"], "schedule": schedule}
            print(json.dumps(result))  # , indent=4))

    elif config.get("set_schedule") is None:
        print(gwy.device_by_id[config["device_id"]])


if __name__ == "__main__":
    cli()

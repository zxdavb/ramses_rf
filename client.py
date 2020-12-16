#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""A CLI for the evohome_rf library.

evohome_rf is used to parse Honeywell's RAMSES-II packets, either via RF or from a file.
"""
import asyncio
import json
import sys
from typing import Tuple

import click
from colorama import init as colorama_init, Fore

from evohome_rf import Gateway, GracefulExit, execute_scripts, monitor_scripts

DONT_CREATE_MESSAGES = 3
DONT_CREATE_ENTITIES = 2
DONT_UPDATE_ENTITIES = 1

DEBUG_ADDR = "0.0.0.0"
DEBUG_PORT = 5678

COLORS = {" I": Fore.GREEN, "RP": Fore.CYAN, "RQ": Fore.CYAN, " W": Fore.MAGENTA}

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

LIB_KEYS = (
    "input_file",
    "serial_port",
    "evofw_flag",
    "execute_cmd",
    "packet_log",
    "process_level",  # TODO
    "reduce_processing",
)


def _proc_kwargs(obj, kwargs) -> Tuple[dict, dict]:
    lib_kwargs, cli_kwargs = obj
    lib_kwargs["config"].update({k: v for k, v in kwargs.items() if k in LIB_KEYS})
    cli_kwargs.update({k: v for k, v in kwargs.items() if k not in LIB_KEYS})
    return lib_kwargs, cli_kwargs


def _convert_to_list(d: str) -> list:
    if not d or not str(d):
        return []
    return [c.strip() for c in d.split(",") if c.strip()]


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option("-z", "--debug-mode", count=True, help="enable debugger")
@click.option("-r", "--reduce-processing", count=True)
@click.option("-c", "--config-file", type=click.File("r"))
@click.pass_context
def cli(ctx, config_file=None, **kwargs):
    """A CLI for the evohome_rf library."""

    if kwargs["debug_mode"]:
        import debugpy

        debugpy.listen(address=(DEBUG_ADDR, DEBUG_PORT))
        print(f"Debugging is enabled, listening on: {DEBUG_ADDR}:{DEBUG_PORT}.")
        print(" - execution paused, waiting for debugger to attach...")
        debugpy.wait_for_client()
        print(" - debugger is now attached, continuing execution.")

    lib_kwargs, cli_kwargs = _proc_kwargs(({"config": {}}, {}), kwargs)

    if config_file is not None:
        lib_kwargs.update(json.load(config_file))

    lib_kwargs["debug_mode"] = cli_kwargs["debug_mode"] > 1
    lib_kwargs["config"]["reduce_processing"] = kwargs["reduce_processing"]

    ctx.obj = lib_kwargs, kwargs


class FileCommand(click.Command):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params.insert(
            0, click.Argument(("input-file",), type=click.File("r"), default=sys.stdin)
        )
        # self.params.insert(1, click.Option(("-r", "--process_level"), count=True))


class PortCommand(click.Command):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params.insert(0, click.Argument(("serial-port",)))
        # self.params.insert(1, click.Option(("-r", "--process_level"), count=True))
        self.params.insert(
            1,
            click.Option(
                ("-o", "--packet-log"),
                type=click.Path(),
                help="Log all packets to this file",
            ),
        )
        self.params.insert(
            2,
            click.Option(
                ("-T", "--evofw-flag"),
                type=click.STRING,
                help="Pass this traceflag to the evofw",
            ),
        )


@click.command(cls=FileCommand)
@click.pass_obj
def parse(obj, **kwargs):
    """Parse a log file for messages/packets."""
    lib_kwargs, cli_kwargs = _proc_kwargs(obj, kwargs)

    lib_kwargs["input_file"] = lib_kwargs["config"].pop("input_file")

    asyncio.run(main(lib_kwargs, command="parse", **cli_kwargs))


@click.command(cls=PortCommand)
@click.option("-d/-nd", "--discover/--no-discover", default=None)
@click.option(  # "--execute-cmd"
    "-x",
    "--execute-cmd",
    type=click.STRING,
    help="e.g.: RQ 01:123456 1F09 00",
)
@click.option("--poll-devices", type=click.STRING, help="device_id, device_id, ...")
@click.pass_obj
def monitor(obj, **kwargs):
    """Monitor (eavesdrop and/or probe) a serial port for messages/packets."""
    lib_kwargs, cli_kwargs = _proc_kwargs(obj, kwargs)

    if cli_kwargs["discover"] is not None:
        lib_kwargs["config"]["disable_discovery"] = not cli_kwargs["discover"]
    lib_kwargs["config"]["poll_devices"] = _convert_to_list(
        cli_kwargs.pop("poll_devices")
    )

    asyncio.run(main(lib_kwargs, command="monitor", **cli_kwargs))


@click.command(cls=PortCommand)
@click.option(  # "--execute-cmd"
    "-x",
    "--execute-cmd",
    type=click.STRING,
    help="e.g.: RQ 01:123456 1F09 00",
)
@click.option("--probe-devices", type=click.STRING, help="device_id, device_id, ...")
@click.option("--get-faults", type=click.STRING, help="controller_id")
@click.option(  # "--get-schedule"
    "--get-schedule",
    default=[None, None],
    type=(str, str),
    help="controller_id, zone_idx (e.g. '0A')",
)
@click.option(  # "--set-schedule"
    "--set-schedule",
    default=[None, None],
    type=(str, click.File("r")),
    help="controller_id, JSON (file)",
)
@click.pass_obj
def execute(obj, **kwargs):
    """Execute any specified scripts, return the results, then quit."""
    lib_kwargs, cli_kwargs = _proc_kwargs(obj, kwargs)

    lib_kwargs["config"]["disable_discovery"] = True
    cli_kwargs["probe_devices"] = _convert_to_list(
        cli_kwargs.pop("probe_devices")
    )

    lib_kwargs["allowlist"] = {}
    if cli_kwargs["probe_devices"]:
        lib_kwargs["allowlist"].update({d: None for d in cli_kwargs["probe_devices"]})
    if cli_kwargs.get("get_faults"):
        lib_kwargs["allowlist"].update({cli_kwargs["get_faults"]: {}})
    if cli_kwargs.get("get_schedule")[0]:
        lib_kwargs["allowlist"].update({cli_kwargs["get_schedule"][0]: {}})
    if cli_kwargs.get("set_schedule")[0]:
        lib_kwargs["allowlist"].update({cli_kwargs["set_schedule"][0]: {}})

    if lib_kwargs["allowlist"]:
        lib_kwargs["config"]["enforce_allowlist"] = True

    asyncio.run(main(lib_kwargs, command="execute", **cli_kwargs))


@click.command(cls=PortCommand)
@click.pass_obj
def listen(obj, **kwargs):
    """Listen to (eavesdrop only) a serial port for messages/packets."""
    lib_kwargs, cli_kwargs = _proc_kwargs(obj, kwargs)

    lib_kwargs["config"]["disable_sending"] = True

    asyncio.run(main(lib_kwargs, command="listen", **cli_kwargs))


async def main(lib_kwargs, **kwargs):
    def print_results(**kwargs):

        if kwargs.get("get_faults"):
            fault_log = gwy.device_by_id[kwargs["get_faults"]]._evo.fault_log()

            if fault_log is None:
                print("No fault log, or failed to get the fault log.")
            else:
                [print(k, v) for k, v in fault_log.items()]

        if kwargs.get("get_schedule") and kwargs["get_schedule"][0]:
            system_id, zone_idx = kwargs["get_schedule"]
            zone = gwy.system_by_id[system_id].zone_by_idx[zone_idx]
            schedule = zone._schedule.schedule

            if schedule is None:
                print("Failed to get the schedule.")
            else:
                print("Schedule = \r\n", json.dumps(schedule, indent=4))

        if kwargs.get("set_schedule") and kwargs["set_schedule"][0]:
            input = json.load(kwargs["set_schedule"][1])
            system_id, zone_idx = kwargs["get_schedule"][1], input["zone_idx"]
            zone = gwy.system_by_id[system_id].zone_by_idx[zone_idx]

            gwy.evo.zone_by_idx[input["zone_idx"]].schedule = input["schedule"]

        # else:
        #     print(gwy.device_by_id[kwargs["device_id"]])

    def process_message(msg) -> None:
        dtm = f"{msg.dtm:%H:%M:%S.%f}"[:-3]
        if msg.src.type == "18" and msg.verb == "RQ":
            print(f"{Fore.BLUE}{dtm} {msg}")
        else:
            print(f"{COLORS.get(msg.verb)}{dtm} {msg}")

        # {print(k, v) for k, v in msg.payload.items()}

    print("\r\nclient.py: Starting evohome_rf...")

    # loop=asyncio.get_event_loop() causes: 'NoneType' object has no attribute 'serial'
    if sys.platform == "win32":  # is better than os.name
        # ERROR:asyncio:Cancelling an overlapped future failed
        # future: ... cb=[BaseProactorEventLoop._loop_self_reading()]
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    gwy = Gateway(lib_kwargs["config"].pop("serial_port", None), **lib_kwargs)

    if kwargs.get("reduce_processing", 0) < 3:
        # no MSGs will be sent to STDOUT, so send PKTs instead
        colorama_init(autoreset=True)
        protocol, _ = gwy.create_client(process_message)

    try:
        task = asyncio.create_task(gwy.start())
        if kwargs["command"] == "execute":
            tasks = await execute_scripts(gwy, **kwargs)
            await asyncio.gather(*tasks)
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

    print("\r\nclient.py: Finished evohome_rf, results:\r\n")

    if kwargs["command"] == "execute":
        print_results(**kwargs)

    elif gwy.evo is None:
        print(f"Schema[gateway] = {json.dumps(gwy.schema)}\r\n")
        print(f"Params[gateway] = {json.dumps(gwy.params)}\r\n")
        print(f"Status[gateway] = {json.dumps(gwy.status)}")

    else:
        print(f"Schema[{repr(gwy.evo)}] = {json.dumps(gwy.evo.schema, indent=4)}\r\n")
        print(f"Params[{repr(gwy.evo)}] = {json.dumps(gwy.evo.params, indent=4)}\r\n")
        print(f"Status[{repr(gwy.evo)}] = {json.dumps(gwy.evo.status, indent=4)}")

    print("\r\nclient.py: Finished evohome_rf.\r\n")


cli.add_command(parse)
cli.add_command(monitor)
cli.add_command(execute)
cli.add_command(listen)

if __name__ == "__main__":
    cli()

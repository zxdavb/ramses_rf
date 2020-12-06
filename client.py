#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""A CLI for the evohome_rf library.

evohome_rf is used to parse Honeywell's RAMSES-II packets, either via RF or from a file.
"""
import asyncio
import json
import sys

import click
from colorama import init as colorama_init, Fore

from evohome_rf import CONFIG_SCHEMA, Gateway, GracefulExit

DEBUG_ADDR = "0.0.0.0"
DEBUG_PORT = 5678

# this is needed only when debugging the client
# import debugpy
# print(f"Debugging is enabled, listening on: {DEBUG_ADDR}:{DEBUG_PORT}.")
# debugpy.listen(address=(DEBUG_ADDR, DEBUG_PORT))
# print(" - execution paused, waiting for debugger to attach...")
# debugpy.wait_for_client()


COLORS = {" I": Fore.GREEN, "RP": Fore.CYAN, "RQ": Fore.BLUE, " W": Fore.MAGENTA}

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option("-z", "--debug-mode", help="TBD", count=True)
@click.option("-r", "--reduce-processing", help="TBD", count=True)
@click.option("-c", "--config-file", help="TBD", type=click.Path())
# @click.option("-C", "--controller-id", help="TBD")
@click.pass_context
def cli(ctx, **kwargs):
    """A CLI for the evohome_rf library."""

    # if kwargs["debug_mode"]:
    #     print(f"cli(): ctx.obj={ctx.obj}, kwargs={kwargs}")
    ctx.obj = kwargs


@click.command()
@click.argument("input-file", type=click.File("r"), default=sys.stdin)
@click.pass_obj
def parse(obj, **kwargs):
    """Parse a log file for packets."""

    debug_wrapper(**obj, **kwargs)


@click.command()
@click.argument("serial-port")
@click.option("-T", "--evofw-flag", help="TBD")
@click.option(  # "--packet-log"
    "-o",
    "--packet-log",
    help="TBD",
    type=click.Path(),
    default="packet.log",
    show_default=True,
)
@click.option("-p", "--enforce-probing", is_flag=True, help="TBD")
@click.option(  # "--execute-cmd"
    "-x",
    "--execute-cmd",
    is_flag=False,
    type=click.STRING,
    help="e.g.: RQ 01:123456 1F09 00",
)
@click.option("--poll-devices", is_flag=False, type=click.STRING)
@click.option("--probe-devices", is_flag=False, type=click.STRING)
@click.pass_obj
def monitor(obj, **kwargs):
    """Monitor (eavesdrop/probe) a serial port for packets."""

    for key in ("poll_devices", "probe_devices"):
        if kwargs[key] is None:
            kwargs[key] = []
        else:
            kwargs[key] = [c.strip() for c in kwargs[key].split(",")]

    debug_wrapper(**obj, **kwargs)


@click.command()
@click.argument("serial-port")
@click.option("-T", "--evofw-flag", help="TBD")
@click.option(  # "--packet-log"
    "-o",
    "--packet-log",
    help="TBD",
    type=click.Path(),
    default="packet.log",
    show_default=True,
)
@click.pass_obj
def listen(obj, **kwargs):
    """Listen to (eavesdrop only) a serial port for packets."""

    kwargs["disable_sending"] = True

    debug_wrapper(**obj, **kwargs)


@click.command()
@click.argument("serial-port")
@click.option("-T", "--evofw-flag", help="TBD")
@click.option(  # "--packet-log"
    "-o",
    "--packet-log",
    help="TBD",
    type=click.Path(),
    default="packet.log",
    show_default=True,
)
@click.option(  # "--device-id"
    "--device-id",
    is_flag=False,
    type=click.STRING,
    required=True,
    help="The device to target with a get_xxx script",
)
@click.option("--get-faults", is_flag=True)
@click.option("--get-schedule", is_flag=False, type=click.STRING)
@click.option("--set-schedule", is_flag=False, type=click.File("r"))
@click.pass_obj
def execute(obj, **kwargs):
    """Execute scripts on a device via a serial port."""

    debug_wrapper(**obj, **kwargs)


def debug_wrapper(config_file=None, **kwargs):

    # 1st: sort out any debug mode...
    assert 0 <= kwargs["debug_mode"] <= 3

    if kwargs["debug_mode"] == 3:
        print("Additional logging enabled (debugging not enabled).")

    elif kwargs["debug_mode"] != 0:
        import debugpy

        print(f"Debugging is enabled, listening on: {DEBUG_ADDR}:{DEBUG_PORT}.")
        debugpy.listen(address=(DEBUG_ADDR, DEBUG_PORT))

        if kwargs["debug_mode"] == 1:
            print(" - execution paused, waiting for debugger to attach...")
            debugpy.wait_for_client()
            print(" - debugger is now attached, continuing execution.")

    # 2nd: merge CLI args with config file, if any, TODO: use a SCHEMA
    config_dict = {"schema": {}, "allowlist": {}, "blocklist": {}}
    if config_file is not None:
        with open(config_file) as json_data:
            config_dict.update(json.load(json_data))

    config = CONFIG_SCHEMA(config_dict.pop("config", {}))
    if "enforce_probing" in kwargs:
        config["disable_discovery"] = not kwargs.pop("enforce_probing")
    # config["input_file"] = kwargs.pop("input_file", None)
    config = {**config_dict, **config, **kwargs}

    # print("client.py: config: ", config)
    serial_port = config.pop("serial_port", None)

    asyncio.run(main(serial_port, **config))


def process_message(msg) -> None:
    dtm = f"{msg.dtm:%H:%M:%S.%f}"[:-3]
    if msg.src.type == "18" and msg.verb == "RQ":
        print(f"{Fore.BLUE}{dtm} {msg}")
    else:
        print(f"{COLORS.get(msg.verb)}{dtm} {msg}")

    # {print(k, v) for k, v in msg.payload.items()}


# def process_device_job() -> None:
#     dtm = f"{msg.dtm:%H:%M:%S.%f}"[:-3]
#     if msg.src.type == "18" and msg.verb == "RQ":
#         print(f"{Fore.BLUE}{dtm} {msg}")
#     else:
#         print(f"{COLORS.get(msg.verb)}{dtm} {msg}")

#     # {print(k, v) for k, v in msg.payload.items()}


async def main(serial_port, loop=None, **config):

    # loop=asyncio.get_event_loop() causes: 'NoneType' object has no attribute 'serial'
    print("\r\nclient.py: Starting evohome_rf...")

    colorama_init(autoreset=True)

    if sys.platform == "win32":  # is better than os.name
        # ERROR:asyncio:Cancelling an overlapped future failed
        # future: ... cb=[BaseProactorEventLoop._loop_self_reading()]
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    gwy = Gateway(serial_port, loop=loop, **config)
    if config.get("reduce_processing") < 3:
        protocol, _ = gwy.create_client(process_message)

    try:
        task = asyncio.create_task(gwy.start())
        # if config.get("device_id"):
        #     process_device_job()
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

    if config.get("device_id"):
        # gwy._get_device()

        if config.get("get_faults"):
            fault_log = gwy.device_by_id[config["device_id"]]._evo.fault_log()
            if fault_log is None:
                print("No fault log, or failed to get the fault log.")
            else:
                [print(k, v) for k, v in fault_log.items()]

        elif config.get("get_schedule") is not None:
            schedule = gwy.evo.zone_by_idx[config["get_schedule"]].schedule()
            if schedule is None:
                print("Failed to get the schedule.")
            else:
                result = {
                    "zone_idx": config["get_schedule"],
                    # "zone_name": gwy.evo.zone_by_idx[config["get_schedule"]].name,
                    "schedule": schedule,
                }
                print(json.dumps(result))  # , indent=4))

        elif config.get("set_schedule") is not None:
            input = json.load(config["set_schedule"])
            gwy.evo.zone_by_idx[input["zone_idx"]].schedule = input["schedule"]

        else:
            print(gwy.device_by_id[config["device_id"]])

    elif gwy.evo is None:
        print(f"Schema[gateway] = {json.dumps(gwy.schema)}\r\n")
        print(f"Params[gateway] = {json.dumps(gwy.params)}\r\n")
        print(f"Status[gateway] = {json.dumps(gwy.status)}")

    else:
        print(f"Schema[{repr(gwy.evo)}] = {json.dumps(gwy.evo.schema, indent=4)}\r\n")
        print(f"Params[{repr(gwy.evo)}] = {json.dumps(gwy.evo.params, indent=4)}\r\n")
        print(f"Status[{repr(gwy.evo)}] = {json.dumps(gwy.evo.status, indent=4)}")

    print("\r\nclient.py: Finished evohome_rf.\r\n")


cli.add_command(execute)
cli.add_command(listen)
cli.add_command(monitor)
cli.add_command(parse)

if __name__ == "__main__":
    cli()

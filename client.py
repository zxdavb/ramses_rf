#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""A CLI for the evohome_rf library.

evohome_rf is used to parse Honeywell's RAMSES-II packets, either via RF or from a file.
"""
import asyncio
import json
import sys
from typing import Optional

import click

from evohome_rf import CONFIG_SCHEMA, Gateway, GracefulExit  # create_ramses_client

DEBUG_ADDR = "0.0.0.0"
DEBUG_PORT = 5678

# this is needed only when debugging the client
# import ptvsd
# print(f"Debugging is enabled, listening on: {DEBUG_ADDR}:{DEBUG_PORT}.")
# ptvsd.enable_attach(address=(DEBUG_ADDR, DEBUG_PORT))
# print(" - execution paused, waiting for debugger to attach...")
# ptvsd.wait_for_attach()

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


class ClientProtocol(asyncio.Protocol):
    """Interface for a message protocol."""

    def __init__(self, msg_handler) -> None:
        self._callback = msg_handler
        self._transport = None
        self._pause_writing = None

    def connection_made(self, transport) -> None:
        """Called when a connection is made."""
        self._transport = transport

    def data_received(self, msg) -> None:
        """Called when some data is received (called by the transport)."""
        self._callback(msg)

    async def send_data(self, cmd) -> None:
        """Called when some data is to be sent (is not a callaback)."""
        while self._pause_writing:
            asyncio.sleep(0.05)
        await self._transport.write(cmd)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when the connection is lost or closed."""
        if exc is not None:
            pass

    def pause_writing(self) -> None:
        """Called when the transport's buffer goes over the high-water mark."""
        self._pause_writing = True

    def resume_writing(self) -> None:
        """Called when the transport's buffer drains below the low-water mark."""
        self._pause_writing = False


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
@click.option(
    "-o",
    "--packet-log",
    help="TBD",
    type=click.Path(),
    default="packet.log",
    show_default=True,
)
@click.option("-p", "--enforce-probing", is_flag=True, help="TBD")
@click.option(
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
@click.option(
    "-o",
    "--packet-log",
    help="TBD",
    type=click.Path(),
    default="packet.log",
    show_default=True,
)
@click.option("--device-id", is_flag=False, type=click.STRING, required=True)
@click.option("--get-schedule", is_flag=False, type=click.STRING)
@click.option("--get-faults", is_flag=True)
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
        import ptvsd

        print(f"Debugging is enabled, listening on: {DEBUG_ADDR}:{DEBUG_PORT}.")
        ptvsd.enable_attach(address=(DEBUG_ADDR, DEBUG_PORT))

        if kwargs["debug_mode"] == 1:
            print(" - execution paused, waiting for debugger to attach...")
            ptvsd.wait_for_attach()
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


async def main(serial_port, loop=None, **config):
    def protocol_factory(callback):
        return ClientProtocol(callback)

    def process_msg(msg):
        print(msg)

    # loop=asyncio.get_event_loop() causes: 'NoneType' object has no attribute 'serial'
    print("\r\nclient.py: Starting evohome_rf...")

    if sys.platform == "win32":  # is better than os.name
        # ERROR:asyncio:Cancelling an overlapped future failed
        # future: ... cb=[BaseProactorEventLoop._loop_self_reading()]
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    gwy = Gateway(serial_port, loop=loop, **config)

    # task = asyncio.create_task(gwy.start())
    # _protocol, _transport = create_ramses_client(gwy, protocol_factory, process_msg)

    try:
        task = asyncio.create_task(gwy.start())
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
                print(json.dumps(schedule, indent=4))

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
cli.add_command(monitor)
cli.add_command(parse)

if __name__ == "__main__":
    cli()

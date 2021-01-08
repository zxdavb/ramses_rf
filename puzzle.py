#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""A CLI for the evohome_rf library.

    evohome_rf is used to parse/process Honeywell's RAMSES-II packets.
    """
import asyncio
from datetime import datetime as dt
import json
import shutil
import sys
from typing import Tuple

import click
from colorama import init as colorama_init, Fore, Style

from evohome_rf import (  # noqa
    DISABLE_DISCOVERY,
    DISABLE_SENDING,
    ENFORCE_ALLOWLIST,
    EVOFW_FLAG,
    INPUT_FILE,
    PACKET_LOG,
    REDUCE_PROCESSING,
    SERIAL_PORT,
    Gateway,
    GracefulExit,
)
from evohome_rf.const import COMMAND_FORMAT
from evohome_rf.helpers import dts_to_hex
from evohome_rf.schema import USE_NAMES

ALLOW_LIST = "allowlist"
DEBUG_MODE = "debug_mode"
EXECUTE_CMD = "execute_cmd"

CONFIG = "config"
COMMAND = "command"

CONSOLE_COLS = int(shutil.get_terminal_size(fallback=(2e3, 24)).columns - 1)

DONT_CREATE_MESSAGES = 3
DONT_CREATE_ENTITIES = 2
DONT_UPDATE_ENTITIES = 1

DEFAULT_INTERVAL = 0.5  # should be 3

LOWER_FREQ = 0x216200
MIDDLE_FREQ = 0x21656A
UPPER_FREQ = 0x216800

DEBUG_ADDR = "0.0.0.0"
DEBUG_PORT = 5678

COLORS = {" I": Fore.GREEN, "RP": Fore.CYAN, "RQ": Fore.CYAN, " W": Fore.MAGENTA}

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

LIB_KEYS = (
    INPUT_FILE,
    SERIAL_PORT,
    EVOFW_FLAG,
    PACKET_LOG,
    REDUCE_PROCESSING,
)


def _proc_kwargs(obj, kwargs) -> Tuple[dict, dict]:
    lib_kwargs, cli_kwargs = obj
    lib_kwargs[CONFIG].update({k: v for k, v in kwargs.items() if k in LIB_KEYS})
    cli_kwargs.update({k: v for k, v in kwargs.items() if k not in LIB_KEYS})
    return lib_kwargs, cli_kwargs


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option("-z", "--debug-mode", count=True, help="enable debugger")
@click.option("-r", "--reduce-processing", count=True, help="-rrr will give packets")
@click.option("-c", "--config-file", type=click.File("r"))
@click.pass_context
def cli(ctx, config_file=None, **kwargs):
    """A CLI for the evohome_rf library."""

    if kwargs[DEBUG_MODE]:
        import debugpy

        debugpy.listen(address=(DEBUG_ADDR, DEBUG_PORT))
        print(f"Debugging is enabled, listening on: {DEBUG_ADDR}:{DEBUG_PORT}.")
        print(" - execution paused, waiting for debugger to attach...")
        debugpy.wait_for_client()
        print(" - debugger is now attached, continuing execution.")

    lib_kwargs, cli_kwargs = _proc_kwargs(({CONFIG: {}}, {}), kwargs)

    if config_file is not None:
        lib_kwargs.update(json.load(config_file))

    lib_kwargs[DEBUG_MODE] = cli_kwargs[DEBUG_MODE] > 1

    red_proc = max((kwargs[REDUCE_PROCESSING], 2))
    lib_kwargs[CONFIG][REDUCE_PROCESSING] = kwargs[REDUCE_PROCESSING] = red_proc
    lib_kwargs[CONFIG][USE_NAMES] = False

    lib_kwargs[ALLOW_LIST] = {"18:000730": {}}  # TODO: messy
    lib_kwargs[CONFIG][ENFORCE_ALLOWLIST] = True
    lib_kwargs[CONFIG][DISABLE_SENDING] = True  # bypassed by calling _write_data
    # lib_kwargs[CONFIG][DISABLE_DISCOVERY] = True

    ctx.obj = lib_kwargs, kwargs


class PortCommand(click.Command):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params.insert(0, click.Argument(("serial-port",)))
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
                help="Pass this traceflag to evofw",
            ),
        )


@click.command(cls=PortCommand)
@click.option(
    "-c",
    "--count",
    type=int,
    default=10,
    help="number of packets to listen for"
)
@click.option(
    "-i",
    "--interval",
    type=float,
    default=DEFAULT_INTERVAL,
    help="expected interval (secs) between packets",
)
@click.pass_obj
def tune(obj, **kwargs):
    """Spawn the puzzle listener."""
    kwargs["interval"] = max((int(kwargs["interval"] * 100) / 100, 0.05))

    lib_kwargs, cli_kwargs = _proc_kwargs(obj, kwargs)
    # lib_kwargs[CONFIG][DISABLE_SENDING] = True

    asyncio.run(main(lib_kwargs, command="tune", **cli_kwargs))


@click.command(cls=PortCommand)
@click.option(
    "-c",
    "--count",
    type=int,
    default=0,
    help="number of packets to send (0 is unlimited)"
)
@click.option(
    "-i",
    "--interval",
    type=float,
    default=DEFAULT_INTERVAL,
    help="minimum interval (secs) between packets",
)
@click.pass_obj
def cast(obj, **kwargs):  # HACK: remove?
    """Spawn the puzzle caster."""
    kwargs["interval"] = max((int(kwargs["interval"] * 100) / 100, 0.05))

    lib_kwargs, cli_kwargs = _proc_kwargs(obj, kwargs)
    # lib_kwargs[CONFIG][DISABLE_SENDING] = False

    asyncio.run(main(lib_kwargs, command="cast", **cli_kwargs))


async def puzzle_tx(gwy, pkt_protocol, interval=None, count=0, length=48, **kwargs):
    async def _periodic(counter):
        _data = f"7F{dts_to_hex(dt.now())}7F{counter % 0x10000:04X}7F{int_hex}7F"
        data = COMMAND_FORMAT.format(
            " I", "18:000730", "63:262142", "7FFF", length, _data.ljust(length * 2, 'F')
        )
        await pkt_protocol._write_data(bytes(f"{data}\r\n".encode("ascii")))
        await asyncio.sleep(interval)

    int_hex = f"{int(interval * 100):04X}"

    if count <= 0:
        counter = 0
        while True:
            await _periodic(counter)
            counter += 1
    else:
        for counter in range(count):
            await _periodic(counter)


async def puzzle_rx(gwy, pkt_protocol, interval=None, count=0, **kwargs):
    def process_message(msg) -> None:
        dtm = f"{msg.dtm:%H:%M:%S.%f}"[:-3]
        print(f"{Style.BRIGHT}{COLORS.get(msg.verb)}{dtm} {msg}"[:CONSOLE_COLS])

    gwy.create_client(process_message)


async def main(lib_kwargs, **kwargs):
    def print_message(msg) -> None:
        dtm = f"{msg.dtm:%H:%M:%S.%f}"[:-3]
        print(f"{Style.BRIGHT}{COLORS.get(msg.verb)}{dtm} {msg}"[:CONSOLE_COLS])

    def print_results(**kwargs):
        pass

    print("\r\nclient.py: Starting evohome_rf (puzzler)...")

    if sys.platform == "win32":  # is better than os.name
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    if kwargs[REDUCE_PROCESSING] < DONT_CREATE_MESSAGES:
        colorama_init(autoreset=True)

    gwy = Gateway(lib_kwargs[CONFIG].pop(SERIAL_PORT, None), **lib_kwargs)
    gwy.create_client(print_message)

    task = asyncio.create_task(gwy.start())
    while gwy.pkt_protocol is None:
        await asyncio.sleep(0.05)
    pkt_protocol = gwy.pkt_protocol

    if kwargs[COMMAND] == "cast":
        asyncio.create_task(puzzle_tx(gwy, pkt_protocol, **kwargs))
    else:  # kwargs[COMMAND] == "tune":
        asyncio.create_task(puzzle_rx(gwy, pkt_protocol, **kwargs))

    try:  # main code here
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

    if kwargs[COMMAND] == "tune":
        print_results(**kwargs)

    print("\r\nclient.py: Finished evohome_rf.\r\n")


cli.add_command(tune)
cli.add_command(cast)

if __name__ == "__main__":
    cli()


# The strategy to tune is to start with FREQ values that you expect to fail well
# away from the standard value of 21 65 6A
# Do the low limit by starting at say 21 62 00 and binary chop towards the
# standard frequency.
# Listen for messages and if you detect ANYTHING (including reported errors)
# you're too close to the standard so move back towards the lower limit.
# If you decide you've detected nothing move towards the  standard frequency.
# Eventually you will find the highest frequency where you cannot detect anything.
# Repeat for the high limit starting at say 21 68 00
# The tuned value is the average of the high and low values.

# The command to change the FREQ value is
# !C rr aa bb cc dd
# bb, cc and dd are optional.

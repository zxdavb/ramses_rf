#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""A CLI for the evohome_rf library.

    evohome_rf is used to parse/process Honeywell's RAMSES-II packets.
    """
import asyncio
from datetime import datetime as dt, timedelta as td
import json
import logging
import sys
from threading import Lock
from typing import ByteString, Optional, Tuple

import click
from colorama import init as colorama_init, Fore, Style

from evohome_rf import Gateway, GracefulExit
from evohome_rf.command import Command, Priority
from evohome_rf.helpers import dts_to_hex
from evohome_rf.packet import CONSOLE_COLS, _PKT_LOGGER, Packet
from evohome_rf.protocol import create_protocol_factory
from evohome_rf.transport import PacketProtocol, create_pkt_stack
from evohome_rf.schema import (
    ALLOW_LIST,
    DISABLE_DISCOVERY,
    DISABLE_SENDING,
    DONT_CREATE_ENTITIES,
    ENFORCE_ALLOWLIST,
    EVOFW_FLAG,
    INPUT_FILE,
    PACKET_LOG,
    REDUCE_PROCESSING,
    SERIAL_PORT,
    USE_NAMES,
)

pkt_lock = Lock()
pkt_seen = None
pkt_counting = None

DEBUG_MODE = "debug_mode"

CONFIG = "config"
COMMAND = "command"

DEFAULT_INTERVAL = 240  # should be 240
QUIESCE_PERIOD = 0.5

FREQ_WIDTH = 0x002000
BASIC_FREQ = 0x21656A

DEBUG_ADDR = "0.0.0.0"
DEBUG_PORT = 5678

COLORS = {" I": Fore.GREEN, "RP": Fore.CYAN, "RQ": Fore.CYAN, " W": Fore.MAGENTA}

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

LIB_KEYS = (INPUT_FILE, SERIAL_PORT, EVOFW_FLAG, PACKET_LOG, REDUCE_PROCESSING)

_LOGGER = logging.getLogger(__name__)
_LOGGER.setLevel(logging.INFO)


class BasedIntParamType(click.ParamType):
    name = "integer"

    def convert(self, value, param, ctx):
        try:
            if isinstance(value, int):
                return value
            elif value[:2].lower() == "0x":
                return int(value[2:], 16)
            elif value[:1] == "0":
                return int(value, 8)
            elif isinstance(value, str):
                return int(value, 10)
            return int(value)
        except TypeError:
            self.fail(
                "expected string for int() conversion, got "
                f"{value!r} of type {type(value).__name__}",
                param,
                ctx,
            )
        except ValueError:
            self.fail(f"{value!r} is not a valid integer", param, ctx)


class PuzzleProtocol(PacketProtocol):
    """Interface for a packet protocol."""

    pkt_callback = None

    def _data_received(  # sans QoS
        self, pkt_dtm: str, pkt_str: Optional[str], pkt_raw: Optional[ByteString] = None
    ) -> None:
        """Called when some normalised data is received (no QoS)."""

        pkt = Packet(pkt_dtm, pkt_str, raw_pkt=pkt_raw)
        if self._has_initialized is None:
            self._has_initialized = True

        if self.pkt_callback:
            self.pkt_callback(pkt)


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
        _LOGGER.info(f"Debugging is enabled, listening on: {DEBUG_ADDR}:{DEBUG_PORT}.")
        _LOGGER.info(" - execution paused, waiting for debugger to attach...")
        debugpy.wait_for_client()
        _LOGGER.info(" - debugger is now attached, continuing execution.")

    lib_kwargs, cli_kwargs = _proc_kwargs(({CONFIG: {}}, {}), kwargs)

    if config_file is not None:
        lib_kwargs.update(json.load(config_file))

    lib_kwargs[DEBUG_MODE] = cli_kwargs[DEBUG_MODE] > 1
    lib_kwargs[CONFIG][USE_NAMES] = False

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
    "-f",
    "--frequency",
    type=BasedIntParamType(),
    default=BASIC_FREQ,
    help="centre frequency (e.g. {BASIC_FREQ}",
)
@click.option(
    "-w",
    "--width",
    type=BasedIntParamType(),
    default=FREQ_WIDTH,
    help=f"width fro lower, upper frequencies (e.g. {FREQ_WIDTH}",
)
@click.option(
    "-c", "--count", type=int, default=1, help="number of packets to listen for"
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

    lib_kwargs[CONFIG][REDUCE_PROCESSING] = DONT_CREATE_ENTITIES

    lib_kwargs[CONFIG][DISABLE_SENDING] = True  # bypassed by calling _write_data

    asyncio.run(main(lib_kwargs, command="tune", **cli_kwargs))


@click.command(cls=PortCommand)
@click.option(  # --count
    "-c",
    "--count",
    type=int,
    default=0,
    help="number of packets to send (0 is unlimited)",
)
@click.option(  # --internal
    "-i",
    "--interval",
    type=float,
    default=DEFAULT_INTERVAL,
    help="minimum interval (secs) between packets",
)
# @click.option(  --packet_length
# "-l",
# "--packet_length",
# type=int,
# default=48,
# help="length of puzzle packet",
# )
@click.pass_obj
def cast(obj, **kwargs):  # HACK: remove?
    """Spawn the puzzle caster."""
    kwargs["interval"] = max((int(kwargs["interval"] * 100) / 100, 0.05))

    lib_kwargs, cli_kwargs = _proc_kwargs(obj, kwargs)

    lib_kwargs[CONFIG][REDUCE_PROCESSING] = max(
        (lib_kwargs[CONFIG][REDUCE_PROCESSING], DONT_CREATE_ENTITIES)
    )

    lib_kwargs[CONFIG][DISABLE_DISCOVERY] = True
    lib_kwargs[CONFIG][ENFORCE_ALLOWLIST] = False
    lib_kwargs[ALLOW_LIST] = {"18:000730": {}}  # TODO: messy

    asyncio.run(main(lib_kwargs, command="cast", **cli_kwargs))


async def puzzle_cast(gwy, pkt_protocol, interval=None, count=0, length=48, **kwargs):
    def print_message(msg) -> None:
        dtm = f"{msg.dtm:%H:%M:%S.%f}"[:-3]
        if msg.code == "7FFF":
            print(f"{Style.BRIGHT}{Fore.CYAN}{dtm} {msg}"[:CONSOLE_COLS])
        else:
            print(f"{Fore.GREEN}{dtm} {msg}"[:CONSOLE_COLS])

    async def cast_puzzle_pkt(ordinal):
        payload = f"7F{dts_to_hex(dt.now())}7F{ordinal % 0x10000:04X}7F{int_hex}7F"
        payload = payload.ljust(length * 2, "F")

        qos = {"priority": Priority.ASAP, "retries": 0}
        await msg_protocol.send_data(
            Command(" I", "63:262142", "7FFF", payload, qos=qos)
        )

    msg_protocol, _ = gwy.create_client(print_message)

    int_hex = f"{int(interval * 100):04X}"

    if count <= 0:
        counter = 0
        while True:
            asyncio.create_task(cast_puzzle_pkt(counter))
            await asyncio.sleep(interval)
            counter += 1
    else:
        for counter in range(count):
            asyncio.create_task(cast_puzzle_pkt(counter))
            await asyncio.sleep(interval)


async def puzzle_tune(
    gwy,
    pkt_protocol,
    frequency=BASIC_FREQ,
    width=FREQ_WIDTH,
    interval=None,
    count=3,
    **kwargs,
):
    def process_packet(pkt) -> None:
        global pkt_seen
        global pkt_counting

        pkt_lock.acquire()
        if not pkt.is_valid:
            msg = f"{Fore.CYAN}{pkt.dtm[11:23]}     {pkt._pkt_str}"
        elif not pkt_counting:
            msg = f"{Style.BRIGHT}{Fore.CYAN}{pkt.dtm[11:23]}     {pkt}"
        else:
            msg = f"{Style.BRIGHT}{Fore.CYAN}{pkt.dtm[11:23]} >>> {pkt}"
            pkt_seen = True
        pkt_lock.release()

        print(msg[:CONSOLE_COLS])

    async def set_freq(frequency):
        hex = f"{frequency:06X}"
        data = f"!C 0D {hex[:2]} {hex[2:4]} {hex[4:]}\r\n"
        await pkt_protocol._send_data(bytes(data.encode("ascii")))
        return frequency

    async def check_reception(freq, count, x, y) -> float:

        global pkt_seen
        global pkt_counting

        _LOGGER.info(
            f"  Checking {Style.BRIGHT}0x{freq:06X}{Style.NORMAL} for max. "
            f"{interval * count}s (x=0x{x:06X}, y=0x{y:06X}, width=0x{abs(x - y):06X})"
        )
        await set_freq(freq)
        await asyncio.sleep(QUIESCE_PERIOD)

        pkt_lock.acquire()
        _LOGGER.info("  - listening now (having waited for freq change to quiesce)")
        pkt_counting = True
        pkt_seen = False
        result = None
        pkt_lock.release()

        dtm_start = dt.now()
        dtm_end = dtm_start + td(seconds=interval * count)
        while dt.now() < dtm_end:
            await asyncio.sleep(0.005)

            pkt_lock.acquire()
            result = bool(pkt_seen)  # take a copy
            if result:
                pkt_counting = False
            pkt_lock.release()

            if result is True:
                break

        MSG = {
            True: "A valid packet was received",
            False: "No valid packets were received",
            None: "SOMETHING WENT WRONG",
        }

        _LOGGER.info(f"  - result = {MSG[result]}")
        print()
        return result

    async def binary_chop(x, y) -> Tuple[int, float]:  # 1, 2
        """Binary chop from x (the start) to y (the target)."""
        _LOGGER.info(f"Puzzling from 0x{x:06X} to 0x{y:06X}...")

        fudge = 1 if x < y else 0 if x == y else -1

        freq, result = int((x + y) / 2), None
        while freq not in (x, y):
            result = await check_reception(freq, count, x, y)
            x, y = (x, freq) if result is True else (freq, y)
            freq = int((x + y) / 2)

        return freq + (0 if result else fudge)

    async def do_a_round(lower, upper):
        print("")
        _LOGGER.info(f"STEP 0: Starting a round from 0x{lower:06X} to 0x{upper:06X}")

        _LOGGER.info(f"STEP 1: Calibrate up from 0x{lower:06X} to 0x{upper:06X}")
        lower_freq = await binary_chop(lower, upper)
        _LOGGER.info(f"Lower = 0x{lower_freq:06X} (upwards calibrated)")

        print("")
        _LOGGER.info(f"STEP 2: Calibrate down from 0x{upper:06X} to 0x{lower_freq:06X}")
        upper_freq = await binary_chop(upper, lower_freq)
        _LOGGER.info(f"Upper = 0x{upper_freq:06X} (downwards calibrated)")

        print("")
        _LOGGER.info(
            f"Average = 0x{int((lower_freq + upper_freq) / 2):06X} "
            f"(0x{lower_freq:06X}-0x{upper_freq:06X})"
        )

        return lower_freq, upper_freq

    _PKT_LOGGER.setLevel(logging.ERROR)

    # gwy.create_client(print_message)
    # gwy.create_client(process_message)
    pkt_protocol.pkt_callback = process_packet

    dtm_expires = dt.now() + td(seconds=3)
    while dt.now() < dtm_expires:
        await asyncio.sleep(0.1)
        if pkt_protocol._has_initialized:
            break
    # else:
    #     raise RuntimeError("Can't find serial interface")

    lower, upper = await do_a_round(frequency - width, frequency + width)

    print("")
    _LOGGER.info(f"OVERALL Result = 0x{int((lower + upper) / 2):06X}")

    # frequency = int((lower + upper) / 2)
    # width = int((frequency - lower) * 1.25)
    # lower, upper = l1, u1 = await do_a_round(frequency - width, frequency + width)

    # frequency = int((lower + upper) / 2)
    # width = int((frequency - lower) * 1.25)
    # lower, upper = l2, u2 = await do_a_round(frequency - width, frequency + width)

    # print("")
    # _LOGGER.info(f"OVERALL Result = 0x{int((l1 + l2 + u1 + u2) / 4):06X}")


async def main(lib_kwargs, **kwargs):
    async def start() -> None:
        pass

        protocol_factory = create_protocol_factory(
            PuzzleProtocol, gwy, gwy.msg_transport._pkt_receiver
        )

        gwy.pkt_protocol, gwy.pkt_transport = create_pkt_stack(
            gwy,
            gwy.msg_transport._pkt_receiver,
            serial_port=gwy.serial_port,
            protocol_factory=protocol_factory,
        )
        gwy._tasks.append(gwy.msg_transport._set_dispatcher(gwy.pkt_protocol.send_data))

    print("\r\nclient.py: Starting evohome_rf (puzzler)...")

    if sys.platform == "win32":  # is better than os.name?
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    colorama_init(autoreset=True)

    gwy = Gateway(lib_kwargs[CONFIG].pop(SERIAL_PORT, None), **lib_kwargs)

    await start()  # replaces asyncio.create_task(gwy.start())

    while gwy.pkt_protocol is None:
        await asyncio.sleep(0.05)

    if kwargs[COMMAND] == "cast":
        task = asyncio.create_task(puzzle_cast(gwy, gwy.pkt_protocol, **kwargs))
    else:  # kwargs[COMMAND] == "tune":
        task = asyncio.create_task(puzzle_tune(gwy, gwy.pkt_protocol, **kwargs))
    gwy._tasks.append(task)

    try:  # main code here
        await task  # await gather gwy_tasks

    except asyncio.CancelledError:
        # _LOGGER.info(" - exiting via: CancelledError (this is expected)")
        pass
    except GracefulExit:
        _LOGGER.info(" - exiting via: GracefulExit")
    except KeyboardInterrupt:
        _LOGGER.info(" - exiting via: KeyboardInterrupt")
    else:  # if no Exceptions raised, e.g. EOF when parsing
        # _LOGGER.info(" - exiting via: else-block (e.g. EOF when parsing)")
        pass

    print("\r\nclient.py: Finished evohome_rf.\r\n")


cli.add_command(tune)
cli.add_command(cast)

if __name__ == "__main__":
    cli()

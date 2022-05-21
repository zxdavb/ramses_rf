#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""A CLI (puzzle) for the ramses_rf library - RF tune.

ramses_rf is used to parse/process Honeywell's RAMSES-II packets.
"""

import asyncio
import json
import logging
import sys
from datetime import datetime as dt
from datetime import timedelta as td
from threading import Lock
from typing import ByteString, Optional, Tuple

import click
from colorama import Fore, Style
from colorama import init as colorama_init

from ramses_rf import Gateway, GracefulExit
from ramses_rf.command import Command, Priority
from ramses_rf.exceptions import EvohomeError
from ramses_rf.helpers import is_valid_dev_id
from ramses_rf.packet import _PKT_LOGGER, CONSOLE_COLS, Packet
from ramses_rf.protocol import create_protocol_factory
from ramses_rf.schema import (
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
from ramses_rf.transport import PacketProtocol, create_pkt_stack

device_id = None
pkt_counting = None
pkt_lock = Lock()
pkt_seen = None

CONFIG = "config"
COMMAND = "command"

DEFAULT_INTERVAL = 240  # should be 240
QUIESCE_PERIOD = 0.5

FREQ_WIDTH = 0x000800
BASIC_FREQ = 0x21656A

DEBUG_MODE = "debug_mode"
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


class DeviceIdParamType(click.ParamType):
    name = "device_id"

    def convert(self, value: str, param, ctx):
        if is_valid_dev_id(value):
            return value.upper()
        self.fail(f"{value!r} is not a valid device_id", param, ctx)


class LocalProtocol(PacketProtocol):
    """Interface for a packet protocol."""

    pkt_callback = None

    def _data_received(  # sans QoS
        self, pkt_dtm: str, pkt_str: Optional[str], pkt_raw: Optional[ByteString] = None
    ) -> None:
        """Called when some normalised data is received (no QoS)."""

        pkt = Packet(pkt_dtm, pkt_str, raw_pkt_line=pkt_raw)
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
    """A CLI for the ramses_rf library."""

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
@click.option(  # --frequency
    "-f",
    "--frequency",
    type=BasedIntParamType(),
    default=BASIC_FREQ,
    help="centre frequency (e.g. {BASIC_FREQ}",
)
@click.option(  # --width
    "-w",
    "--width",
    type=BasedIntParamType(),
    default=FREQ_WIDTH,
    help=f"width for lower, upper frequencies (e.g. {FREQ_WIDTH}",
)
@click.option(  # --device-id
    "-d",
    "--device-id",
    type=DeviceIdParamType(),
    default=None,
    help="device_id to filter for (e.g. 01:123456)",
)
@click.option(  # --count
    "-c", "--count", type=int, default=1, help="number of packets to listen for"
)
@click.option(  # --interval
    "-i",
    "--interval",
    type=float,
    default=DEFAULT_INTERVAL,
    help="minimum interval (secs) between packets",
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
    help="interval (secs) between sending packets",
)
# @click.option(  # --packet_length
#     "-l",
#     "--packet_length",
#     type=int,
#     default=48,
#     help="length of puzzle packet",
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

    async def cast_puzzle_pkt(ordinal):  # TODO: broken
        ordinal = ordinal % 0x10000
        qos = {"priority": Priority.HIGHEST, "retries": 0}
        await msg_protocol.send_data(
            Command._puzzle(
                "7F", ordinal=ordinal, interval=int_hex, length=length**qos
            )
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
        global device_id
        global pkt_counting
        global pkt_seen

        pkt_lock.acquire()
        if not pkt.is_valid:
            msg, hdr = f"{pkt.dtm[11:23]}     {pkt._pkt_str}", f"{Fore.CYAN}"
        elif not pkt_counting:
            msg, hdr = f"{pkt.dtm[11:23]}     {pkt}", f"{Style.BRIGHT}{Fore.CYAN}"
        elif device_id and device_id in (pkt.src_addr.id, pkt.dst_addr.id):
            msg, hdr = f"{pkt.dtm[11:23]}     {pkt}", f"{Style.BRIGHT}{Fore.CYAN}"
        else:
            msg, hdr = f"{pkt.dtm[11:23]} >>> {pkt}", f"{Style.BRIGHT}{Fore.CYAN}"
            pkt_seen = True
        pkt_lock.release()

        print(f"{hdr}{msg[:CONSOLE_COLS]}")

    async def set_freq(frequency):
        hex = f"{frequency:06X}"
        data = f"!C 0D {hex[:2]} {hex[2:4]} {hex[4:]}\r\n"
        await pkt_protocol._send_data(bytes(data.encode("ascii")))
        return frequency

    async def check_reception(freq, x, y) -> float:

        global pkt_seen
        global pkt_counting

        _LOGGER.info(
            f"  Checking {Style.BRIGHT}0x{freq:06X}{Style.NORMAL} for max. "
            f"{interval * count}s (x=0x{x:06X}, y=0x{y:06X}, width=0x{abs(x - y):06X})"
        )
        await set_freq(freq)
        await asyncio.sleep(QUIESCE_PERIOD)

        pkt_lock.acquire()
        _LOGGER.info("  - listening now (after having waited for freq to quiesce)")
        pkt_counting = True
        pkt_seen = False
        result = None
        pkt_lock.release()

        dtm_start = dt.now()
        dtm_end = dtm_start + td(seconds=interval * count + QUIESCE_PERIOD)
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

    async def binary_chop(x, y) -> int:  # 1, 2
        """Binary chop from x (the start) to y (the target).

        Assumes the initial value of x, y are negative, positive.
        """
        _LOGGER.info(f"Puzzling from 0x{x:06X} to 0x{y:06X}...")

        freq = int((x + y) / 2)
        while freq not in (x, y):
            pkt_found = await check_reception(freq, x, y)  # x, y used only for logging
            x, y = (x, freq) if pkt_found else (freq, y)
            freq = int((x + y) / 2)

        return y

    async def do_a_round(lower, upper):
        print("")
        _LOGGER.info(f"STEP 0: Starting a round from 0x{lower:06X} to 0x{upper:06X}")
        print("")

        _LOGGER.info(f"STEP 1: Calibrate up from 0x{lower:06X} to 0x{upper:06X}")
        lower_freq = await binary_chop(lower, upper)
        _LOGGER.info(f"Lower = 0x{lower_freq:06X} (walking upwards)")

        print("")
        _LOGGER.info(f"STEP 2: Calibrate down from 0x{upper:06X} to 0x{lower_freq:06X}")
        upper_freq = await binary_chop(upper, lower_freq)
        _LOGGER.info(f"Upper = 0x{upper_freq:06X} (walking downwards)")

        print("")
        _LOGGER.info(
            f"Average = 0x{int((lower_freq + upper_freq) / 2):06X} "
            f"(0x{lower_freq:06X}-0x{upper_freq:06X})"
        )

        return lower_freq, upper_freq

    global device_id

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

    device_id = kwargs.get("device_id")
    lower, upper = await do_a_round(frequency - width, frequency + width)

    result = int((lower + upper) / 2)
    print("")
    _LOGGER.info(
        f"{Style.BRIGHT}"
        f"OVERALL Result is: 0x{result:06X} (+/-0x{result - lower:04X}), "
        f"scan center was: 0x{frequency:06X} ({'-' if result > frequency else '+'}"
        f"0x{abs(result - frequency):04X}, +/-0x{width:04x})"
    )

    # frequency = int((lower + upper) / 2)
    # width = int((frequency - lower) * 1.25)
    # lower, upper = l1, u1 = await do_a_round(frequency - width, frequency + width)

    # frequency = int((lower + upper) / 2)
    # width = int((frequency - lower) * 1.25)
    # lower, upper = l2, u2 = await do_a_round(frequency - width, frequency + width)

    # print("")
    # _LOGGER.info(f"OVERALL Result = 0x{int((l1 + l2 + u1 + u2) / 4):06X}")


async def main(lib_kwargs, **kwargs):
    async def start(gwy) -> None:
        protocol_factory = create_protocol_factory(
            LocalProtocol, gwy, gwy.msg_transport._pkt_receiver
        )

        gwy.pkt_protocol, gwy.pkt_transport = create_pkt_stack(
            gwy,
            gwy.msg_transport._pkt_receiver,
            serial_port=gwy.ser_name,
            protocol_factory=protocol_factory,
        )
        gwy._tasks.append(gwy.msg_transport._set_dispatcher(gwy.pkt_protocol.send_data))

    print("\r\nclient.py: Starting ramses_rf (puzzler)...")

    if sys.platform == "win32":  # is better than os.name?
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    colorama_init(autoreset=True)

    gwy = Gateway(lib_kwargs[CONFIG].pop(SERIAL_PORT, None), **lib_kwargs)
    await start(gwy)  # replaces asyncio.create_task(gwy.start())

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
        msg = " - ended via: CancelledError (e.g. SIGINT)"
    except GracefulExit:
        msg = " - ended via: GracefulExit"
    except KeyboardInterrupt:
        msg = " - ended via: KeyboardInterrupt"
    except EvohomeError as err:
        msg = f" - ended via: EvohomeError: {err}"
    else:  # if no Exceptions raised, e.g. EOF when parsing
        msg = " - ended without error (e.g. EOF)"

    print(f"\r\nclient.py: Finished ramses_rf (puzzler).\r\n{msg}\r\n")


cli.add_command(tune)
cli.add_command(cast)

if __name__ == "__main__":
    cli()

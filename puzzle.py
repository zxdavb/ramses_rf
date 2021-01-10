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
import shutil
import sys
from threading import Lock
from typing import ByteString, Tuple

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
from evohome_rf.command import Command, Priority
from evohome_rf.helpers import dts_to_hex
from evohome_rf.packet import _PKT_LOGGER, PacketProtocol
from evohome_rf.protocol import WRITER_TASK, MessageTransport, create_pkt_stack
from evohome_rf.schema import USE_NAMES

count_lock = Lock()
count_rcvd = 0

ALLOW_LIST = "allowlist"
DEBUG_MODE = "debug_mode"
EXECUTE_CMD = "execute_cmd"

CONFIG = "config"
COMMAND = "command"

CONSOLE_COLS = int(shutil.get_terminal_size(fallback=(2e3, 24)).columns - 4)

DONT_CREATE_MESSAGES = 3
DONT_CREATE_ENTITIES = 2
DONT_UPDATE_ENTITIES = 1

DEFAULT_INTERVAL = 5  # should be 240

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

    def data_received(self, data: ByteString) -> None:
        """Called when some data is received."""
        _LOGGER.debug("PktProtocol.data_received(%s)", data)

        self._recv_buffer += data
        if b"\r\n" in self._recv_buffer:
            lines = self._recv_buffer.split(b"\r\n")
            self._recv_buffer = lines[-1]

            for line in lines[:-1]:
                self._data_received(line)

                if self.pkt_callback:
                    self.pkt_callback(line)


def create_protocol_factory(gwy, msg_handler: MessageTransport):
    def protocol_factory():
        # msg_handler._pkt_receiver is from MessageTransport
        return PuzzleProtocol(gwy, msg_handler._pkt_receiver)

    return protocol_factory


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
    red_proc = DONT_CREATE_MESSAGES
    lib_kwargs[CONFIG][REDUCE_PROCESSING] = kwargs[REDUCE_PROCESSING] = red_proc

    lib_kwargs[CONFIG][DISABLE_SENDING] = True  # bypassed by calling _write_data

    asyncio.run(main(lib_kwargs, command="tune", **cli_kwargs))


@click.command(cls=PortCommand)
@click.option(
    "-c",
    "--count",
    type=int,
    default=0,
    help="number of packets to send (0 is unlimited)",
)
@click.option(
    "-i",
    "--interval",
    type=float,
    default=DEFAULT_INTERVAL,
    help="minimum interval (secs) between packets",
)
# @click.option(
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
    red_proc = max((kwargs[REDUCE_PROCESSING], DONT_CREATE_ENTITIES))
    lib_kwargs[CONFIG][REDUCE_PROCESSING] = kwargs[REDUCE_PROCESSING] = red_proc

    lib_kwargs[CONFIG][DISABLE_DISCOVERY] = True

    lib_kwargs[ALLOW_LIST] = {"18:000730": {}}  # TODO: messy
    lib_kwargs[CONFIG][ENFORCE_ALLOWLIST] = False

    asyncio.run(main(lib_kwargs, command="cast", **cli_kwargs))


async def puzzle_cast(gwy, pkt_protocol, interval=None, count=0, length=48, **kwargs):
    def print_message(msg) -> None:
        dtm = f"{msg.dtm:%H:%M:%S.%f}"[:-3]
        if msg.code == "7FFF":
            print(f"{Style.BRIGHT}{Fore.CYAN}{dtm} {msg}"[:CONSOLE_COLS])
        else:
            print(f"{Fore.GREEN}{dtm} {msg}"[:CONSOLE_COLS])

    async def _periodic(ordinal):
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
            asyncio.create_task(_periodic(counter))
            await asyncio.sleep(interval)
            counter += 1
    else:
        for counter in range(count):
            asyncio.create_task(_periodic(counter))
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
    def print_message(msg) -> None:
        dtm = f"{msg.dtm:%H:%M:%S.%f}"[:-3]
        if msg.code == "7FFF":
            print(f"{Style.BRIGHT}{Fore.CYAN}{dtm} {msg}"[:CONSOLE_COLS])
        else:
            print(f"{Fore.GREEN}{dtm} {msg}"[:CONSOLE_COLS])

    def process_message(msg) -> None:
        global count_rcvd

        count_lock.acquire()
        count_rcvd += 1
        count_lock.release()

        # if msg.payload["interval"] != interval:
        #     raise RuntimeError("Intervals don't match")

    def process_packet(pkt_raw) -> None:
        global count_rcvd

        _LOGGER.info("%s", pkt_raw)

        if pkt_raw[:1] != b"#":
            pkt = pkt_protocol._create_pkt(pkt_raw)

            count_lock.acquire()
            count_rcvd = count_rcvd if count_rcvd is True else pkt.is_valid
            count_lock.release()

    async def set_freq(frequency):
        hex = f"{frequency:06X}"
        data = f"!C 0D {hex[:2]} {hex[2:4]} {hex[4:]}\r\n"
        await pkt_protocol._write_data(bytes(data.encode("ascii")))
        return frequency

    async def check_reception(freq, count, x, y) -> float:
        """Returns: 0.0 nothing, 0.5 invalid pkt, 1.0 valid packet."""

        global count_rcvd
        count_lock.acquire()
        count_rcvd = None
        count_lock.release()

        _LOGGER.info(
            f"  Checking 0x{freq:06X} for max. {interval * count}s "
            f"(x=0x{x:06X}, y=0x{y:06X}, width=0x{abs(x - y):06X})"
        )
        await set_freq(freq)

        dtm_start = dt.now()
        dtm_end = dtm_start + td(seconds=interval * count)
        while dt.now() < dtm_end:
            await asyncio.sleep(0.005)
            if count_rcvd is not None:
                break

        MSG = {
            True: "A valid packet was received",
            False: "An invalid packet was received",
            None: "No packets were received",
        }

        _LOGGER.info(f"    result = {MSG[count_rcvd]}")
        print()
        return count_rcvd

    async def binary_chop(x, y, threshold=0) -> Tuple[int, float]:  # 1, 2
        """Binary chop from x (the start) to y (the target)."""
        _LOGGER.info(f"Puzzling from 0x{x:06X} to 0x{y:06X}...")

        freq, result = int((x + y) / 2), None
        while freq not in (x, y):
            result = await check_reception(freq, count, x, y)
            x, y = (x, freq) if result is not None else (freq, y)
            freq = int((x + y) / 2)

        return freq, result

    async def do_a_round(lower, upper):
        print("")
        _LOGGER.info(f"STEP 0: Starting a round from 0x{lower:06X} to 0x{upper:06X}")

        _LOGGER.info(f"STEP 1: Calibrate up from 0x{lower:06X} to 0x{upper:06X}")
        lower_freq, _ = await binary_chop(lower, upper)
        _LOGGER.info(f"Lower = 0x{lower_freq:06X} (upwards calibrated)")

        print("")
        _LOGGER.info(f"STEP 2: Calibrate down from 0x{upper:06X} to 0x{lower_freq:06X}")
        upper_freq, _ = await binary_chop(upper, lower_freq)
        _LOGGER.info(f"Upper = 0x{lower_freq:06X} (downwards calibrated)")

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

    print("\r\nclient.py: Starting evohome_rf (puzzler)...")

    if sys.platform == "win32":  # is better than os.name
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    if kwargs[REDUCE_PROCESSING] < DONT_CREATE_MESSAGES:
        colorama_init(autoreset=True)

    gwy = Gateway(lib_kwargs[CONFIG].pop(SERIAL_PORT, None), **lib_kwargs)

    # asyncio.create_task(gwy.start())
    protocol_factory = create_protocol_factory(gwy, gwy.msg_transport)
    gwy.pkt_protocol, gwy.pkt_transport = create_pkt_stack(
        gwy, gwy.msg_transport, gwy.serial_port, protocol_factory=protocol_factory
    )
    if gwy.msg_transport:
        gwy._tasks.append(gwy.msg_transport.get_extra_info(WRITER_TASK))

    while gwy.pkt_protocol is None:
        await asyncio.sleep(0.05)
    pkt_protocol = gwy.pkt_protocol

    if kwargs[COMMAND] == "cast":
        task = asyncio.create_task(puzzle_cast(gwy, pkt_protocol, **kwargs))
    else:  # kwargs[COMMAND] == "tune":
        task = asyncio.create_task(puzzle_tune(gwy, pkt_protocol, **kwargs))

    try:  # main code here
        await task

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

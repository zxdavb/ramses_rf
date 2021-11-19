#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""A CLI for the ramses_rf library.

ramses_rf is used to parse/process Honeywell's RAMSES-II packets.
"""

# import cProfile
# import pstats

import asyncio
import json
import logging
import sys
from typing import Tuple

import click
from colorama import Fore, Style
from colorama import init as colorama_init

from ramses_rf import Gateway, GracefulExit, is_valid_dev_id
from ramses_rf.const import DONT_CREATE_MESSAGES
from ramses_rf.discovery import GET_FAULTS, GET_SCHED, SET_SCHED, spawn_scripts
from ramses_rf.protocol.exceptions import EvohomeError
from ramses_rf.protocol.logger import (
    CONSOLE_COLS,
    DEFAULT_DATEFMT,
    DEFAULT_FMT,
    LOG_FILE_NAME,
)
from ramses_rf.schema import (
    CONFIG,
    DISABLE_DISCOVERY,
    DISABLE_SENDING,
    ENABLE_EAVESDROP,
    ENFORCE_KNOWNLIST,
    EVOFW_FLAG,
    INPUT_FILE,
    KNOWN_LIST,
    PACKET_LOG,
    PACKET_LOG_SCHEMA,
    REDUCE_PROCESSING,
    SERIAL_PORT,
)

DEBUG_MODE = "debug_mode"

# this is called after import colorlog to ensure its handlers wrap the correct streams
logging.basicConfig(level=logging.WARNING, format=DEFAULT_FMT, datefmt=DEFAULT_DATEFMT)


EXECUTE = "execute"
LISTEN = "listen"
MONITOR = "monitor"
PARSE = "parse"

DEBUG_ADDR = "0.0.0.0"
DEBUG_PORT = 5678

COLORS = {" I": Fore.GREEN, "RP": Fore.CYAN, "RQ": Fore.CYAN, " W": Fore.MAGENTA}

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

LIB_KEYS = (
    SERIAL_PORT,
    INPUT_FILE,
    EVOFW_FLAG,
    PACKET_LOG,
    REDUCE_PROCESSING,
)


def normalise_config_schema(config) -> Tuple[str, dict]:
    """Convert a HA config dict into the client library's own format."""

    serial_port = config[CONFIG].pop(SERIAL_PORT, None)

    if config[CONFIG].get(PACKET_LOG):
        if not isinstance(config[CONFIG][PACKET_LOG], dict):
            config[CONFIG][PACKET_LOG] = PACKET_LOG_SCHEMA(
                {LOG_FILE_NAME: config[CONFIG][PACKET_LOG]}
            )
    else:
        config[CONFIG][PACKET_LOG] = {}

    return serial_port, config


def _proc_kwargs(obj, kwargs) -> Tuple[dict, dict]:
    lib_kwargs, cli_kwargs = obj
    lib_kwargs[CONFIG].update({k: v for k, v in kwargs.items() if k in LIB_KEYS})
    cli_kwargs.update({k: v for k, v in kwargs.items() if k not in LIB_KEYS})
    return lib_kwargs, cli_kwargs


def _convert_to_list(d: str) -> list:
    if not d or not str(d):
        return []
    return [c.strip() for c in d.split(",") if c.strip()]


def _arg_split(ctx, param, value):  # callback=_arg_split
    return [x.strip() for x in value.split(",")]


class DeviceIdParamType(click.ParamType):
    name = "device_id"

    def convert(self, value: str, param, ctx):
        if is_valid_dev_id(value):
            return value.upper()
        self.fail(f"{value!r} is not a valid device_id", param, ctx)


@click.group(context_settings=CONTEXT_SETTINGS)  # , invoke_without_command=True)
@click.option("-z", "--debug-mode", count=True, help="enable debugger")
@click.option("-r", "--reduce-processing", count=True, help="-rrr will give packets")
@click.option("-l/-nl", "--long-dates/--no-long-dates", default=None)
@click.option("-c", "--config-file", type=click.File("r"))
@click.option("-e/-ne", "--eavesdrop/--no-eavesdrop", default=None)
@click.option("-k", "--client-state", type=click.File("r"))
@click.option("-ns", "--hide-summary", is_flag=True, help="dont print any summarys")
@click.option("-s", "--show-summary", help="show these portions of schema/params/state")
@click.pass_context
def cli(ctx, config_file=None, **kwargs):
    """A CLI for the ramses_rf library."""

    # if ctx.invoked_subcommand is None:
    #     pass

    if 0 < kwargs[DEBUG_MODE] < 3:
        import debugpy

        debugpy.listen(address=(DEBUG_ADDR, DEBUG_PORT))
        print(f"Debugging is enabled, listening on: {DEBUG_ADDR}:{DEBUG_PORT}.")

        if kwargs[DEBUG_MODE] == 1:
            print(" - execution paused, waiting for debugger to attach...")
            debugpy.wait_for_client()
            print(" - debugger is now attached, continuing execution.")

    lib_kwargs, cli_kwargs = _proc_kwargs(({CONFIG: {}}, {}), kwargs)

    if config_file:
        lib_kwargs.update(json.load(config_file))

    lib_kwargs[DEBUG_MODE] = cli_kwargs[DEBUG_MODE] > 1
    lib_kwargs[CONFIG][REDUCE_PROCESSING] = kwargs[REDUCE_PROCESSING]
    lib_kwargs[CONFIG][ENABLE_EAVESDROP] = bool(cli_kwargs.pop("eavesdrop"))

    ctx.obj = lib_kwargs, kwargs


class FileCommand(click.Command):  # input-file file
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params.insert(
            0, click.Argument(("input-file",), type=click.File("r"), default=sys.stdin)
        )
        # NOTE: The following is useful for only for test/dev
        # self.params.insert(  # --packet-log
        #     1,
        #     click.Option(
        #         ("-o", "--packet-log"),
        #         type=click.Path(),
        #         help="Log all packets to this file",
        #     ),
        # )


class PortCommand(click.Command):  # serial-port port --packet-log xxx --evofw3-flag xxx
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params.insert(0, click.Argument(("serial-port",)))
        self.params.insert(  # --packet-log
            1,
            click.Option(
                ("-o", "--packet-log"),
                type=click.Path(),
                help="Log all packets to this file",
            ),
        )
        self.params.insert(  # --evofw-flag
            2,
            click.Option(
                ("-T", "--evofw-flag"),
                type=click.STRING,
                help="Pass this traceflag to evofw",
            ),
        )


@click.command(cls=FileCommand)  # parse a packet log, then stop
@click.pass_obj
def parse(obj, **kwargs):
    """Parse a log file for messages/packets."""

    lib_kwargs, cli_kwargs = _proc_kwargs(obj, kwargs)

    lib_kwargs[INPUT_FILE] = lib_kwargs[CONFIG].pop(INPUT_FILE)

    asyncio.run(main(PARSE, lib_kwargs, **cli_kwargs))


@click.command(cls=PortCommand)  # (optionally) execute a command/script, then monitor
@click.option("-d/-nd", "--discover/--no-discover", default=None)  # --no-discover
@click.option(  # --execute-cmd 'RQ 01:123456 1F09 00'
    "-x", "--exec-cmd", type=click.STRING, help="e.g. 'RQ 01:123456 1F09 00'"
)
@click.option(  # --execute-scr script device_id
    "-X",
    "--exec-scr",
    type=(str, DeviceIdParamType()),
    help="scan_disc|scan_full|scan_hard|bind device_id",
)
@click.option(  # --poll-devices device_id, device_id,...
    "--poll-devices", type=click.STRING, help="e.g. 'device_id, device_id, ...'"
)
@click.pass_obj
def monitor(obj, **kwargs):
    """Monitor (eavesdrop and/or probe) a serial port for messages/packets."""
    lib_kwargs, cli_kwargs = _proc_kwargs(obj, kwargs)

    if cli_kwargs["discover"] is None:
        cli_kwargs["discover"] = (
            cli_kwargs["exec_cmd"] is None
            and cli_kwargs["exec_scr"] is None
            and cli_kwargs["poll_devices"] is None
        )

    if cli_kwargs["discover"] is not None:
        lib_kwargs[CONFIG][DISABLE_DISCOVERY] = not cli_kwargs.pop("discover")

    allowed = lib_kwargs[KNOWN_LIST] = lib_kwargs.get(KNOWN_LIST, {})

    # for k in ("scan_disc", "scan_full", "scan_hard", "scan_xxxx"):
    #     cli_kwargs[k] = _convert_to_list(cli_kwargs.pop(k))
    #     allowed.update({d: None for d in cli_kwargs[k] if d not in allowed})

    # lib_kwargs[CONFIG]["poll_devices"] = _convert_to_list(
    #     cli_kwargs.pop("poll_devices")
    # )

    # if lib_kwargs[KNOWN_LIST]:
    #     lib_kwargs[CONFIG][ENFORCE_KNOWNLIST] = True

    asyncio.run(main(MONITOR, lib_kwargs, **cli_kwargs))


@click.command(cls=PortCommand)  # execute a (complex) script, then stop
@click.option(  # --get-faults ctl_id
    "--get-faults", type=DeviceIdParamType(), help="controller_id"
)
@click.option(  # --get-schedule ctl_id zone_idx|HW
    "--get-schedule",
    default=[None, None],
    type=(DeviceIdParamType(), str),
    help="controller_id, zone_idx (e.g. '0A', 'HW')",
)
@click.option(  # --set-schedule ctl_id zone_idx|HW
    "--set-schedule",
    default=[None, None],
    type=(DeviceIdParamType(), click.File("r")),
    help="controller_id, filename.json",
)
@click.pass_obj
def execute(obj, **kwargs):
    """Execute any specified scripts, return the results, then quit.

    Disables discovery, and enforces a strict allow_list.
    """
    lib_kwargs, cli_kwargs = _proc_kwargs(obj, kwargs)

    if lib_kwargs[CONFIG][DISABLE_DISCOVERY] is None:
        lib_kwargs[CONFIG][DISABLE_DISCOVERY] = False

    if cli_kwargs.get(GET_FAULTS):
        lib_kwargs[KNOWN_LIST] = {cli_kwargs[GET_FAULTS]: {}}

    elif cli_kwargs[GET_SCHED][0]:
        lib_kwargs[KNOWN_LIST] = {cli_kwargs[GET_SCHED][0]: {}}

    elif cli_kwargs[SET_SCHED][0]:
        lib_kwargs[KNOWN_LIST] = {cli_kwargs[SET_SCHED][0]: {}}

    if lib_kwargs[KNOWN_LIST]:
        lib_kwargs[CONFIG][ENFORCE_KNOWNLIST] = True

    asyncio.run(main(EXECUTE, lib_kwargs, **cli_kwargs))


@click.command(cls=PortCommand)  # (optionally) execute a command, then listen
@click.option(  # --execute-cmd 'RQ 01:123456 1F09 00'
    "-x", "--execute-cmd", type=click.STRING, help="e.g. 'RQ 01:123456 1F09 00'"
)
@click.pass_obj
def listen(obj, **kwargs):
    """Listen to (eavesdrop only) a serial port for messages/packets."""
    lib_kwargs, cli_kwargs = _proc_kwargs(obj, kwargs)

    lib_kwargs[CONFIG][DISABLE_SENDING] = True

    asyncio.run(main(LISTEN, lib_kwargs, **cli_kwargs))


def _print_results(gwy, **kwargs):

    if kwargs[GET_FAULTS]:
        fault_log = gwy.system_by_id[kwargs[GET_FAULTS]]._fault_log.fault_log

        if fault_log is None:
            print("No fault log, or failed to get the fault log.")
        else:
            [print(f"{k:02X}", v) for k, v in fault_log.items()]

    if kwargs[GET_SCHED][0]:
        system_id, zone_idx = kwargs[GET_SCHED]
        if zone_idx == "HW":
            zone = gwy.system_by_id[system_id].dhw
        else:
            zone = gwy.system_by_id[system_id].zone_by_idx[zone_idx]
        schedule = zone.schedule

        if schedule is None:
            print("Failed to get the schedule.")
        else:
            result = {"zone_idx": zone_idx, "schedule": schedule}
            print(">>> Schedule JSON begins <<<")
            print(json.dumps(result, indent=4))
            print(">>> Schedule JSON ended <<<")

    if kwargs[SET_SCHED][0]:
        system_id, _ = kwargs[GET_SCHED]

    # else:
    #     print(gwy.device_by_id[kwargs["device_id"]])


def _save_state(gwy):
    schema, msgs = gwy._get_state()

    with open("state_msgs.log", "w") as f:
        [f.write(f"{dtm} {pkt}\r\n") for dtm, pkt in msgs.items()]  # if not m._expired

    with open("state_schema.json", "w") as f:
        f.write(json.dumps(schema, indent=4))


def _print_state(gwy, **kwargs):
    (schema, packets) = gwy._get_state(include_expired=True)

    print(f"Schema  = {json.dumps(schema, indent=4)}\r\n")
    # print(f"Packets = {json.dumps(packets, indent=4)}\r\n")
    [print(f"{dtm} {pkt}") for dtm, pkt in packets.items()]


def _print_summary(gwy, **kwargs):
    entity = gwy.evo or gwy

    if not kwargs.get("hide_schema"):
        print(f"Schema[{repr(entity)}] = {json.dumps(entity.schema, indent=4)}\r\n")
        print(f"allow_list (hints) = {json.dumps(gwy._include, indent=4)}\r\n")

    # if not kwargs.get("hide_params"):
    #     print(f"Params[{repr(entity)}] = {json.dumps(entity.params, indent=4)}\r\n")

    # if not kwargs.get("hide_status"):
    #     print(f"Status[{repr(entity)}] = {json.dumps(entity.status, indent=4)}\r\n")

    # if kwargs.get("show_device"):
    #     devices = sorted(gwy.devices)
    #     # devices = [d for d in sorted(gwy.devices) if d not in gwy.evo.devices]

    #     schema = {d.id: d.schema for d in devices}
    #     print(f"Schema[devices] = {json.dumps({'schema': schema}, indent=4)}\r\n")
    #     params = {d.id: d.params for d in devices}
    #     print(f"Params[devices] = {json.dumps({'params': params}, indent=4)}\r\n")
    #     status = {d.id: d.status for d in devices}
    #     print(f"Status[devices] = {json.dumps({'status': status}, indent=4)}\r\n")


async def main(command, lib_kwargs, **kwargs):
    def process_message(msg) -> None:
        dtm = (
            msg.dtm.isoformat(timespec="microseconds")
            if kwargs["long_dates"]
            else f"{msg.dtm:%H:%M:%S.%f}"[:-3]
        )
        if msg.src and msg.src.type == "18":
            print(f"{Style.BRIGHT}{COLORS.get(msg.verb)}{dtm} {msg}"[:CONSOLE_COLS])
        # elif msg.code == "3B00":  # TODO: temp
        #     print(f"{Style.BRIGHT}{COLORS.get(msg.verb)}{dtm} {msg}"[:CONSOLE_COLS])
        else:
            print(f"{COLORS.get(msg.verb)}{dtm} {msg}"[:CONSOLE_COLS])

    print("\r\nclient.py: Starting ramses_rf...")

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    serial_port, lib_kwargs = normalise_config_schema(lib_kwargs)
    gwy = Gateway(serial_port, **lib_kwargs)

    if kwargs[REDUCE_PROCESSING] < DONT_CREATE_MESSAGES:
        # no MSGs will be sent to STDOUT, so send PKTs instead
        colorama_init(autoreset=True)  # TODO: remove strip=True
        protocol, _ = gwy.create_client(process_message)

    try:  # main code here
        if kwargs["client_state"]:
            print("Restoring client state...")
            state = json.load(kwargs["client_state"])
            await gwy._set_state(**state["data"]["client_state"])

        gwy_task = asyncio.create_task(gwy.start())

        if command == EXECUTE:
            tasks = spawn_scripts(gwy, **kwargs)
            await asyncio.gather(*tasks)

        # elif command == LISTEN:
        #     await gwy_task

        elif command == MONITOR:
            tasks = spawn_scripts(gwy, **kwargs)
            # await asyncio.sleep(5)
            # gwy.device_by_id["17:145039"].temperature = 19
            # gwy.device_by_id["34:145039"].temperature = 21.3
            await gwy_task

        else:
            await gwy_task

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

    print("\r\nclient.py: Finished ramses_rf, results:\r\n")

    if False:  # or kwargs["show_state"]:
        _print_state(gwy, **kwargs)

    elif command == EXECUTE:
        _print_results(gwy, **kwargs)

    elif not kwargs["hide_summary"]:
        _print_summary(gwy, **kwargs)

    # if kwargs["save_state"]:
    #    _save_state(gwy)

    print(f"\r\nclient.py: Finished ramses_rf.\r\n{msg}\r\n")


cli.add_command(parse)
cli.add_command(monitor)
cli.add_command(execute)
cli.add_command(listen)

if __name__ == "__main__":
    # profile = cProfile.Profile()

    try:
        # profile.run("cli()")
        cli()
    except SystemExit:
        pass

    # ps = pstats.Stats(profile)
    # ps.sort_stats(pstats.SortKey.TIME).print_stats(60)

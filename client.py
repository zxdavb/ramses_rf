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

import click
from colorama import Fore, Style
from colorama import init as colorama_init

from ramses_rf import Gateway, GracefulExit, is_valid_dev_id
from ramses_rf.const import DONT_CREATE_MESSAGES, SZ_ZONE_IDX
from ramses_rf.discovery import GET_FAULTS, GET_SCHED, SET_SCHED, spawn_scripts
from ramses_rf.protocol.exceptions import EvohomeError
from ramses_rf.protocol.logger import (
    CONSOLE_COLS,
    DEFAULT_DATEFMT,
    DEFAULT_FMT,
    LOG_FILE_NAME,
)
from ramses_rf.protocol.schema import SERIAL_PORT
from ramses_rf.schema import (
    DISABLE_DISCOVERY,
    DISABLE_SENDING,
    ENABLE_EAVESDROP,
    ENFORCE_KNOWN_LIST,
    EVOFW_FLAG,
    INPUT_FILE,
    PACKET_LOG,
    PACKET_LOG_SCHEMA,
    REDUCE_PROCESSING,
    SZ_CONFIG,
    SZ_KNOWN_LIST,
)

# skipcq: PY-W2000
from ramses_rf.const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    DEV_TYPE_MAP,
)

# skipcq: PY-W2000
from ramses_rf.const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    _0005,
    _000A,
    _000C,
    _1F09,
    _2309,
    _30C9,
)

DEBUG_MODE = "debug_mode"

# DEFAULT_SUMMARY can be: True, False, or None
SHOW_SCHEMA = False
SHOW_PARAMS = False
SHOW_STATUS = False
SHOW_KNOWNS = False
SHOW_TRAITS = False
SHOW_CRAZYS = False

PRINT_STATE = False  # print engine state
# GET_STATE = False  # get engine state
# SET_STATE = False  # set engine state

# this is called after import colorlog to ensure its handlers wrap the correct streams
logging.basicConfig(level=logging.WARNING, format=DEFAULT_FMT, datefmt=DEFAULT_DATEFMT)


EXECUTE = "execute"
LISTEN = "listen"
MONITOR = "monitor"
PARSE = "parse"

DEBUG_ADDR = "0.0.0.0"
DEBUG_PORT = 5678

COLORS = {
    I_: Fore.GREEN,
    RP: Fore.CYAN,
    RQ: Fore.CYAN,
    W_: Style.BRIGHT + Fore.MAGENTA,
}

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

LIB_KEYS = (
    SERIAL_PORT,
    INPUT_FILE,
    EVOFW_FLAG,
    PACKET_LOG,
    REDUCE_PROCESSING,
)


def normalise_config_schema(config) -> tuple[str, dict]:
    """Convert a HA config dict into the client library's own format."""

    serial_port = config[SZ_CONFIG].pop(SERIAL_PORT, None)

    if config[SZ_CONFIG].get(PACKET_LOG):
        if not isinstance(config[SZ_CONFIG][PACKET_LOG], dict):
            config[SZ_CONFIG][PACKET_LOG] = PACKET_LOG_SCHEMA(
                {LOG_FILE_NAME: config[SZ_CONFIG][PACKET_LOG]}
            )
    else:
        config[SZ_CONFIG][PACKET_LOG] = {}

    return serial_port, config


def _proc_kwargs(obj, kwargs) -> tuple[dict, dict]:
    lib_kwargs, cli_kwargs = obj
    lib_kwargs[SZ_CONFIG].update({k: v for k, v in kwargs.items() if k in LIB_KEYS})
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
@click.option("-c", "--config-file", type=click.File("r"))
@click.option("-rc", "--restore-cache", type=click.File("r"))
@click.option("-r", "--reduce-processing", count=True, help="-rrr will give packets")
@click.option("-lf", "--long-format", is_flag=True, help="dont truncate STDOUT")
@click.option("-e/-ne", "--eavesdrop/--no-eavesdrop", default=None)
@click.option("-g", "--print-state", count=True, help="print state (g=schema, gg=all)")
# @click.option(  # get_state
#     "--get-state/--no-get-state", default=GET_STATE, help="get the engine state",
# )
# @click.option(  # set_state
#     "--set-state/--no-set-state", default=SET_STATE, help="set the engine state",
# )
@click.option(  # show_schema
    "-k/-nk",
    "--show-schema/--no-show-schema",
    default=SHOW_SCHEMA,
    help="display system schema",
)
@click.option(  # show_params
    "-p/-np",
    "--show-params/--no-show-params",
    default=SHOW_PARAMS,
    help="display system params",
)
@click.option(  # show_status
    "-s/-ns",
    "--show-status/--no-show-status",
    default=SHOW_STATUS,
    help="display system state",
)
@click.option(  # show_knowns
    "-n/-nn",
    "--show-knowns/--no-show-knowns",
    default=SHOW_KNOWNS,
    help="display known_list (of devices)",
)
@click.option(  # show_traits
    "-t/-nt",
    "--show-traits/--no-show-traits",
    default=SHOW_TRAITS,
    help="display device traits",
)
@click.option(  # show_crazys
    "-x/-nx",
    "--show-crazys/--no-show-crazys",
    default=SHOW_CRAZYS,
    help="display crazy things",
)
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

    lib_kwargs, cli_kwargs = _proc_kwargs(({SZ_CONFIG: {}}, {}), kwargs)

    if config_file:
        lib_kwargs.update(json.load(config_file))

    lib_kwargs[DEBUG_MODE] = cli_kwargs[DEBUG_MODE] > 1
    lib_kwargs[SZ_CONFIG][REDUCE_PROCESSING] = kwargs[REDUCE_PROCESSING]
    lib_kwargs[SZ_CONFIG][ENABLE_EAVESDROP] = bool(cli_kwargs.pop("eavesdrop"))

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
        # self.params.insert(  # --no-discover
        #     1,
        #     click.Option(
        #         ("-d/-nd", "--discover/--no-discover"),
        #         is_flag=True,
        #         default=False,
        #         help="Log all packets to this file",
        #     ),
        # )
        self.params.insert(  # --packet-log
            2,
            click.Option(
                ("-o", "--packet-log"),
                type=click.Path(),
                help="Log all packets to this file",
            ),
        )
        self.params.insert(  # --evofw-flag
            3,
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

    lib_kwargs[INPUT_FILE] = lib_kwargs[SZ_CONFIG].pop(INPUT_FILE)

    asyncio.run(main(PARSE, lib_kwargs, **cli_kwargs))


@click.command(cls=PortCommand)  # (optionally) execute a command/script, then monitor
@click.option("-d/-nd", "--discover/--no-discover", default=None)  # --no-discover
@click.option(  # --exec-cmd 'RQ 01:123456 1F09 00'
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
            cli_kwargs["exec_scr"] is None and cli_kwargs["poll_devices"] is None
        )

    if cli_kwargs["discover"] is not None:
        lib_kwargs[SZ_CONFIG][DISABLE_DISCOVERY] = not cli_kwargs.pop("discover")

    lib_kwargs[SZ_KNOWN_LIST] = lib_kwargs.get(SZ_KNOWN_LIST, {})
    # allowed = lib_kwargs[SZ_KNOWN_LIST] = lib_kwargs.get(SZ_KNOWN_LIST, {})

    # for k in ("scan_disc", "scan_full", "scan_hard", "scan_xxxx"):
    #     cli_kwargs[k] = _convert_to_list(cli_kwargs.pop(k))
    #     allowed.update({d: None for d in cli_kwargs[k] if d not in allowed})

    # lib_kwargs[SZ_CONFIG]["poll_devices"] = _convert_to_list(
    #     cli_kwargs.pop("poll_devices")
    # )

    # if lib_kwargs[SZ_KNOWN_LIST]:
    #     lib_kwargs[SZ_CONFIG][ENFORCE_KNOWN_LIST] = True

    asyncio.run(main(MONITOR, lib_kwargs, **cli_kwargs))


@click.command(cls=PortCommand)  # execute a (complex) script, then stop
@click.option("-d/-nd", "--discover/--no-discover", default=None)  # --no-discover
@click.option(  # --exec-cmd 'RQ 01:123456 1F09 00'
    "-x", "--exec-cmd", type=click.STRING, help="e.g. 'RQ 01:123456 1F09 00'"
)
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

    if lib_kwargs[SZ_CONFIG].get(DISABLE_DISCOVERY) is None:
        lib_kwargs[SZ_CONFIG][DISABLE_DISCOVERY] = True

    if cli_kwargs[GET_FAULTS]:
        lib_kwargs[SZ_KNOWN_LIST] = {cli_kwargs[GET_FAULTS]: {}}

    elif cli_kwargs[GET_SCHED][0]:
        lib_kwargs[SZ_KNOWN_LIST] = {cli_kwargs[GET_SCHED][0]: {}}

    elif cli_kwargs[SET_SCHED][0]:
        lib_kwargs[SZ_KNOWN_LIST] = {cli_kwargs[SET_SCHED][0]: {}}

    if lib_kwargs.get(SZ_KNOWN_LIST):
        lib_kwargs[SZ_CONFIG][ENFORCE_KNOWN_LIST] = True

    asyncio.run(main(EXECUTE, lib_kwargs, **cli_kwargs))


@click.command(cls=PortCommand)  # (optionally) execute a command, then listen
@click.pass_obj
def listen(obj, **kwargs):
    """Listen to (eavesdrop only) a serial port for messages/packets."""
    lib_kwargs, cli_kwargs = _proc_kwargs(obj, kwargs)

    lib_kwargs[SZ_CONFIG][DISABLE_SENDING] = True

    asyncio.run(main(LISTEN, lib_kwargs, **cli_kwargs))


def print_results(gwy, **kwargs):

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
            result = {SZ_ZONE_IDX: zone_idx, "schedule": schedule}
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


def _print_engine_state(gwy, **kwargs):
    (schema, packets) = gwy._get_state(include_expired=True)

    if kwargs["print_state"] > 0:
        print(f"schema: {json.dumps(schema, indent=4)}\r\n")
    if kwargs["print_state"] > 1:
        print(f"packets: {json.dumps(packets, indent=4)}\r\n")
    # [print(f"{dtm} {pkt}") for dtm, pkt in packets.items()]


def print_summary(gwy, **kwargs):
    entity = gwy.tcs or gwy

    if kwargs.get("show_schema"):
        print(f"Schema[{entity}] = {json.dumps(entity.schema, indent=4)}\r\n")

        # schema = {d.id: d.schema for d in sorted(gwy.devices)}
        # print(f"Schema[devices] = {json.dumps({'schema': schema}, indent=4)}\r\n")

    if kwargs.get("show_params"):
        print(f"Params[{entity}] = {json.dumps(entity.params, indent=4)}\r\n")

        params = {d.id: d.params for d in sorted(gwy.devices)}
        print(f"Params[devices] = {json.dumps({'params': params}, indent=4)}\r\n")

    if kwargs.get("show_status"):
        print(f"Status[{entity}] = {json.dumps(entity.status, indent=4)}\r\n")

        status = {d.id: d.status for d in sorted(gwy.devices)}
        print(f"Status[devices] = {json.dumps({'status': status}, indent=4)}\r\n")

    if kwargs.get("show_knowns"):  # show device hints (show-knowns)
        print(f"allow_list (hints) = {json.dumps(gwy._include, indent=4)}\r\n")

    if kwargs.get("show_traits"):  # show device traits
        result = {
            d.id: d.traits  # {k: v for k, v in d.traits.items() if k[:1] == "_"}
            for d in sorted(gwy.devices)
        }
        print(json.dumps(result, indent=4), "\r\n")

    if kwargs.get("show_crazys"):
        for device in [d for d in gwy.devices if d.type == DEV_TYPE_MAP.CTL]:
            for code, verbs in device._msgz.items():
                if code in (_0005, _000C):
                    for verb in verbs.values():
                        for pkt in verb.values():
                            print(f"{pkt}")
            print()
        for device in [d for d in gwy.devices if d.type == DEV_TYPE_MAP.UFC]:
            for code in device._msgz.values():
                for verb in code.values():
                    for pkt in verb.values():
                        print(f"{pkt}")
            print()


async def main(command, lib_kwargs, **kwargs):
    def process_msg(msg, prev_msg=None) -> None:
        """Process the message as it arrives (a callback).

        In this case, the message is merely printed.
        """

        # if kwargs["long_format"]:  # HACK for test/dev
        #     print(
        #         f'{msg.dtm.isoformat(timespec="microseconds")} ... {msg._pkt}  # {msg.payload}'
        #     )
        #     # print(f'{msg.dtm.isoformat(timespec="microseconds")} ... {msg._pkt}  # ("{msg._pkt.src!r}", "{msg._pkt.dst!r}")')
        #     return

        if kwargs["long_format"]:
            dtm = msg.dtm.isoformat(timespec="microseconds")
            con_cols = CONSOLE_COLS
        else:
            dtm = f"{msg.dtm:%H:%M:%S.%f}"[:-3]
            con_cols = None

        if msg.src and msg.src.type == DEV_TYPE_MAP.HGI:
            print(f"{Style.BRIGHT}{COLORS.get(msg.verb)}{dtm} {msg}"[:con_cols])
        elif msg.code == _1F09 and msg.verb == I_:
            print(f"{Fore.YELLOW}{dtm} {msg}"[:con_cols])
        elif msg.code in (_000A, _2309, _30C9) and msg._has_array:
            print(f"{Fore.YELLOW}{dtm} {msg}"[:con_cols])
        else:
            print(f"{COLORS.get(msg.verb)}{dtm} {msg}"[:con_cols])

    print("\r\nclient.py: Starting ramses_rf...")

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    serial_port, lib_kwargs = normalise_config_schema(lib_kwargs)
    gwy = Gateway(serial_port, **lib_kwargs)

    if kwargs[REDUCE_PROCESSING] < DONT_CREATE_MESSAGES:
        # no MSGs will be sent to STDOUT, so send PKTs instead
        colorama_init(autoreset=True)  # TODO: remove strip=True
        gwy.create_client(process_msg)

    try:  # main code here
        if kwargs["restore_cache"]:
            print("Restoring client schema/state cache...")
            state = json.load(kwargs["restore_cache"])
            await gwy._set_state(**state["data"]["restore_cache"])

        await gwy.start()

        if command == EXECUTE:
            tasks = spawn_scripts(gwy, **kwargs)
            await asyncio.gather(*tasks)

        elif command in MONITOR:
            tasks = spawn_scripts(gwy, **kwargs)
            # await asyncio.sleep(5)
            # gwy.device_by_id["17:145039"].temperature = 19
            # gwy.device_by_id["34:145039"].temperature = 21.3
            await gwy.pkt_source

        else:  # elif command in (LISTEN, PARSE):
            await gwy.pkt_source

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

    # await gwy.stop()

    print("\r\nclient.py: Finished ramses_rf, results:\r\n")

    if kwargs["print_state"]:
        _print_engine_state(gwy, **kwargs)

    elif command == EXECUTE:
        print_results(gwy, **kwargs)

    print_summary(gwy, **kwargs)

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

"""Evohome RF logger/parser."""
import argparse
import asyncio
import os
import sys

import click

from evohome import Gateway

DEBUG_ADDR = "0.0.0.0"
DEBUG_PORT = 5678

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


def _parse_args():
    def extant_file(file_name):
        """Check that value is the name of a existant file."""
        if not os.path.exists(file_name):
            raise argparse.ArgumentTypeError(f"{file_name} does not exist")
        return file_name

    parser = argparse.ArgumentParser()

    group = parser.add_argument_group(title="packet source (one is required)")
    mutex = group.add_mutually_exclusive_group(required=True)
    mutex.add_argument("-s", "--serial_port", help="port to poll for packets")
    mutex.add_argument(
        "-i", "--input_file", type=extant_file, help="file to read for packets"
    )

    group = parser.add_argument_group(title="packet logging")
    group.add_argument(
        "-o",
        "--packet_log",
        nargs="?",
        const="packets.log",
        help="copy all received packets to file",
    )
    group.add_argument(
        "-d",
        "--database",
        nargs="?",
        const="packets.db",
        help="archive valid/filtered packets to sqlite DB",
    )

    group = parser.add_argument_group(title="known devices")
    group.add_argument(
        "-k",
        "--known_devices",
        nargs="?",
        const="known_devices.json",
        help="name and/or blacklist known devices",
    )
    group.add_argument(
        "-w",
        "--device_whitelist",
        action="store_true",
        help="process only packets with known, non-blacklisted devices",
    )
    # group.add_argument("-c", "--controller_id", type=str, action="store",
    #     help="controller to use in favour of discovery",
    # )

    # group = parser.add_argument_group(title="Packet filtering")
    # mutex = group.add_mutually_exclusive_group(required=True)
    # mutex.add_argument(
    #     "--whitelist",  # default=whitelist,
    #     nargs="*",
    #     default="",
    #     help="DONT USE - parse only packets matching these regular expressions",
    # )
    # mutex.add_argument(
    #     "--blacklist",
    #     nargs="*",
    #     help="DONT USE - don't parse any packets matching these strings",
    # )  # TODO: need to flesh out whitelist/blacklist

    group = parser.add_argument_group(title="packet processing")
    group.add_argument(
        "-r",
        "--raw_output",
        action="count",
        default=0,
        help="1=parse payloads, but don't maintain state, 2=validate packets only",
    )
    group.add_argument(
        "-m",
        "--message_log",
        nargs="?",
        const="messages.log",
        help="copy messages to file (includes errors)",
    )

    group = parser.add_argument_group(title="command options")
    group.add_argument(
        "-x", "--execute_cmd", action="store", help='e.g.: "RQ 01:145038 1F09 00"'
    )
    group.add_argument(
        "-p", "--probe_system", action="store_true", help="send discovery packets"
    )
    # group.add_argument(
    #     "--execute_macro", action="store", type=str, help="e.g. fault-log, schedule)",
    # )
    # group.add_argument(
    #     "--execute_file", action="store", type=str, help="execute a file of commands",
    # )

    group = parser.add_argument_group(title="debug options")
    group.add_argument(
        "-z", "--debug_mode", action="count", default=0, help="1=N/A, 2=enable, 3=wait"
    )

    args = parser.parse_args()

    if args.device_whitelist and not args.known_devices:
        parser.error("argument --device_whitelist: requires argument --known_devices")

    if args.execute_cmd and args.input_file:
        parser.error("argument --execute_cmd: not allowed with argument --input_file")

    if args.probe_system and args.input_file:
        parser.error("argument --probe_system: not allowed with argument --input_file")

    if args.probe_system and args.raw_output == 2:  # TODO: or is it 1
        parser.error("argument --probe_system: not allowed with argument -rr")

    if args.message_log and args.raw_output == 2:
        parser.error("argument --message_log: not allowed with argument -rr")

    return args


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option("-k", "--known-devices", help="TBD", type=click.Path())
@click.option("-w", "--device-whitelist", help="TBD", is_flag=True)
@click.option("-m", "--message_log", help="TBD", type=click.Path())
@click.option("-r", "--raw-output", help="TBD", count=True)
@click.option("-z", "--debug-mode", help="TBD", count=True)
@click.pass_context
# async def main(loop=None, **kwargs):
def cli(ctx, **kwargs):
    """A CLI for the evohome_rf library.

    evohome_rf is used to process RAMSES-II packets, either via RF or from a file.
    """
    ctx.obj = kwargs
    return


@click.command()
@click.argument("input-file", type=click.File("r"), default=sys.stdin)
@click.pass_obj
def parse(obj, **kwargs):
    """Parse a file for packets."""
    # print(f"parse: obj={obj}, kwargs={kwargs}")

    try:
        asyncio.run(main(**obj, **kwargs))
    except asyncio.CancelledError:
        pass


@click.command()
@click.argument("serial-port")
@click.option("-d", "--database", type=click.Path())
@click.option("-p", "--probe-system", help="TBD", is_flag=True)
@click.option("-x", "--execute-cmd", help="TBD")
@click.option("-T", "--evofw-flag", help="TBD")
@click.option("-C", "--ser2net", help="addr:port, e.g. '127.0.0.1:5001'")
@click.option(
    "-o", "--packet_log", help="TBD", type=click.Path(), default="packets.log"
)
@click.pass_obj
def monitor(obj, **kwargs):
    """Monitor a serial port for packets."""
    print(f"monitor: obj={obj}, kwargs={kwargs}")

    try:
        asyncio.run(main(**obj, **kwargs))
    except asyncio.CancelledError:
        pass


cli.add_command(monitor)
cli.add_command(parse)


async def main(loop=None, **kwargs):
    # loop=asyncio.get_event_loop() causes: 'NoneType' object has no attribute 'serial'
    """A CLI for the evohome_rf library."""

    if kwargs.get("debug_mode") == 1:
        print("Additional logging enabled (debugging not enabled).")
        # print(kwargs)
        pass

    elif kwargs.get("debug_mode") > 1:
        import ptvsd

        print(f"Debugging is enabled, listening on: {DEBUG_ADDR}:{DEBUG_PORT}.")
        ptvsd.enable_attach(address=(DEBUG_ADDR, DEBUG_PORT))

        if kwargs.get("debug_mode") > 2:
            print("Execution paused, waiting for debugger to attach...")
            ptvsd.wait_for_attach()
            print("Debugger is attached, continuing execution.")

    if sys.platform == "win32":  # better than os.name
        # ERROR:asyncio:Cancelling an overlapped future failed
        # future: ... cb=[BaseProactorEventLoop._loop_self_reading()]
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    gateway = Gateway(**kwargs, loop=loop)

    await gateway.start()


if __name__ == "__main__":
    cli()

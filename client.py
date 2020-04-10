"""Evohome RF logger/parser."""
import argparse
import asyncio
import os
import sys

from evohome import Gateway

DEBUG_ADDR = "172.27.0.138"
DEBUG_PORT = 5679


def _parse_args():
    def extant_file(file_name):
        """Check that value is the name of a existant file."""
        if not os.path.exists(file_name):
            raise argparse.ArgumentTypeError(f"{file_name} does not exist")
        return file_name

    parser = argparse.ArgumentParser()

    group = parser.add_argument_group(title="Packet source")
    mutex = group.add_mutually_exclusive_group(required=True)
    mutex.add_argument("-s", "--serial_port", help="port to poll for packets")
    mutex.add_argument(
        "-i",
        "--input_file",
        type=extant_file,
        help="file to read for packets (implies listen_only)",
    )

    group = parser.add_argument_group(title="Packet logging")
    group.add_argument(
        "-o",
        "--output_file",
        nargs="?",
        const="packets.log",
        help="copy all valid/filtered packets to file",
    )
    group.add_argument(
        "-d",
        "--database",
        nargs="?",
        const="packets.db",
        help="archive all valid packets to sqlite DB",
    )

    group = parser.add_argument_group(title="Payload parsing")
    mutex = group.add_mutually_exclusive_group()
    mutex.add_argument(
        "-r",
        "--raw_output",
        action="count",
        default=0,
        help="0=full payload parse, 1=validate structure, 2=no processing",
    )
    mutex.add_argument(
        "-m",
        "--message_log",
        nargs="?",
        const="messages.log",
        help="copy all decoded messages to file (in addition to stdout/stderr)",
    )

    group = parser.add_argument_group(title="Known devices")
    group.add_argument(
        "-k",
        "--known_devices",
        nargs="?",
        const="known_devices.json",
        help="friendly names for (your) or blacklist of (your neighbour's) devices",
    )
    group.add_argument(
        "-w",
        "--whitelist",
        action="store_true",
        help="accept only packets containing known devices that are not blacklisted",
    )
    # group.add_argument("-c", "--controller_id", type=str, action="store",
    #     help="controller to use in favour of discovery",
    # )

    # group = parser.add_argument_group(title="Filters", description="Parser filers")
    # group.add_argument(
    #     "--whitelist",  # default=whitelist,
    #     nargs="*",
    #     default="",
    #     help="DONT USE - parse only packets matching these regular expressions",
    # )
    group.add_argument(
        "--blacklist",
        nargs="*",
        help="DONT USE - don't parse any packets matching these strings",
    )

    group = parser.add_argument_group(title="Debug options")
    group.add_argument(
        "-l",
        "--listen_only",
        action="store_true",
        help="don't send any discovery packets (eavesdrop only)",
    )
    # group.add_argument(
    #     "--execute_macro",
    #     action="store",
    #     type=str,
    #     help="execute a defined script (discover, fault-log, schedule)",
    # )
    # group.add_argument(
    #     "--execute_file",
    #     action="store",
    #     type=str,
    #     help="execute a file of commands",
    # )
    group.add_argument(
        "-x",
        "--execute_cmd",
        action="store",
        type=str,
        # default="RQ 01:145038 1F09 00",
        help="<verb> <device_id> <code> <payload>",
    )
    group.add_argument(
        "-z", "--debug_mode", action="count", default=0, help="1=log, 2=enable, 3=wait",
    )

    args = parser.parse_args()

    if args.whitelist and not args.known_devices:
        parser.error("--whitelist requires --known_devices")

    return args


async def main(loop=None):
    """Main loop."""
    args = _parse_args()

    if args.debug_mode == 1:
        # print(f"Debugging not enabled, additional logging enabled.")
        pass

    elif args.debug_mode > 1:
        import ptvsd

        print(f"Debugging is enabled, listening on: {DEBUG_ADDR}:{DEBUG_PORT}.")
        ptvsd.enable_attach(address=(DEBUG_ADDR, DEBUG_PORT))

        if args.debug_mode > 2:
            print("Execution paused, waiting for debugger to attach...")
            ptvsd.wait_for_attach()
            print("Debugger is attached, continuing execution.")

    gateway = Gateway(**vars(args), loop=loop)

    await gateway.start()


if __name__ == "__main__":
    if sys.platform == "win32":  # better than os.name
        # ERROR:asyncio:Cancelling an overlapped future failed
        # future: ... cb=[BaseProactorEventLoop._loop_self_reading()]
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    asyncio.run(main())

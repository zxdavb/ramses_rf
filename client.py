"""Evohome serial."""
# https://stackoverflow.com/questions/18499497/how-to-process-sigterm-signal-gracefully

import argparse
import asyncio

from evohome import Gateway

DEBUG_ADDR = "172.27.0.138"
DEBUG_PORT = 5679


def _parse_args():
    parser = argparse.ArgumentParser()

    group = parser.add_argument_group(title="packet source")
    mutex = group.add_mutually_exclusive_group(required=True)  # one is required
    mutex.add_argument("-s", "--serial_port", help="port to poll for packets")
    mutex.add_argument(
        "-i", "--input_file", help="file to read for packets (implies listen_only)"
    )

    group = parser.add_argument_group(title="packet logging")
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

    group = parser.add_argument_group(title="payload parsing")
    mutex = group.add_mutually_exclusive_group()  # OK to have neither
    mutex.add_argument(
        "-r",
        "--raw_output",
        action="count",
        default=0,
        help="0=parse payloads, 1=process packets, 3=no packet processing",
    )
    mutex.add_argument(
        "-m",
        "--message_log",
        nargs="?",
        const="messages.log",
        help="copy all decoded messages to file (in addition to stdout/stderr)",
    )

    group = parser.add_argument_group(title="known devices")
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

    group = parser.add_argument_group(title="debugging bits")
    group.add_argument(
        "-l",
        "--listen_only",
        action="store_true",
        help="don't send any discovery packets (eavesdrop only)",
    )
    # group.add_argument(
    #     "--execute_script",
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
        "-z",
        "--debug_mode",
        action="count",
        default=0,
        help="1=debug logging, 2=enabled, 3=wait for attach",
    )

    args = parser.parse_args()

    if args.whitelist and not args.known_devices:
        parser.error("--whitelist requires --known_devices")

    return args


async def main(loop=None):
    """Main loop."""
    args = _parse_args()

    if args.debug_mode == 1:
        # print(f"Debugging is enabled, additional logging enabled.")
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


if __name__ == "__main__":  # called from CLI?
    asyncio.run(main())

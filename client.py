"""Evohome RF logger/parser."""
import argparse
import asyncio
import os
import sys

from evohome import Gateway

DEBUG_ADDR = "0.0.0.0"
DEBUG_PORT = 5678


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
        "-i", "--input_file", type=extant_file, help="file to read for packets",
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
        "-x", "--execute_cmd", action="store", help='e.g.: "RQ 01:145038 1F09 00"',
    )
    group.add_argument(
        "-l", "--learn_mode", action="store_true", help="send discovery packets",
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

    if args.execute_cmd and args.input_file:
        parser.error("argument --execute_cmd: not allowed with argument --input_file")

    if args.learn_mode and args.input_file:
        parser.error("argument --learn_mode: not allowed with argument --input_file")

    if args.device_whitelist and not args.known_devices:
        parser.error("argument --device_whitelist: requires argument --known_devices")

    if args.message_log and args.raw_output == 2:
        parser.error("argument --message_log: not allowed with argument -rr")

    return args


async def main(loop=None):
    # loop=asyncio.get_event_loop() causes: 'NoneType' object has no attribute 'serial'
    """Main loop."""
    args = _parse_args()

    if args.debug_mode == 1:
        print("Additional logging enabled (debugging not enabled).")
        print(args)
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

    try:
        asyncio.run(main())
    except asyncio.CancelledError:  # TODO: rubbish
        pass

"""Evohome serial."""
import asyncio

import argparse
import logging

from evohome import _CONSOLE, _LOGGER, Gateway

DEBUG_ADDR = "172.27.0.138"
DEBUG_PORT = 5679

BLACK_LIST = ["12:227486", "12:249582", "12:259810", "13:171587"]  # nextdoor
# BLACK_LIST += ["30:082155", "32:206250", "32:168090"]  # Nuaire

WHITE_LIST = [
    "01:145038",
    "07:045960",
    "13:237335",
    "13:106039",
    "12:010740",
    "34:136285",
    "34:205645",
    "34:064023",
    "34:092243",
    "04:189082",
    "04:189080",
    "04:056057",
    "04:056053",
    "04:056059",
    "04:189076",
    "04:189078",
    "04:056061",
]

_LOGGER.setLevel(logging.DEBUG)
_LOGGER.addHandler(_CONSOLE)


def _parse_args():
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group(required=True)  # one is required
    group.add_argument("-s", "--serial_port", help="poll port for packets")
    group.add_argument("-i", "--input_file", help="read file for packets")

    parser.add_argument("-o", "--output_file", help="copy valid packets to file")
    parser.add_argument("-d", "--database", help="copy valid packets to sqlite DB")

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--black_list",
        default=BLACK_LIST,
        help="discard all packets to/from these devices, e.g. ['32:654321']",
    )
    group.add_argument(
        "--white_list",
        # default=WHITE_LIST,
        help="accept any packets to/from these devices, e.g. ['01:123456', '13:654321']",
    )

    parser.add_argument(
        "-c",
        "--controller_id",
        type=str,
        action="store",
        help="controller to use in favour of discovery",
    )

    parser.add_argument(
        "-r",
        "--raw_output",
        action="store_true",
        help="display packets rather than messages",
    )
    parser.add_argument(
        "-l",
        "--listen_only",
        action="store_true",
        help="don't send any discovery packets",
    )
    parser.add_argument(
        "-x",
        "--execute_cmd",
        action="store",
        type=str,
        default="RQ 01:145038 1F09 00",
        help="VERB DEVICE_ID CODE PAYLOAD",
    )
    parser.add_argument(
        "-z",
        "--debug_mode",
        action="count",
        default=0,
        help="0=none, 1=enable_attach, 2=wait_for_attach",
    )

    return parser.parse_args()


async def main(loop):
    """Main loop."""
    args = _parse_args()

    if args.debug_mode > 0:
        import ptvsd  # pylint: disable=import-error

        print(f"Debugging is enabled, listening on: {DEBUG_ADDR}:{DEBUG_PORT}.")
        ptvsd.enable_attach(address=(DEBUG_ADDR, DEBUG_PORT))

        if args.debug_mode > 1:
            print("Waiting for debugger to attach...")
            ptvsd.wait_for_attach()
            print("Debugger is attached!")

    gateway = Gateway(**vars(args), loop=loop)

    await gateway.start()


if __name__ == "__main__":  # called from CLI?
    LOOP = asyncio.get_event_loop()
    LOOP.run_until_complete(main(LOOP))
    LOOP.close()

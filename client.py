"""Evohome serial."""
# https://stackoverflow.com/questions/18499497/how-to-process-sigterm-signal-gracefully

import argparse
import asyncio

from evohome import Gateway

DEBUG_ADDR = "172.27.0.138"
DEBUG_PORT = 5679

BLACK_LIST = ["12:227486", "12:249582", "12:259810", "13:171587"]  # nextdoor
BLACK_LIST += ["30:082155", "32:206250", "32:168090"]  # Nuaire

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


def _parse_args():
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group(required=True)  # one is required
    group.add_argument("-s", "--serial_port", help="port to poll for packets")
    group.add_argument("-i", "--input_file",  help="file to read for packets (implies listen_only)")

    parser.add_argument("-l", "--listen_only", action="store_true",
        help="don't send any discovery packets (eavesdrop only)",
    )

    parser.add_argument("-o", "--output_file",  default="packets.log",  help="copy all valid packets to file")
    parser.add_argument("-d", "--database",     default="packets.db",   help="copy all valid packets to sqlite DB")

    group = parser.add_mutually_exclusive_group()  # OK to have neither
    group.add_argument("-r", "--raw_output", action="store_true",
        help="display packets rather than decoded messages")
    group.add_argument("-m", "--message_log", default="messages.log",
        help="copy all decoded messages to file (in addition to stdout)")

    parser.add_argument("-n", "--lookup_file",  default="devices.json", help="friendly names, etc.")

    group = parser.add_mutually_exclusive_group()  # OK to have neither
    group.add_argument("--black_list", default=BLACK_LIST,
        help="TODO: ignore all packets sent to/from these devices",
    )
    group.add_argument("--white_list",  # default=WHITE_LIST,
        help="TODO: accept only packets sent to/from these devices",
    )

    # parser.add_argument("-c", "--controller_id", type=str, action="store",
    #     help="controller to use in favour of discovery",
    # )
    parser.add_argument("-x", "--execute_cmd", action="store", type=str,
        # default="RQ 01:145038 1F09 00",
        help="VERB DEVICE_ID CODE PAYLOAD",
    )
    parser.add_argument("-z", "--debug_mode", action="count", default=0,
        help="0=disabled, 1=enabled (no wait), 2=wait for attach",
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
            print("Execution paused. Waiting for debugger to attach...")
            ptvsd.wait_for_attach()
            print("Debugger is attached. Continuing execution.")

    gateway = Gateway(**vars(args), loop=loop)

    await gateway.start()


if __name__ == "__main__":  # called from CLI?

    LOOP = asyncio.get_event_loop()
    LOOP.run_until_complete(main(LOOP))
    LOOP.close()

"""Evohome serial."""
import asyncio

import argparse
import logging

import ptvsd  # pylint: disable=import-error

from evohome import _CONSOLE, _LOGGER, Gateway

DEBUG_MODE = True
DEBUG_ADDR = "172.27.0.138"
DEBUG_PORT = 5679


_LOGGER.setLevel(logging.DEBUG)
print(f"Debugging is enabled, listening on: {DEBUG_ADDR}:{DEBUG_PORT}.")
ptvsd.enable_attach(address=(DEBUG_ADDR, DEBUG_PORT))
_LOGGER.addHandler(_CONSOLE)

if DEBUG_MODE is True:
    print("Waiting for debugger to attach...")
    ptvsd.wait_for_attach()

    print("Debugger is attached!")


def _parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-m",
        "--monitor",
        action="store_true",
        required=False,
        help="listen to packets",
    )
    parser.add_argument(
        "-c", "--command", type=str, required=False, help="command to send",
    )

    parser.add_argument(
        "-p", "--port", type=str, required=False, help="serial port to use",
    )
    args = parser.parse_args()

    if bool(args.monitor) & bool(args.command):
        parser.error("--monitor and --command ...")
        return None

    return args


async def main(loop):
    """Main loop."""
    args = _parse_args()

    gateway = Gateway(serial_port=args.port, console_log=True, loop=loop)

    if not args.command or args.monitor:
        await gateway.start()


if __name__ == "__main__":  # called from CLI?
    LOOP = asyncio.get_event_loop()
    LOOP.run_until_complete(main(LOOP))
    LOOP.close()

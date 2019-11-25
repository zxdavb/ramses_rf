"""Evohome serial."""
import logging
import argparse

from evohome import _LOGGER, Gateway


DEBUG_MODE = False
# _LOGGER.setLevel(logging.DEBUG)

# if DEBUG_MODE is True:
import ptvsd  # pylint: disable=import-error

_LOGGER.setLevel(logging.DEBUG)
_LOGGER.warning("The debugger is enabled.")
ptvsd.enable_attach(address=("172.27.0.138", 5679))

if DEBUG_MODE is True:
    # import ptvsd  # pylint: disable=import-error

    # _LOGGER.setLevel(logging.DEBUG)
    # _LOGGER.warning("Waiting for debugger to attach...")
    # ptvsd.enable_attach(address=("172.27.0.138", 5679))

    ptvsd.wait_for_attach()
    _LOGGER.debug("Debugger is attached!")


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

    args = parser.parse_args()

    if bool(args.monitor) & bool(args.command):
        parser.error("--monitor and --command ...")
        return None

    return args


def main():
    """Main loop."""
    args = _parse_args()

    gateway = Gateway()

    if not args.command or args.monitor:
        gateway.start()


if __name__ == "__main__":  # called from CLI?
    main()

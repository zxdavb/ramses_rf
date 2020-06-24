"""A CLI for the evohome_rf library.

evohome_rf is used to parse Honeywell's RAMSES-II packets, either via RF or from a file.
"""
import asyncio
import json
import sys

import click

from evohome import Gateway, GracefulExit, DONT_CREATE_MESSAGES

DEBUG_ADDR = "0.0.0.0"
DEBUG_PORT = 5678

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option("-k", "--known-devices", help="TBD", type=click.Path())
@click.option("-w", "--device-whitelist", help="TBD", is_flag=True)
@click.option("-m", "--message-log", help="TBD", type=click.Path())
@click.option("-r", "--raw-output", help="TBD", count=True)
# @click.option("-d", "--database", help="TBD", type=click.Path())
@click.option("-z", "--debug-mode", help="TBD", count=True)
@click.pass_context
def cli(ctx, **kwargs):
    """A CLI for the evohome_rf library."""
    # if kwargs["debug_mode"]:
    #     print(f"cli(): ctx.obj={ctx.obj}, kwargs={kwargs}")

    if kwargs["raw_output"] >= DONT_CREATE_MESSAGES and kwargs["message_log"]:
        print(
            f"Raw output = {kwargs['raw_output']} (don't create messages),",
            f"so disabling message_log ({kwargs['message_log']})",
        )
        kwargs["message_log"] = False

    ctx.obj = kwargs


@click.command()
@click.argument("input-file", type=click.File("r"), default=sys.stdin)
@click.pass_obj
def parse(obj, **kwargs):
    """Parse a file for packets."""
    # if obj["debug_mode"]:
    #     print(f"parse(): obj={obj}, kwargs={kwargs}")

    debug_wrapper(**obj, **kwargs)


@click.command()
@click.argument("serial-port")
@click.option("-p", "--probe-system", help="TBD", is_flag=True)
@click.option("-x", "--execute-cmd", help="TBD")
@click.option("-T", "--evofw-flag", help="TBD")
@click.option("-C", "--ser2net-server", help="addr:port, e.g. '127.0.0.1:5001'")
@click.option(
    "-o", "--packet-log", help="TBD", type=click.Path(), default="packets.log"
)
@click.pass_obj
def monitor(obj, **kwargs):
    """Monitor a serial port for packets."""
    # if obj["debug_mode"]:
    #     print(f"monitor(): obj={obj}, kwargs={kwargs}")

    debug_wrapper(**obj, **kwargs)


def debug_wrapper(**kwargs):
    if kwargs["debug_mode"] == 1:
        print("Additional logging enabled (debugging not enabled).")

    elif kwargs.get("debug_mode") > 1:
        import ptvsd

        print(f"Debugging is enabled, listening on: {DEBUG_ADDR}:{DEBUG_PORT}.")
        ptvsd.enable_attach(address=(DEBUG_ADDR, DEBUG_PORT))

        if kwargs.get("debug_mode") > 2:
            print(" - execution paused, waiting for debugger to attach...")
            ptvsd.wait_for_attach()
            print(" - debugger is now attached, continuing execution.")

    asyncio.run(main(**kwargs))


async def main(loop=None, **kwargs):
    # loop=asyncio.get_event_loop() causes: 'NoneType' object has no attribute 'serial'
    print("Starting evohome_rf...")

    if sys.platform == "win32":  # better than os.name
        # ERROR:asyncio:Cancelling an overlapped future failed
        # future: ... cb=[BaseProactorEventLoop._loop_self_reading()]
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    try:
        gateway = Gateway(**kwargs, loop=loop)
        await gateway.start()

    except asyncio.CancelledError:
        print(" - exiting via: CancelledError (this is expected)")
    except GracefulExit:
        print(" - exiting via: GracefulExit")
    except KeyboardInterrupt:
        print(" - exiting via: KeyboardInterrupt")
    else:  # if no Exceptions raised, e.g. EOF when parsing
        print(" - exiting via: else-block (e.g. EOF when parsing)")
    finally:  # if all raised Exceptions handled (other than any in else)
        # print(" - state database:\r\n", gateway)  # or repr(gateway)
        print(" - devices:\r\n", json.dumps(gateway.evo._devices, indent=4))
        print(repr(gateway))

    print("Finished evohome_rf.")


cli.add_command(monitor)
cli.add_command(parse)

if __name__ == "__main__":
    cli()

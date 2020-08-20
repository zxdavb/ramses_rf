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

# this is needed only when debugging the client
# import ptvsd
# ptvsd.enable_attach(address=(DEBUG_ADDR, DEBUG_PORT))
# ptvsd.wait_for_attach()

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option(
    "-c",
    "--config-file",
    help="TBD",
    type=click.Path(),
    # default="evohome.json",
    # show_default=True,
)
@click.option("-m", "--message-log", help="TBD", type=click.Path())
@click.option("-r", "--raw-output", help="TBD", count=True)
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
@click.option("-x", "--execute-cmd", help="e.g.: RQ 01:123456 1F09 00")
@click.option("-T", "--evofw-flag", help="TBD")
@click.option(
    "-o",
    "--packet-log",
    help="TBD",
    type=click.Path(),
    default="packet.log",
    show_default=True,
)
@click.pass_obj
def monitor(obj, **kwargs):
    """Monitor a serial port for packets."""
    # if obj["debug_mode"]:
    #     print(f"monitor(): obj={obj}, kwargs={kwargs}")

    debug_wrapper(**obj, **kwargs)


def debug_wrapper(**kwargs):
    assert 0 <= kwargs["debug_mode"] <= 3

    if kwargs["debug_mode"] == 3:
        print("Additional logging enabled (debugging not enabled).")

    elif kwargs["debug_mode"] != 0:
        import ptvsd

        print(f"Debugging is enabled, listening on: {DEBUG_ADDR}:{DEBUG_PORT}.")
        ptvsd.enable_attach(address=(DEBUG_ADDR, DEBUG_PORT))

        if kwargs["debug_mode"] == 1:
            print(" - execution paused, waiting for debugger to attach...")
            ptvsd.wait_for_attach()
            print(" - debugger is now attached, continuing execution.")

    asyncio.run(main(**kwargs))


async def main(loop=None, **kwargs):
    # loop=asyncio.get_event_loop() causes: 'NoneType' object has no attribute 'serial'
    print("Starting evohome_rf...")
    gateway = None

    if sys.platform == "win32":  # is better than os.name
        # ERROR:asyncio:Cancelling an overlapped future failed
        # future: ... cb=[BaseProactorEventLoop._loop_self_reading()]
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    try:
        gateway = Gateway(**kwargs, loop=loop)
        task = asyncio.create_task(gateway.start())
        # await asyncio.sleep(20)
        # print(await gateway.evo.zones[0].name)
        await task

    except asyncio.CancelledError:
        print(" - exiting via: CancelledError (this is expected)")
    except GracefulExit:
        print(" - exiting via: GracefulExit")
    except KeyboardInterrupt:
        print(" - exiting via: KeyboardInterrupt")
    else:  # if no Exceptions raised, e.g. EOF when parsing
        print(" - exiting via: else-block (e.g. EOF when parsing)")

    if gateway.evo is not None:
        print(f"\r\nSchema[{gateway.evo.id}] = {json.dumps(gateway.evo.schema)}")
        print(f"\r\nParams[{gateway.evo.id}] = {json.dumps(gateway.evo.params)}")
        print(f"\r\nStatus[{gateway.evo.id}] = {json.dumps(gateway.evo.status)}")

    # else:
    print(f"\r\nSchema[gateway] = {json.dumps(gateway.schema)}")

    print("\r\nFinished evohome_rf.")


cli.add_command(monitor)
cli.add_command(parse)

if __name__ == "__main__":
    cli()

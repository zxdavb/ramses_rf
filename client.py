"""A CLI for the evohome_rf library.

evohome_rf is used to parse Honeywell's RAMSES-II packets, either via RF or from a file.
"""
import asyncio
import json
import sys

import click

from evohome import CONFIG_SCHEMA, __dev_mode__, Gateway, GracefulExit

DEBUG_ADDR = "0.0.0.0"
DEBUG_PORT = 5678

# this is needed only when debugging the client
# import ptvsd
# ptvsd.enable_attach(address=(DEBUG_ADDR, DEBUG_PORT))
# ptvsd.wait_for_attach()

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option("-z", "--debug-mode", help="TBD", count=True)
@click.option("-r", "--reduce-processing", help="TBD", count=True)
@click.option("-c", "--config-file", help="TBD", type=click.Path())
# @click.option("-C", "--controller-id", help="TBD")
@click.pass_context
def cli(ctx, **kwargs):
    """A CLI for the evohome_rf library."""
    # if kwargs["debug_mode"]:
    #     print(f"cli(): ctx.obj={ctx.obj}, kwargs={kwargs}")
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
@click.option("-p", "--enforce-probing", help="TBD", is_flag=True)
@click.option("-T", "--evofw-flag", help="TBD")
@click.option("-x", "--execute-cmd", help="e.g.: RQ 01:123456 1F09 00")
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


def debug_wrapper(config_file=None, **kwargs):
    # 1st: sort out any debug mode...
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

    # 2nd: merge CLI args with config file, if any, TODO: use a SCHEMA
    config_dict = {"schema": {}, "allow_list": {}, "block_list": {}}
    if config_file is not None:
        with open(config_file) as json_data:
            config_dict.update(json.load(json_data))

    config = CONFIG_SCHEMA(config_dict.pop("config", {}))
    if "enforce_probing" in kwargs:
        config["disable_probing"] = not kwargs.pop("enforce_probing")
    # config["input_file"] = kwargs.pop("input_file", None)
    config = {**config_dict, **config, **kwargs}

    print("config", config)
    serial_port = config.pop("serial_port", None)

    asyncio.run(main(serial_port, **config))


async def main(serial_port, loop=None, **config):

    # loop=asyncio.get_event_loop() causes: 'NoneType' object has no attribute 'serial'
    print("Starting evohome_rf...")

    if sys.platform == "win32":  # is better than os.name
        # ERROR:asyncio:Cancelling an overlapped future failed
        # future: ... cb=[BaseProactorEventLoop._loop_self_reading()]
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    gwy = None  # avoid 'possibly unbound' lint error
    try:
        gwy = Gateway(serial_port, loop=loop, **config)
        task = asyncio.create_task(gwy.start())
        # await asyncio.sleep(20)
        # print(await gwy.evo.zones[0].name)
        await task

    except asyncio.CancelledError:
        print(" - exiting via: CancelledError (this is expected)")
    except GracefulExit:
        print(" - exiting via: GracefulExit")
    except KeyboardInterrupt:
        print(" - exiting via: KeyboardInterrupt")
    else:  # if no Exceptions raised, e.g. EOF when parsing
        print(" - exiting via: else-block (e.g. EOF when parsing)")

    if True or gwy.evo is None:
        print(f"\r\nSchema[gateway] = {json.dumps(gwy.schema)}")
        print(f"\r\nParams[gateway] = {json.dumps(gwy.params)}")
        print(f"\r\nStatus[gateway] = {json.dumps(gwy.status)}")

    if __dev_mode__ and gwy.evo is not None:
        print(f"\r\nSchema[{gwy.evo.id}] = {json.dumps(gwy.evo.schema)}")
        print(f"\r\nParams[{gwy.evo.id}] = {json.dumps(gwy.evo.params)}")
        print(f"\r\nStatus[{gwy.evo.id}] = {json.dumps(gwy.evo.status)}")

    elif gwy.evo is not None:
        print(f"\r\nSchema[{gwy.evo.id}] = {json.dumps(gwy.evo.schema, indent=2)}")
        print(f"\r\nParams[{gwy.evo.id}] = {json.dumps(gwy.evo.params, indent=2)}")
        print(f"\r\nStatus[{gwy.evo.id}] = {json.dumps(gwy.evo.status, indent=2)}")

    print("\r\nFinished evohome_rf.")


cli.add_command(monitor)
cli.add_command(parse)

if __name__ == "__main__":
    cli()

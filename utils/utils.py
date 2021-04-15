#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""A CLI (utils) for the evohome_rf library - logarchiver.

evohome_rf is used to parse/process Honeywell's RAMSES-II packets.
"""

import asyncio
import json
import logging
import sqlite3
import sys
from typing import ByteString, Optional, Tuple

import click
from colorama import Fore, Style
from colorama import init as colorama_init

from evohome_rf import Gateway, GracefulExit
from evohome_rf.exceptions import EvohomeError
from evohome_rf.packet import CONSOLE_COLS, Packet
from evohome_rf.protocol import create_protocol_factory
from evohome_rf.schema import (
    DONT_CREATE_MESSAGES,
    ENFORCE_ALLOWLIST,
    INPUT_FILE,
    PACKET_LOG,
    REDUCE_PROCESSING,
    USE_NAMES,
)
from evohome_rf.transport import POLLER_TASK, PacketProtocolRead, create_pkt_stack

CONFIG = "config"
COMMAND = "command"
ARCHIVE = "archive"
DATABASE = "database"

DEBUG_MODE = "debug_mode"
DEBUG_ADDR = "0.0.0.0"
DEBUG_PORT = 5678

COLORS = {" I": Fore.GREEN, "RP": Fore.CYAN, "RQ": Fore.CYAN, " W": Fore.MAGENTA}

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

LIB_KEYS = (INPUT_FILE, PACKET_LOG)

SQL_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS packets (
        dtm     TEXT PRIMARY KEY,
        rssi    TEXT NOT NULL,
        verb    TEXT NOT NULL,
        seqn    TEXT NOT NULL,
        dev0    TEXT NOT NULL,
        dev1    TEXT NOT NULL,
        dev2    TEXT NOT NULL,
        code    TEXT NOT NULL,
        len     TEXT NOT NULL,
        payload TEXT NOT NULL
    ) WITHOUT ROWID;
"""
SQL_CREATE_INDEX = """
CREATE INDEX code_idx ON packets(code);
"""
SQL_UPSERT_ROW = """
INSERT INTO packets (
        dtm,
        rssi,
        verb,
        seqn,
        dev0,
        dev1,
        dev2,
        code,
        len,
        payload
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT DO NOTHING;
"""

_LOGGER = logging.getLogger(__name__)
_LOGGER.setLevel(logging.INFO)

counter = 0
last_pkt = None


class LocalProtocol(PacketProtocolRead):
    """Interface for a packet protocol."""

    pkt_callback = None

    def _data_received(  # sans QoS
        self, pkt_dtm: str, pkt_str: Optional[str], pkt_raw: Optional[ByteString] = None
    ) -> None:
        """Called when some normalised data is received (no QoS)."""

        pkt = Packet(pkt_dtm, pkt_str, raw_pkt_line=pkt_raw)
        if self._has_initialized is None:
            self._has_initialized = True

        if self.pkt_callback:
            self.pkt_callback(pkt)


def _proc_kwargs(obj, kwargs) -> Tuple[dict, dict]:
    lib_kwargs, cli_kwargs = obj
    lib_kwargs[CONFIG].update({k: v for k, v in kwargs.items() if k in LIB_KEYS})
    cli_kwargs.update({k: v for k, v in kwargs.items() if k not in LIB_KEYS})
    return lib_kwargs, cli_kwargs


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option("-z", "--debug-mode", count=True, help="enable debugger")
@click.option("-c", "--config-file", type=click.File("r"))
@click.pass_context
def cli(ctx, config_file=None, **kwargs):
    """A CLI for the evohome_rf library."""

    if kwargs[DEBUG_MODE]:
        import debugpy

        debugpy.listen(address=(DEBUG_ADDR, DEBUG_PORT))
        _LOGGER.info(f"Debugging is enabled, listening on: {DEBUG_ADDR}:{DEBUG_PORT}.")
        _LOGGER.info(" - execution paused, waiting for debugger to attach...")
        debugpy.wait_for_client()
        _LOGGER.info(" - debugger is now attached, continuing execution.")

    lib_kwargs, cli_kwargs = _proc_kwargs(({CONFIG: {}}, {}), kwargs)

    if config_file is not None:
        lib_kwargs.update(json.load(config_file))

    lib_kwargs[DEBUG_MODE] = cli_kwargs[DEBUG_MODE]
    lib_kwargs[CONFIG][USE_NAMES] = False

    ctx.obj = lib_kwargs, kwargs


class FileCommand(click.Command):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params.insert(
            0, click.Argument(("input-file",), type=click.File("r"), default=sys.stdin)
        )
        # self.params.insert(1, click.Option(("-r", "--process_level"), count=True))


@click.command(cls=FileCommand)
@click.option(  # --database
    "-d",
    "--database",
    type=click.Path(),
    default="packets.db",
)
@click.pass_obj
def archive(obj, **kwargs):
    """Archive packets to a SQLite database"""

    lib_kwargs, cli_kwargs = _proc_kwargs(obj, kwargs)

    lib_kwargs[INPUT_FILE] = lib_kwargs[CONFIG].pop(INPUT_FILE)
    lib_kwargs[CONFIG][REDUCE_PROCESSING] = DONT_CREATE_MESSAGES - 1
    lib_kwargs[CONFIG][ENFORCE_ALLOWLIST] = False

    asyncio.run(main(lib_kwargs, command="archive", **cli_kwargs))


async def main(lib_kwargs, **kwargs):
    async def start(gwy) -> None:
        protocol_factory = create_protocol_factory(LocalProtocol, gwy, None)

        gwy.pkt_protocol, gwy.pkt_transport = create_pkt_stack(
            gwy,
            None,
            packet_log=gwy._input_file,
            protocol_factory=protocol_factory,
        )
        if gwy.pkt_transport.get_extra_info(POLLER_TASK):
            gwy._tasks.append(gwy.pkt_transport.get_extra_info(POLLER_TASK))

    def setup_database(db_file: str):
        con = None
        try:
            con = sqlite3.connect(db_file)
        except sqlite3.Error as err:
            print(err)

        try:
            cur = con.cursor()
            cur.execute(SQL_CREATE_TABLE)
        except sqlite3.Error as err:
            print(err)

        return con

    def process_packet(pkt) -> None:
        global last_pkt

        def insert_pkt(pkt):
            global counter

            data_fields = (
                pkt.dtm,  # dtm
                pkt.packet[0:3],  # rssi
                pkt.packet[4:6],  # verb
                pkt.packet[7:10],  # seqn
                pkt.packet[11:20],  # dev0
                pkt.packet[21:30],  # dev1
                pkt.packet[31:40],  # dev2
                pkt.packet[41:45],  # code
                pkt.packet[46:49],  # len
                pkt.packet[50:],  # payload
            )

            try:
                # cur = con.cursor()
                cur.execute(SQL_UPSERT_ROW, data_fields)

            except sqlite3.Error as err:
                print(err)

            else:
                if counter % 1000 == 0:
                    msg, hdr = f"{pkt.dtm} {pkt}", f"{Style.BRIGHT}{Fore.CYAN}"
                    print(f"{hdr}{msg[:CONSOLE_COLS]}")
                elif counter % 1000 == 1:
                    con.commit()
                counter += 1

            return cur.lastrowid

        if not pkt.is_valid:
            # msg, hdr = f"{pkt.dtm} {pkt._pkt_str}", f"{Fore.MAGENTA}"
            # print(f"{hdr}{msg[:CONSOLE_COLS]}")
            return

        if last_pkt:
            if all(
                (
                    pkt.packet[4:6] == "RP",
                    pkt.packet[11:20] == last_pkt.packet[21:30],
                    pkt.packet[21:30] == last_pkt.packet[11:20],
                    pkt.packet[41:45] == last_pkt.packet[41:45],
                )
            ):
                insert_pkt(last_pkt)
            last_pkt = None

        elif pkt.packet[4:6] == "RQ" and pkt.packet[11:13] == "18":
            last_pkt = pkt
            return

        else:
            insert_pkt(pkt)

    global counter

    print("\r\nclient.py: Starting evohome_rf (utils)...")

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    colorama_init(autoreset=True)
    con = setup_database(kwargs[DATABASE])
    cur = con.cursor()

    gwy = Gateway(None, **lib_kwargs)
    await start(gwy)  # replaces asyncio.create_task(gwy.start())

    while gwy.pkt_protocol is None:
        await asyncio.sleep(0.05)
    gwy.pkt_protocol.pkt_callback = process_packet

    try:  # main code here
        await asyncio.gather(*gwy._tasks)

    except asyncio.CancelledError:
        msg = " - ended via: CancelledError (e.g. SIGINT)"
    except GracefulExit:
        msg = " - ended via: GracefulExit"
    except (KeyboardInterrupt, SystemExit):
        msg = " - ended via: KeyboardInterrupt"
    except EvohomeError as err:
        msg = f" - ended via: EvohomeError: {err}"
    else:  # if no Exceptions raised, e.g. EOF when parsing
        msg = " - ended without error (e.g. EOF)"

    con.commit()

    print(f"\r\nclient.py: Finished evohome_rf (utils).\r\n{msg}\r\n")
    print(f"  - uploaded {counter} rows\r\n")


cli.add_command(archive)

if __name__ == "__main__":
    cli()


SQL_CLEANUP_00 = """
    SELECT * FROM packets
    WHERE dev0 IN ("08:000730", "01:000730")
      OR dev1 IN ("08:000730", "01:000730");
"""  # before next query
SQL_CLEANUP_00 = """
    DELETE FROM packets
    WHERE dev0 IN ("08:000730", "01:000730")
      OR dev1 IN ("08:000730", "01:000730");
"""  # before next query

SQL_CHECK_01 = """
    SELECT substr('       ' || Count(*), -7, 7), * FROM packets
    GROUP BY code ORDER BY Count(*) DESC;
"""  # These will be the valid codes
SQL_CLEANUP_01 = """
    DELETE FROM packets
    WHERE verb = " W" and dev0 = "18:013393" and dev1 = "01:145038" and payload = "01";
"""  # before next query

SQL_CHECK_02 = """
    SELECT substr('       ' || Count(*), -7, 7), * FROM packets
    WHERE code not in (
        SELECT code FROM packets
        WHERE Substr(dev0, 1, 2) != "18"
        GROUP BY code ORDER BY code
    )
    GROUP BY code ORDER BY code DESC;
"""
SQL_CLEANUP_02 = """
    DELETE FROM packets
    WHERE code not in (
        SELECT code FROM packets
        WHERE Substr(dev0, 1, 2) != "18"
    ) and Substr(dev0, 1, 2) == "18";
"""

"""
sqlite3 -separator ' ' packets.db 'select * from packets' | grep -vE 'RQ ... 18:' | python client.py -rr parse > /dev/null  # noqa: E501
sqlite3 -separator ' ' packets.db 'select * from packets' | python client.py -rr parse > /dev/null                          # noqa: E501
"""

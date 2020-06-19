"""Evohome serial."""
import asyncio
from collections import deque
import json
import logging
import os
from queue import PriorityQueue
import signal
import sys
from threading import Lock

# from typing import Optional

from .command import Command, PAUSE_LONG
from .const import __dev_mode__  # INDEX_SQL, TABLE_SQL, INSERT_SQL,
from .logger import set_logging, BANDW_SUFFIX, COLOR_SUFFIX, CONSOLE_FMT, PKT_LOG_FMT
from .message import _LOGGER as msg_logger, Message
from .packet import _LOGGER as pkt_logger, Packet, PortPktProvider, file_pkts, port_pkts
from .ser2net import Ser2NetServer
from .system import EvohomeSystem

DONT_CREATE_MESSAGES = 3
DONT_CREATE_ENTITIES = 2
DONT_UPDATE_ENTITIES = 1

_LOGGER = logging.getLogger(__name__)
if __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)


async def schedule_task(delay, func, *args, **kwargs):
    """Start a coro after delay seconds."""

    async def scheduled_func(delay, func, *args, **kwargs):
        await asyncio.sleep(delay)
        await func(*args, **kwargs)

    asyncio.create_task(scheduled_func(delay, func, *args, **kwargs))


class GracefulExit(SystemExit):
    code = 1


class Gateway:
    """The gateway class."""

    def __init__(self, serial_port=None, loop=None, **config) -> None:
        """Initialise the class."""
        if config.get("debug_mode"):
            _LOGGER.setLevel(logging.DEBUG)  # should be INFO?
        _LOGGER.debug("Starting evohome_rf, **config = %s", config)

        self.serial_port = serial_port
        self.loop = loop if loop else asyncio.get_running_loop()  # get_event_loop()
        self.config = config

        config["input_file"] = config.get("input_file")
        config["known_devices"] = config.get("known_devices")
        config["raw_output"] = config.get("raw_output", 0)

        if self.serial_port and config["input_file"]:
            _LOGGER.warning(
                "Serial port specified (%s), so ignoring input file (%s)",
                self.serial_port,
                config["input_file"],
            )
            config["input_file"] = None

        config["listen_only"] = not config.get("probe_system")
        if config["input_file"]:
            config["listen_only"] = True

        if config["raw_output"] >= DONT_CREATE_MESSAGES:
            config["message_log"] = None
            _stream = (None, sys.stdout)
        else:
            _stream = (sys.stdout, None)

        set_logging(msg_logger, stream=_stream[0], file_name=config.get("message_log"))
        set_logging(
            pkt_logger,
            stream=_stream[1],
            file_name=config.get("packet_log"),
            file_fmt=PKT_LOG_FMT + BANDW_SUFFIX,
            cons_fmt=CONSOLE_FMT + COLOR_SUFFIX,
        )

        self.cmd_que = PriorityQueue(maxsize=200)
        self._buffer = deque()
        self._sched_zone = None
        self._sched_lock = Lock()

        # if config.get("ser2net_server"):
        self._relay = None

        # if config["known_devices"]:
        self.known_devices = {}
        self.dev_blacklist = []
        self.dev_whitelist = []

        # if config.get("database"):
        self._output_db = self._db_cursor = None

        # if config["raw_output"] > 0:
        self.evo = EvohomeSystem(controller_id=None)

        self._tasks = []
        self._setup_signal_handler()

    def __repr__(self) -> str:
        return json.dumps(self.evo.state_db, indent=4)

    def __str__(self) -> str:
        return json.dumps(self.evo.status, indent=4)

    def _setup_signal_handler(self):
        def _sig_handler_win32(signalnum, frame):
            """2 = signal.SIGINT (Ctrl-C)."""
            _LOGGER.info("Received a signal (signalnum=%s), processing...", signalnum)

            if signalnum == signal.SIGINT:  # is this the only useful win32 signal?
                self.cleanup("_sig_handler_win32()")

                raise GracefulExit()

        async def _sig_handler_posix(signal):
            """Handle signals on posix platform."""
            _LOGGER.info("Received a signal (%s), processing...", signal.name)

            if signal == signal.SIGUSR1:  # can also have: signal.SIGUSR2
                _LOGGER.info("Raw state data: \r\n%s", self.evo)

            if signal in [signal.SIGHUP, signal.SIGINT, signal.SIGTERM]:
                await self.async_cleanup("_sig_handler_posix()")  # before task.cancel
                self.cleanup("_sig_handler_posix()")  # OK for after tasks.cancel

                tasks = [
                    t for t in asyncio.all_tasks() if t is not asyncio.current_task()
                ]
                [task.cancel() for task in tasks]
                logging.info(f"Cancelling {len(tasks)} outstanding tasks...")

                # raise CancelledError
                await asyncio.gather(*tasks, return_exceptions=True)

        _LOGGER.debug("Creating signal handlers...")
        signals = [signal.SIGINT, signal.SIGTERM]

        if os.name == "nt":  # TODO: or is sys.platform better?
            for sig in signals + [signal.SIGBREAK]:
                signal.signal(sig, _sig_handler_win32)

        else:  # if os.name == "posix":
            for sig in signals + [signal.SIGHUP, signal.SIGUSR1, signal.SIGUSR2]:
                self.loop.add_signal_handler(
                    sig, lambda sig=sig: asyncio.create_task(_sig_handler_posix(sig))
                )

    async def async_cleanup(self, xxx=None) -> None:
        """Perform the async portion of a graceful shutdown."""

        _LOGGER.info("async_cleanup() invoked by: %s", xxx)

        if self._output_db:  # close packet database
            _LOGGER.info(f"async_cleanup(): Closing packets database...")
            await self._output_db.commit()
            await self._output_db.close()
            self._output_db = None  # TODO: is this needed - if re-entrant?

    def cleanup(self, xxx=None) -> None:
        """Perform the non-async portion of a graceful shutdown."""

        _LOGGER.info("cleanup() invoked by: %s", xxx)

        if self.config["known_devices"]:
            _LOGGER.info("cleanup(): Updating known_devices file...")
            try:
                for d in self.evo.devices:
                    device_attrs = {
                        "friendly_name": d._friendly_name,
                        "blacklist": d._blacklist,
                    }
                    if d.id in self.known_devices:
                        self.known_devices[d.id].update(device_attrs)
                    else:
                        self.known_devices[d.id] = device_attrs

                with open(self.config["known_devices"], "w") as json_file:
                    json.dump(self.known_devices, json_file, sort_keys=True, indent=4)

            except (AssertionError, AttributeError, LookupError, TypeError, ValueError):
                _LOGGER.exception("Failed update of %s", self.config["known_devices"])

    async def start(self) -> None:
        async def file_reader(fp):
            async for raw_pkt in file_pkts(fp):
                self._process_payload(raw_pkt)

        async def port_reader(manager):
            async for raw_pkt in port_pkts(manager, self._relay):
                self._process_payload(raw_pkt)

                if self.config.get("evofw_flag") and "evofw3" in raw_pkt.packet:
                    # !V, !T - print the version, or the current mask
                    # !T00   - turn off all mask bits
                    # !T01   - cause raw data for all messages to be printed
                    await manager.put_pkt(self.config["evofw_flag"], _LOGGER)

        async def port_writer(manager):
            while True:
                await self._dispatch_pkt(destination=manager)
                await asyncio.sleep(0)

        # if self.config.get("database"):
        #     import aiosqlite as sqlite3

        #     self._output_db = await sqlite3.connect(self.config["database"])
        #     self._db_cursor = await self._output_db.cursor()
        #     await self._db_cursor.execute(TABLE_SQL)  # create if not existant
        #     await self._db_cursor.execute(INDEX_SQL)  # index if not already
        #     await self._output_db.commit()

        if self.config["known_devices"]:
            try:
                with open(self.config["known_devices"]) as json_file:
                    devices = self.known_devices = json.load(json_file)
            except FileNotFoundError:  # if it doesn't exist, we'll create it later
                self.known_devices = {}
            else:
                if self.config["device_whitelist"]:
                    self.dev_whitelist = [
                        k for k, v in devices.items() if not v.get("blacklist")
                    ]
                else:
                    self.dev_blacklist = [
                        k for k, v in devices.items() if v.get("blacklist")
                    ]

        # Finally, source of packets is either a text file, or a serial port:
        if self.config["input_file"]:
            reader = asyncio.create_task(file_reader(self.config["input_file"]))
            self._tasks.extend([asyncio.create_task(port_writer(None)), reader])

        else:  # if self.serial_port
            if self.config.get("ser2net_server"):
                self._relay = Ser2NetServer(
                    self.config["ser2net_server"], self.cmd_que, loop=self.loop
                )
                self._tasks.append(asyncio.create_task(self._relay.start()))

            async with PortPktProvider(self.serial_port, loop=self.loop) as manager:
                if self.config.get("execute_cmd"):  # e.g. "RQ 01:145038 1F09 00"
                    cmd = self.config["execute_cmd"]
                    cmd = Command(cmd[:2], cmd[3:12], cmd[13:17], cmd[18:])
                    await manager.put_pkt(cmd, _LOGGER)

                reader = asyncio.create_task(port_reader(manager))
                self._tasks.extend([asyncio.create_task(port_writer(manager)), reader])

        await reader  # was: await asyncio.gather(*self._tasks)
        await self.async_cleanup("start()")
        self.cleanup("start()")

    async def _dispatch_pkt(self, destination=None) -> None:
        """Send a command unless in listen_only mode."""

        async def consider_rq_0404(kmd) -> bool:
            """Consider cmd, return True if it was sent for transmission."""

            async def check_message() -> None:
                """Queue next RQ/0404, or re-queue the last one if required."""
                self._sched_lock.acquire()

                if self._sched_zone:
                    _LOGGER.info("Checking zone(%s).schedule...", self._sched_zone.id)

                    if self._sched_zone.schedule is None:  # is schedule done?
                        _LOGGER.warning("zone(%s): NOT DONE", self._sched_zone.id)
                        self._sched_zone._schedule.req_fragment(restart=True)  # TODO
                        await schedule_task(PAUSE_LONG * 100, check_fragments)

                    else:
                        _LOGGER.warning("zone(%s): done", self._sched_zone.id)
                        self._sched_zone = None

                self._sched_lock.release()

            async def check_fragments() -> None:
                """Queue next RQ/0404s, or re-queue as required."""
                while True:
                    self._sched_lock.acquire()

                    if self._sched_zone:
                        if self._sched_zone.schedule:
                            print("Schedule complete for zone(%s)", self._sched_zone.id)
                            self._sched_zone = None
                            break

                        else:
                            print("RQd missing frags for zone(%s)", self._sched_zone.id)
                            self._sched_zone._schedule.req_fragment()

                    self._sched_lock.release()
                    await asyncio.sleep(PAUSE_LONG * 10)

                self._sched_lock.release()

            self._sched_lock.acquire()

            if self._sched_zone is None:  # not getting any zone's sched?
                self._sched_zone = self.evo.zone_by_id[kmd.payload[:2]]
                print("Sending initial RQ for a New zone(%s)...", self._sched_zone.id)
                await schedule_task(PAUSE_LONG * 100, check_message)
                await schedule_task(PAUSE_LONG, check_fragments)

            if self._sched_zone.id == kmd.payload[:2]:  # getting this zone's sched?
                print("Sent RQ for (this) zone(%s)", self._sched_zone.id, kmd)
                self._sched_lock.release()

                await destination.put_pkt(kmd, _LOGGER)
                return True

            self._sched_lock.release()

        # if destination is not None:
        #     serial = destination.reader._transport.serial
        #     if serial is not None and serial.in_waiting == 0:
        #         _LOGGER.warning("")
        #         return

        if len(self._buffer):
            if await consider_rq_0404(self._buffer[0]) is True:
                self._buffer.popleft()  # the pkt was sent for transmission
                return  # can't send any other initial RQs now

        while not self.cmd_que.empty():
            cmd = self.cmd_que.get()

            if str(cmd).startswith("!") and destination is not None:
                await destination.put_pkt(cmd, _LOGGER)

            elif destination is None or self.config["listen_only"]:
                # await asyncio.sleep(0)  # clear the whole queue
                pass

            elif cmd.verb == "RQ" and cmd.code == "0404":
                if await consider_rq_0404(cmd) is True:
                    self.cmd_que.task_done()  # the pkt was sent for transmission
                    print("RQ is for this zone: sent for transmission")
                else:
                    self._buffer.append(cmd)  # otherwise, send the pkt later on
                    print("RQ is for another zone: buffered for later")
                break  # can't send any other initial RQs now

            else:
                await destination.put_pkt(cmd, _LOGGER)

            self.cmd_que.task_done()

    def _process_payload(self, pkt: Packet) -> None:
        """Decode the packet and its payload."""

        def is_wanted(dev_whitelist=None, dev_blacklist=None) -> bool:
            """Return True is a packet is not to be filtered out."""

            def has_wanted_dev(dev_whitelist=None, dev_blacklist=None) -> bool:
                """Return True only if a packet contains 'wanted' devices."""
                if " 18:" in pkt.packet:  # TODO: should we ever blacklist a HGI80?
                    return True
                if dev_whitelist:
                    return any(device in pkt.packet for device in dev_whitelist)
                return not any(device in pkt.packet for device in dev_blacklist)

            # if any(x in pkt.packet for x in self.config.get("blacklist", [])):
            #     return  # silently drop packets with blacklisted text

            if has_wanted_dev(dev_whitelist, dev_blacklist):
                pkt_logger.info("%s ", pkt.packet, extra=pkt.__dict__)  # a hack
                return True
            return False

        if not is_wanted(
            dev_whitelist=self.dev_whitelist, dev_blacklist=self.dev_blacklist
        ):
            return  # silently drop packets with blacklisted (e.g. neighbour's) devices

        # if self._output_db:  # archive all valid packets, even those not to be parsed
        #     ts_pkt = f"{pkt.date}T{pkt.time} {pkt.packet}"
        #     w = [0, 27, 31, 34, 38, 48, 58, 68, 73, 77, 165]  # 165? 199 works
        #     data = tuple([ts_pkt[w[i - 1] : w[i] - 1] for i in range(1, len(w))])
        #     await self._db_cursor.execute(INSERT_SQL, data)
        #     await self._output_db.commit()

        if self.config["raw_output"] >= DONT_CREATE_MESSAGES:
            return

        # process packet payloads as messages
        try:
            msg = Message(pkt, self)
            if not msg.is_valid:  # trap/logs all exceptions appropriately
                return

        except (AssertionError, NotImplementedError):
            msg_logger.exception("%s", pkt.packet, extra=pkt.__dict__)
            return
        except (LookupError, TypeError, ValueError):  # TODO: shouldn't be needed
            msg_logger.exception("%s", pkt.packet, extra=pkt.__dict__)
            return

        if self.config["raw_output"] >= DONT_CREATE_ENTITIES:
            return

        # only reliable packets should become part of the state data
        if msg.dev_from[:2] == "18":  # RQs are required, but also less unreliable
            return

        try:
            msg._create_entities()  # create the devices, zones, domains

            if self.config["raw_output"] >= DONT_UPDATE_ENTITIES:
                return

            msg._update_entities()  # update the state database

        except AssertionError:  # TODO: for dev only?
            msg_logger.exception("%s", pkt.packet, extra=pkt.__dict__)
        except (LookupError, TypeError, ValueError):  # TODO: shouldn't be needed?
            msg_logger.exception("%s", pkt.packet, extra=pkt.__dict__)

        # else:
        #     if msg.verb == "RP" and msg.code == "0404":
        #         self._sched_lock.acquire()
        #        if self._sched_zone and self._sched_zone.id == msg.payload["zone_idx"]:
        #             if self._sched_zone.schedule:
        #                 self._sched_zone = None
        #             elif msg.payload["frag_index"] == 1:
        #                 self._sched_zone._schedule.req_fragment(block_mode=False)
        #             else:
        #                 self._sched_zone._schedule.req_fragment(block_mode=False)
        #         self._sched_lock.release()

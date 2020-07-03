"""Evohome serial."""
import asyncio
from collections import deque, namedtuple
import json
import logging
import os
from queue import PriorityQueue
import signal
import sys
from threading import Lock
from typing import Dict, List, Optional

from .command import Command, PAUSE_LONG
from .const import __dev_mode__
from .devices import Controller, Device, create_device as EvoDevice
from .logger import set_logging, BANDW_SUFFIX, COLOR_SUFFIX, CONSOLE_FMT, PKT_LOG_FMT
from .message import _LOGGER as msg_logger, Message
from .packet import _LOGGER as pkt_logger, Packet, PortPktProvider, file_pkts, port_pkts
from .ser2net import Ser2NetServer
from .system import EvoSystem

DONT_CREATE_MESSAGES = 3
DONT_CREATE_ENTITIES = 2
DONT_UPDATE_ENTITIES = 1

Address = namedtuple("DeviceAddress", "addr, type")
NON_DEVICE = Address(addr="", type="--")

_LOGGER = logging.getLogger(__name__)
if __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)


async def schedule_task(delay, func, *args, **kwargs):
    """Start a coro after delay seconds."""

    async def scheduled_func(delay, func, *args, **kwargs):
        await asyncio.sleep(delay)
        await func(*args, **kwargs)

    asyncio.create_task(scheduled_func(delay, func, *args, **kwargs))


class Error(Exception):
    """Base class for exceptions in this module."""

    pass


class MultipleControllerError(Error):
    """Raised when there is more than one Controller."""

    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)
        self.message = args[0] if args else None

    def __str__(self):
        err_msg = "There is more than one Evohome Controller"
        err_tip = "(use a ignore list to prevent this error)"
        if self.message:
            return f"{err_msg}: {self.message} {err_tip}"
        return f"{err_msg} {err_tip}"


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

        self.cmd_que = PriorityQueue()  # TODO: maxsize=200)
        self._buffer = deque()
        self._sched_zone = None
        self._sched_lock = Lock()

        self._last_msg = None

        self._tasks = []
        self._setup_signal_handler()

        # if config.get("ser2net_server"):
        self._relay = None

        # if config["known_devices"]:
        self.known_devices = {}
        self._exclude_list = []
        self._include_list = []

        # if config.get("database"):
        self._output_db = self._db_cursor = None

        # if config["raw_output"] > 0:
        self.evo = None  # EvoSystem(controller=config["controller_id"])
        self.systems: List[EvoSystem] = []
        self.system_by_id: Dict = {}
        self.devices: List[Device] = []
        self.device_by_id: Dict = {}

    def __repr__(self) -> str:
        ctls = [d.id for d in self.devices if d.is_controller]
        if self.evo.ctl:
            ctl_id = self.evo.ctl.id
        else:
            ctl_id = ctls[0] if ctls else None

        result = {"EVO": ctl_id, "CTLs": ctls}
        return str(result)

    def __str__(self) -> str:
        return json.dumps([s.id for s in self.systems])
        # return self.evo.state_db
        # return self.evo.status

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

            if signal in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
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
                        "ignore": d._ignored,
                    }
                    if d.id in self.known_devices:
                        self.known_devices[d.id].update(device_attrs)
                    else:
                        self.known_devices[d.id] = device_attrs

                with open(self.config["known_devices"], "w") as json_file:
                    json.dump(self.known_devices, json_file, sort_keys=True, indent=4)

            except AssertionError:
                _LOGGER.exception("Failed update of %s", self.config["known_devices"])

    async def start(self) -> None:
        async def file_reader(fp):
            async for raw_pkt in file_pkts(fp):
                self._process_packet(raw_pkt)

        async def port_reader(manager):
            async for raw_pkt in port_pkts(manager, self._relay):
                self._process_packet(raw_pkt)

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
                    self._include_list = [
                        k for k, v in devices.items() if not v.get("ignore")
                    ]
                else:
                    self._exclude_list = [
                        k for k, v in devices.items() if v.get("ignore")
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
                    _id = self._sched_zone.id
                    _LOGGER.info("zone(%s): checking schedule", _id)

                    if self._sched_zone.schedule is None:  # is schedule done?
                        _LOGGER.warning("zone(%s): timed out, restarting...", _id)
                        self._sched_zone._schedule.req_fragment(restart=True)
                        await schedule_task(PAUSE_LONG * 100, check_fragments)

                    else:
                        _LOGGER.warning("zone(%s): completed.", _id)
                        self._sched_zone = None

                self._sched_lock.release()

            async def check_fragments() -> None:
                """Queue next RQ/0404s, or re-queue as required."""
                while True:
                    self._sched_lock.acquire()

                    if self._sched_zone:
                        _id = self._sched_zone.id
                        if self._sched_zone.schedule:
                            _LOGGER.info("zone(%s): Schedule completed", _id)
                            self._sched_zone = None
                            break

                        self._sched_zone._schedule.req_fragment()
                        _LOGGER.info("zone(%s): Queued RQ for next missing frag", _id)

                    self._sched_lock.release()
                    await asyncio.sleep(PAUSE_LONG * 10)

                self._sched_lock.release()

            self._sched_lock.acquire()

            if self._sched_zone is None:  # not getting any zone's sched?
                self._sched_zone = self.evo.zone_by_id[kmd.payload[:2]]
                _LOGGER.info("zone(%s): Queuing 1st RQ...", self._sched_zone.id)
                await schedule_task(PAUSE_LONG * 100, check_message)
                await schedule_task(PAUSE_LONG, check_fragments)

            if self._sched_zone.id == kmd.payload[:2]:  # getting this zone's sched?
                _LOGGER.info("zone(%s): RQ was sent", self._sched_zone.id)
                self._sched_lock.release()

                await destination.put_pkt(kmd, _LOGGER)
                return True

            self._sched_lock.release()

        # # used for development only...
        # for payload in (
        #   "0000", "0100", "00", "01", "F8", "F9", "FA", "FB", "FC", "FF"
        # ):
        #     for code in range(int("4000", 16)):
        #         cmd = Command(" W", "01:145038", f"{code:04X}", payload)
        #         await destination.put_pkt(cmd, _LOGGER)

        # if destination is not None:
        #     serial = destination.reader._transport.serial
        #     if serial is not None and serial.in_waiting == 0:
        #         _LOGGER.warning("")
        #         return

        if len(self._buffer):
            if await consider_rq_0404(self._buffer[0]) is True:
                _LOGGER.info("zone(%s): Buffered RQ was sent.", self._sched_zone.id)
                self._buffer.popleft()  # the pkt was sent for transmission
                return  # can't send any other initial RQs now

        while not self.cmd_que.empty():
            cmd = self.cmd_que.get()

            if str(cmd).startswith("!") and destination is not None:
                await destination.put_pkt(cmd, _LOGGER)

            if cmd.verb == " W" and destination is not None:
                await destination.put_pkt(cmd, _LOGGER)

            elif destination is None or self.config["listen_only"]:
                # await asyncio.sleep(0)  # clear the whole queue
                pass

            elif cmd.verb == "RQ" and cmd.code == "0404":
                if await consider_rq_0404(cmd) is True:
                    _LOGGER.info("zone(%s): Queued RQ was sent.", self._sched_zone.id)
                else:
                    self._buffer.append(cmd)  # otherwise, send the pkt later on
                    _LOGGER.info("zone(xx): Queued RQ was buffered.")

                self.cmd_que.task_done()  # the pkt was sent for transmission
                break  # can't send any other initial RQs now

            else:
                await destination.put_pkt(cmd, _LOGGER)

            self.cmd_que.task_done()

    def _process_packet(self, pkt: Packet) -> None:
        """Decode the packet and its payload."""

        def is_wanted(include=None, exclude=None) -> bool:
            """Return True is a packet is not to be filtered out."""

            def has_wanted_dev(include=None, exclude=None) -> bool:
                """Return True only if a packet contains 'wanted' devices."""
                if " 18:" in pkt.packet:  # TODO: should we ever ignore a HGI80?
                    return True
                if include:
                    return any(device in pkt.packet for device in include)
                return not any(device in pkt.packet for device in exclude)

            if has_wanted_dev(include, exclude):
                pkt_logger.info("%s ", pkt.packet, extra=pkt.__dict__)  # a hack
                return True
            return False

        if not is_wanted(include=self._include_list, exclude=self._exclude_list):
            return  # silently drop packets with ignored (e.g. neighbour's) devices

        # if self._output_db:  # archive all valid packets, even those not to be parsed
        #     ts_pkt = f"{pkt.date}T{pkt.time} {pkt.packet}"
        #     w = [0, 27, 31, 34, 38, 48, 58, 68, 73, 77, 165]  # 165? 199 works
        #     data = tuple([ts_pkt[w[i - 1] : w[i] - 1] for i in range(1, len(w))])
        #     await self._db_cursor.execute(INSERT_SQL, data)
        #     await self._output_db.commit()

        if self.config["raw_output"] >= DONT_CREATE_MESSAGES:
            return

        try:  # harvest devices from packet header
            pkt.harvest_devices(self.get_device)

        except AssertionError:
            msg_logger.exception("%s", pkt.packet, extra=pkt.__dict__)
            return

        try:  # process packet payloads as messages
            msg = Message(self, pkt)
            if not msg.is_valid:  # trap/logs all exceptions appropriately
                return

            msg.harvest_devices(self.get_device)  # from e.g. 000C payloads

        except AssertionError:
            msg_logger.exception("%s", pkt.packet, extra=pkt.__dict__)
            return
        except NotImplementedError:
            msg_logger.error("%s", pkt.packet, extra=pkt.__dict__)
            return
        except (LookupError, TypeError, ValueError):  # TODO: shouldn't be needed
            msg_logger.error("%s", pkt.packet, extra=pkt.__dict__)
            raise

        if self.config["raw_output"] >= DONT_CREATE_ENTITIES:
            return

        # only reliable packets should become part of the state data
        if msg.src.type == "18":  # RQs from a 18: are unreliable, RPs are required
            return

        if self.evo:  # TODO: allow multiple controllers
            # if self.evo.device_by_id[msg.src.id].is_controller:
            #     if msg.src.id != self.evo.ctl.id:
            if msg.src.is_controller and msg.src.id != self.evo.ctl.id:
                # raise MultipleControllerError(
                #     f"{msg.src.id} in addition to {self.evo.ctl.id}"
                # )
                pass

        if msg.src is not msg.dst:
            if type(msg.src) == Controller and isinstance(msg.dst, Device):
                msg.dst.controller = msg.src
            elif type(msg.dst) == Controller and isinstance(msg.src, Device):
                msg.src.controller = msg.dst

        try:
            msg._create_entities()  # create the devices & zones

            if self.config["raw_output"] >= DONT_UPDATE_ENTITIES:
                return

            msg._update_entities()  # update the state database

        except AssertionError:  # TODO: for dev only?
            msg_logger.exception("%s", pkt.packet, extra=pkt.__dict__)
        except (LookupError, TypeError, ValueError):  # TODO: shouldn't be needed?
            # msg_logger.exception("%s", pkt.packet, extra=pkt.__dict__)
            msg_logger.error("%s", pkt.packet, extra=pkt.__dict__)
            raise

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

        # only reliable packets should become part of the state data
        if "18" in (msg.src.type, msg.dst.type):
            return

        if self.evo is None:
            return

        for evo in self.systems:
            if msg.src.controller in [evo.ctl, None]:
                evo.eavesdrop(msg, self._last_msg)  # TODO: WIP
                if msg.src.controller is not None:
                    break
        self._last_msg = msg

    def get_device(
        self, address, controller=None, parent_000c=None
    ) -> Optional[Device]:
        """Return a device (and create it if required).

        Can also set the parent system, if any (and create it if required).
        """

        # assert address.type in known device types
        if address.type == "18":
            return

        device = self.device_by_id.get(address.id, EvoDevice(self, address))

        if parent_000c is not None:
            device._parent_000c = parent_000c  # TODO: a bit messy

        # controller could be a Device, or only an Address
        if device.is_controller:
            if controller is not None and controller.id != device.id:
                raise LookupError
            controller = device

        elif controller is not None:
            controller = self.device_by_id.get(
                controller.id, EvoDevice(self, controller)
            )

        if controller is not None:  # now controller is a Device
            system = self.get_system(controller)
            system.add_device(device)

        return device

    def get_system(self, controller) -> Optional[EvoSystem]:
        """Return a system (and create it if required)."""
        # TODO: a way for the client to specify the controller id

        # system = self.system_by_id.get(controller.id, EvoSystem(self, controller))
        system = self.system_by_id.get(controller.id)
        if system is None:
            system = EvoSystem(self, controller)

        if self.evo is None:
            self.evo = system  # this is the first evohome-compatible system
        elif self.evo is not system:  # TODO: check this earlier?
            # raise ValueError(
            #     f">1 controller! (new: {system.ctl.id}, old: {self.evo.ctl.id})"
            # )
            pass

        return system

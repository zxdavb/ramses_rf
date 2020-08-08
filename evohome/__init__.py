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
from typing import Dict, List, Optional

from .command import Command, Pause
from .const import __dev_mode__
from .devices import DEVICE_CLASSES, Device

# from .exceptions import MultipleControllerError
from .logger import set_logging, BANDW_SUFFIX, COLOR_SUFFIX, CONSOLE_FMT, PKT_LOG_FMT
from .message import _LOGGER as msg_logger, Message
from .packet import _LOGGER as pkt_logger, Packet, PortPktProvider, file_pkts, port_pkts
from .schema import load_config
from .ser2net import Ser2NetServer
from .system import EvoSystem

DONT_CREATE_MESSAGES = 3
DONT_CREATE_ENTITIES = 2
DONT_UPDATE_ENTITIES = 1

_LOGGER = logging.getLogger(__name__)
if __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)
else:
    _LOGGER.setLevel(logging.WARNING)


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

        self._prev_msg = None

        self._tasks = []
        self._setup_signal_handler()

        # if config.get("ser2net_server"):
        self._relay = None  # ser2net_server relay

        # if config["raw_output"] > 0:
        self.evo = None  # EvoSystem(controller=config["controller_id"])
        self.systems: List[EvoSystem] = []
        self.system_by_id: Dict = {}
        self.devices: List[Device] = []
        self.device_by_id: Dict = {}

        self.known_devices = {}
        self._include_list = self._exclude_list = []

        config["known_devices"] = False  # bool(self.known_devices)
        params, self._include_list, self._exclude_list = load_config(self, **config)

    def __repr__(self) -> str:
        return json.dumps(self.schema)

    def __str__(self) -> str:
        return json.dumps(self.schema, indent=2)

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
                self.cleanup("_sig_handler_posix()")  # OK for after tasks.cancel

                tasks = [
                    t for t in asyncio.all_tasks() if t is not asyncio.current_task()
                ]
                [task.cancel() for task in tasks]
                logging.debug(f"Cancelling {len(tasks)} outstanding tasks...")

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

    def cleanup(self, xxx=None) -> None:
        """Perform the non-async portion of a graceful shutdown."""

        _LOGGER.debug("cleanup() invoked by: %s", xxx)

        if self.config["known_devices"]:
            _LOGGER.debug("cleanup(): Updating known_devices file...")
            for d in self.devices:
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

    async def start(self) -> None:
        async def file_reader(fp):
            async for raw_pkt in file_pkts(
                fp, include=self._include_list, exclude=self._exclude_list
            ):
                self._process_packet(raw_pkt)
                # await asyncio.sleep(Pause.NONE)  # needed for Ctrl_C to work

        async def port_reader(manager):
            async for raw_pkt in port_pkts(
                manager,
                include=self._include_list,
                exclude=self._exclude_list,
                relay=self._relay,
            ):
                self._process_packet(raw_pkt)
                # await asyncio.sleep(Pause.NONE)  # NOTE: 0.005 works well

                # TODO: not elegant - move elsewhere?
                if self.config.get("evofw_flag") and "evofw3" in raw_pkt.packet:
                    # !V, !T - print the version, or the current mask
                    # !T00   - turn off all mask bits
                    # !T01   - cause raw data for all messages to be printed
                    await manager.put_pkt(self.config["evofw_flag"], _LOGGER)

                await asyncio.sleep(Pause.MINIMUM)  # TODO: was: 0.005

        async def port_writer(manager):
            while True:
                await self._dispatch_pkt(destination=manager)
                await asyncio.sleep(Pause.SHORT)  # NOTE: was: 0.05

        # if self.config["known_devices"]:
        #     self.known_devices = ...
        #     self._include_list = [
        #     self._exclude_list = [

        # Finally, source of packets is either a text file, or a serial port:
        if self.config["input_file"]:  # reader = file_reader(config["input_file"])
            reader = asyncio.create_task(file_reader(self.config["input_file"]))
            self._tasks.extend([asyncio.create_task(port_writer(None)), reader])

        else:  # if self.serial_port, reader = port_reader(manager)
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
        # await asyncio.gather(*self._tasks)
        self.cleanup("start()")

    async def _dispatch_pkt(self, destination=None) -> None:
        """Send a command unless in listen_only mode."""

        # async def consider_rq_0404(kmd) -> bool:
        #     """Consider cmd, return True if it was sent for transmission."""

        #     async def check_message() -> None:
        #         """Queue next RQ/0404, or re-queue the last one if required."""
        #         self._sched_lock.acquire()

        #         if self._sched_zone:
        #             _id = self._sched_zone.id
        #             _LOGGER.info("zone(%s): checking schedule", _id)

        #             if self._sched_zone.schedule is None:  # is schedule done?
        #                 _LOGGER.warning("zone(%s): timed out, restarting...", _id)
        #                 self._sched_zone._schedule.req_fragment(restart=True)
        #                 await schedule_task(Pause.LONG * 100, check_fragments)

        #             else:
        #                 _LOGGER.warning("zone(%s): completed.", _id)
        #                 self._sched_zone = None

        #         self._sched_lock.release()

        #     async def check_fragments() -> None:
        #         """Queue next RQ/0404s, or re-queue as required."""
        #         while True:
        #             self._sched_lock.acquire()

        #             if self._sched_zone:
        #                 _id = self._sched_zone.id
        #                 if self._sched_zone.schedule:
        #                     _LOGGER.info("zone(%s): Schedule completed", _id)
        #                     self._sched_zone = None
        #                     break

        #                 self._sched_zone._schedule.req_fragment()
        #                 _LOGGER.info("zone(%s): Queued RQ for next missing frag", _id)

        #             self._sched_lock.release()
        #             await asyncio.sleep(Pause.LONG * 10)

        #         self._sched_lock.release()

        #     self._sched_lock.acquire()

        #     if self._sched_zone is None:  # not getting any zone's sched?
        #         self._sched_zone = self.evo.zone_by_id[kmd.payload[:2]]
        #         _LOGGER.info("zone(%s): Queuing 1st RQ...", self._sched_zone.id)
        #         await schedule_task(Pause.LONG * 100, check_message)
        #         await schedule_task(Pause.LONG, check_fragments)

        #     if self._sched_zone.id == kmd.payload[:2]:  # getting this zone's sched?
        #         _LOGGER.info("zone(%s): RQ was sent", self._sched_zone.id)
        #         self._sched_lock.release()

        #         await destination.put_pkt(kmd, _LOGGER)
        #         return True

        #     self._sched_lock.release()

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

        # if len(self._buffer):
        #     if await consider_rq_0404(self._buffer[0]) is True:
        #         _LOGGER.info("zone(%s): Buffered RQ was sent.", self._sched_zone.id)
        #         self._buffer.popleft()  # the pkt was sent for transmission
        #         return  # can't send any other initial RQs now

        while True:
            await asyncio.sleep(Pause.SHORT)  # TODO: this was casing an issue...
            if self.cmd_que.empty():
                await destination.put_pkt(None, _LOGGER)
                continue

            cmd = self.cmd_que.get()

            if destination is not None and str(cmd).startswith("!"):
                await destination.put_pkt(cmd, _LOGGER)

            elif destination is None or self.config["listen_only"]:
                pass  # clear the whole queue

            # elif cmd.verb == "RQ" and cmd.code == "0404":
            #     if await consider_rq_0404(cmd) is True:
            #         _LOGGER.info("zone(%s): Queued RQ was sent.", self._sched_zone.id)
            #     else:
            #         self._buffer.append(cmd)  # otherwise, send the pkt later on
            #         _LOGGER.info("zone(xx): Queued RQ was buffered.")

            #     self.cmd_que.task_done()  # the pkt was sent for transmission
            #     break  # can't send any other initial RQs now

            else:
                await destination.put_pkt(cmd, _LOGGER)

            # if cmd is not None:
            self.cmd_que.task_done()

    def _process_packet(self, pkt: Packet) -> None:
        """Decode the packet and its payload."""

        try:
            if self.config["raw_output"] >= DONT_CREATE_MESSAGES:
                return

            msg = Message(self, pkt)  # trap/logs all invalids msgs appropriately

            if self.config["raw_output"] >= DONT_CREATE_ENTITIES:
                return

            msg.create_devices()  # from pkt header & from msg payload (e.g. 000C)

            if msg.src.type == "18":  # 18:/RQs are unreliable, RPs are reqd for state
                return

            msg.create_entities()  # create zones & ufh_zones (TBD)

            if self.config["raw_output"] >= DONT_UPDATE_ENTITIES:
                return

            msg.update_entities(self._prev_msg)  # update the state database

            # if msg.verb == "RP" and msg.code == "0404":
            # self._sched_lock.acquire()
            # if self._sched_zone and self._sched_zone.id == msg.payload["zone_idx"]:
            #     if self._sched_zone.schedule:
            #         self._sched_zone = None
            #     elif msg.payload["frag_index"] == 1:
            #         self._sched_zone._schedule.req_fragment(block_mode=False)
            #     else:
            #         self._sched_zone._schedule.req_fragment(block_mode=False)
            # self._sched_lock.release()

        except (AssertionError, NotImplementedError):
            return

        self._prev_msg = msg if msg.is_valid else None

    def get_device(self, dev_addr, controller=None, domain_id=None) -> Optional[Device]:
        """Return a device (will create it if required).

        Can also set a controller/system (will create as required). If a controller is
        provided, can also set the domain_id as one of: zone_idx, FF (controllers), FC
        (heater_relay), HW (DHW sensor, relay), or None (unknown, TBA).
        """

        ctl = (
            None if controller is None else self.get_device(controller, domain_id="FF")
        )

        if dev_addr.type in ("18", "63", "--"):  # valid addresses, but not devices
            return

        if isinstance(dev_addr, Device):
            device = dev_addr
        else:
            device = self.device_by_id.get(dev_addr.id)

        if device is None:
            if dev_addr.type in ("01", "23") or domain_id == "FF":
                device = EvoSystem(self, dev_addr, domain_id=domain_id)
            else:
                device = DEVICE_CLASSES.get(dev_addr.type, Device)(
                    self, dev_addr, controller=ctl, domain_id=domain_id
                )
        else:  # update the existing device with any metadata
            if ctl is not None:
                device.controller = ctl

            if domain_id in ("FC", "FF"):
                device._domain_id = domain_id
            elif domain_id is not None and ctl is not None:
                device.zone = ctl.get_zone(domain_id)

        return device

    @property
    def schema(self) -> dict:
        """Return the global schema."""

        schema = {"controller": self.evo.id if self.evo else None}

        systems = [s.id for s in self.systems if s is not self.evo]
        systems.sort()
        schema.update({"alien_controllers": systems})

        if self.evo:
            schema.update(self.evo.schema)
        for evo in self.systems:
            schema.update(evo.schema)

        orphans = [d.id for d in self.devices if d.controller is None]
        orphans.sort()
        schema.update({"orphans": orphans})

        return schema

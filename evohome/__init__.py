"""Evohome serial."""
import asyncio
import json
import logging
import os
import psutil  # TODO: mem leak
import objgraph  # TODO: mem leak
import gc
from guppy import hpy

import signal
import sys
from queue import Queue
from typing import Optional

from .command import Command
from .const import INDEX_SQL, TABLE_SQL, INSERT_SQL
from .entity import System
from .logger import set_logging, BANDW_SUFFIX, COLOR_SUFFIX, CONSOLE_FMT, PKT_LOG_FMT
from .message import _LOGGER as msg_logger, Message
from .packet import _LOGGER as pkt_logger, Packet, PortPktProvider

_LOGGER = logging.getLogger(__name__)


class Gateway:
    """The gateway class."""

    def __init__(self, serial_port, loop=None, **config) -> None:
        """Initialise the class."""  # TODO: config.get() vs config[]
        self.serial_port = serial_port
        self.loop = loop if loop else asyncio.get_event_loop()
        self.config = config

        self._h = self._hp = None

        if self.serial_port and config.get("input_file"):
            _LOGGER.warning(
                "Serial port specified (%s), so ignoring input file (%s)",
                self.serial_port,
                config["input_file"],
            )
            config["input_file"] = None

        config["listen_only"] = not config.get("probe_system")

        if config.get("input_file"):
            if not config.get("listen_only"):
                _LOGGER.warning(
                    "Input file specified (%s), so forcing listen_only mode",
                    config["input_file"],
                )
                config["listen_only"] = True

            if config.get("execute_cmd"):
                _LOGGER.warning(
                    "Input file specified (%s), so disabling execute_cmd (%s)",
                    config["input_file"],
                    config["execute_cmd"],
                )
                config["execute_cmd"] = None

        if config.get("raw_output") > 1 and config.get("message_log"):
            _LOGGER.warning(
                "Raw output specified, so disabling message_log (%s)",
                config["message_log"],
            )
            config["message_log"] = False

        set_logging(
            msg_logger,
            stream=None if config.get("raw_output") > 1 else sys.stdout,
            file_name=self.config.get("message_log"),
        )

        set_logging(
            pkt_logger,
            stream=sys.stdout if config.get("raw_output") == 2 else None,
            file_name=self.config.get("packet_log"),
            file_fmt=PKT_LOG_FMT + BANDW_SUFFIX,
            cons_fmt=CONSOLE_FMT + COLOR_SUFFIX,
        )

        self.command_queue = Queue(maxsize=200)
        self.message_queue = Queue(maxsize=400)

        self.zones = []  # not used
        self.zone_by_id = {}

        self.domains = []
        self.domain_by_id = {}

        self.devices = []
        self.device_by_id = {}
        self.known_devices = {}

        # if self.config.get("known_devices"):
        self.device_blacklist = []
        self.device_whitelist = []

        # if self.config.get("database"):
        self._output_db = self._db_cursor = None

        # if self.config.get("raw_output") > 0:
        self.system = System(self)
        self.data = {f"{i:02X}": {} for i in range(12)}

        signals = [signal.SIGINT, signal.SIGTERM]
        if os.name == "posix":  # TODO: or sys.platform is better?
            signals += [signal.SIGHUP, signal.SIGUSR1, signal.SIGUSR2]
        for sig in signals:
            self.loop.add_signal_handler(
                sig, lambda sig=sig: asyncio.create_task(self._signal_handler(sig))
            )

    async def _signal_handler(self, signal):
        _LOGGER.debug(f"Received signal {signal.name}...")

        if signal == signal.SIGUSR1:  # and self.config.get("raw_output") < 2:
            _LOGGER.info("State data: %s", f"\r\n{json.dumps(self._devices, indent=4)}")

        if signal == signal.SIGUSR2:
            _LOGGER.info("Debug data is:")
            self._debug_info()

        if signal in [signal.SIGHUP, signal.SIGINT, signal.SIGTERM]:
            _LOGGER.info("Received a %s, exiting gracefully...", signal)
            try:
                await self.shutdown()
            except (TypeError):
                pass
            sys.exit()

    def _debug_info(self) -> None:
        gc.collect()

        _LOGGER.info("mem_fullinfo: %s", psutil.Process(os.getpid()).memory_full_info())
        _LOGGER.info("common_types: %s", objgraph.most_common_types())
        _LOGGER.info(
            "leaking_objs: %s", objgraph.count("dict", objgraph.get_leaking_objects())
        )

        _LOGGER.info("heap_stuff:")
        _LOGGER.info("%s", self._hp.heap())
        _LOGGER.info("%s", self._hp.heap().more)

    async def shutdown(self) -> None:
        if self.config.get("database"):
            _LOGGER.info(f"Closing database connections...")
            await self._output_db.commit()
            await self._output_db.close()

        if self.config.get("known_devices"):
            _LOGGER.info(f"Updating known_devices database...")
            self.known_devices.update(
                {
                    d.device_id: {
                        "friendly_name": d._friendly_name,
                        "blacklist": d._blacklist,
                    }
                    for d in self.devices
                }
            )
            with open(self.config["known_devices"], "w") as outfile:
                json.dump(self.known_devices, outfile, sort_keys=True, indent=4)

        _LOGGER.info("State data: %s", f"\r\n{json.dumps(self._devices, indent=4)}")

        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        logging.info(f"Cancelling {len(tasks)} outstanding tasks")
        [task.cancel() for task in tasks]
        await asyncio.gather(*tasks)

    @property
    def _devices(self) -> Optional[dict]:
        """Calculate a system schema."""

        def attrs(device) -> list:
            return [
                attr
                for attr in dir(device)
                if not attr.startswith("_") and not callable(getattr(device, attr))
            ]

        return {d.device_id: {a: getattr(d, a) for a in attrs(d)} for d in self.devices}

    @property
    def status(self) -> Optional[dict]:
        """Calculate a system schema."""
        controllers = [d for d in self.devices if d.device_type == "CTL"]
        if len(controllers) != 1:
            print("fail test 0: more/less than 1 controller")
            return

        structure = {
            "controller": controllers[0].device_id,
            "boiler": {
                "dhw_sensor": controllers[0].dhw_sensor,
                "tpi_relay": controllers[0].tpi_relay,
            },
            "zones": {},
            #  "devices": {},
        }

        orphans = structure["orphans"] = [
            d.device_id for d in self.devices if d.parent_zone is None
        ]

        structure["heat_demand"] = {
            d.device_id: d.heat_demand
            for d in self.devices
            if hasattr(d, "heat_demand")
        }

        thermometers = structure["thermometers"] = {
            d.device_id: d.temperature
            for d in self.devices
            if hasattr(d, "temperature")
        }
        thermometers.pop(structure["boiler"]["dhw_sensor"], None)

        for z in self.zone_by_id:  # [z.zone_idx for z in self.zones]:
            actuators = [k for d in self.data[z].get("actuators", []) for k in d.keys()]
            children = [d.device_id for d in self.devices if d.parent_zone == z]

            zone = structure["zones"][z] = {
                "name": self.data[z].get("name"),  # TODO: do it this way
                "temperature": self.zone_by_id[z].temperature,  # TODO: or this way
                "heat_demand": self.zone_by_id[z].heat_demand,
                "sensor": None,
                "actuators": actuators,
                "children": children,  # TODO: could this include non-actuators?
                "devices": list(set(actuators) | set(children)),
            }
            orphans = list(set(orphans) - set(zone["devices"]))

        # check each zones has a unique (and non-null) temperature
        zone_map = {
            str(v["temperature"]): k
            for k, v in structure["zones"].items()
            if v["temperature"] is not None
        }

        structure["orphans"] = orphans

        # for z in self.zone_by_id:  # [z.zone_idx for z in self.zones]:
        #     if

        # TODO: needed? or just process only those with a unique temp?
        if len(zone_map) != len(structure["zones"]):  # duplicate/null temps
            print("fail test 1: non-unique (null) zone temps")
            return structure

        # check all possible sensors have a unique temp - how?
        temp_map = [t for t in thermometers.values() if t is not None]
        if len(temp_map) != len(thermometers):  # duplicate/null temps
            print("fail test 2: null device temps")
            return structure

        temp_map = {str(v): k for k, v in thermometers.items() if v is not None}

        for zone_idx in structure["zones"]:
            zone = structure["zones"][zone_idx]
            sensor = temp_map.get(str(zone["temperature"]))
            if sensor:
                zone["sensor"] = sensor
                if sensor in structure["orphans"]:
                    structure["orphans"].remove(sensor)
                orphans = list(set(orphans) - set(sensor))

                # TODO: max 1 remaining zone without a sensor
                # if len(thermometers) == 0:
                # structure.pop("thermometers")

                structure["orphans"] = orphans

        return structure

    async def start(self) -> None:
        async def proc_packets_from_file() -> None:
            """Process packets from a file, asynchonously."""
            # async with FilePktProvider(self.config["input_file"]) as manager:
            #     await asyncio.gather(port_reader(manager), port_writer(None))

            import aiofiles  # TODO: move to packet.py

            async with aiofiles.open(self.config["input_file"]) as input_fp:
                async for ts_pkt_line in input_fp:
                    await self._process_packet(ts_pkt_line)
                    await self._dispatch_packet(destination=None)  # to empty the buffer

        async def proc_packets_from_port() -> None:
            async def port_reader(manager):
                self._hp = hpy()
                self._hp.setrelheap()
                # lf._h = self._hp.heap()

                raw_pkt = b""  # TODO: hack for testing
                while True:  # main loop
                    gc.collect()  # TODO: mem leak
                    ts_pkt_line, raw_pkt = await manager.get_next_packet(None)
                    await self._process_packet(ts_pkt_line, raw_pkt)
                    # await asyncio.sleep(0.01)

            async def port_writer(manager):
                while True:  # main loop
                    if manager.reader._transport.serial.in_waiting == 0:
                        await self._dispatch_packet(destination=manager.writer)
                        await asyncio.sleep(0.05)  # 0.05 works well, 0.03 too short
                    else:
                        await asyncio.sleep(0.01)

            async with PortPktProvider(self.serial_port, loop=self.loop) as manager:
                if self.config.get("execute_cmd"):  # e.g. "RQ 01:145038 1F09 FF"
                    cmd = self.config["execute_cmd"]
                    self.command_queue.put_nowait(
                        Command(self, cmd[13:17], cmd[:2], cmd[3:12], cmd[18:])
                    )
                    await self._dispatch_packet(destination=manager.writer)

                await asyncio.gather(port_reader(manager), port_writer(manager))

        if self.config.get("database"):
            import aiosqlite as sqlite3

            self._output_db = await sqlite3.connect(self.config["database"])
            self._db_cursor = await self._output_db.cursor()
            await self._db_cursor.execute(TABLE_SQL)  # create if not existant
            await self._db_cursor.execute(INDEX_SQL)  # index if not already
            await self._output_db.commit()

        if self.config.get("known_devices"):
            try:
                with open(self.config["known_devices"]) as json_file:
                    devices = self.known_devices = json.load(json_file)
            except FileNotFoundError:  # if it doesn't exist, we'll create it later
                self.known_devices = {}
            else:
                if self.config["device_whitelist"]:
                    # discard packets unless to/from one of our devices
                    self.device_whitelist = [
                        k for k, v in devices.items() if not v.get("blacklist")
                    ]
                else:
                    # discard packets to/from any explicitly blacklisted device
                    self.device_blacklist = [
                        k for k, v in devices.items() if v.get("blacklist")
                    ]

        # Finally, source of packets is either a text file, or a serial port:
        if self.config.get("input_file"):
            await proc_packets_from_file()  # main loop
        else:  # if self.config["serial_port"] or if self.serial_port
            await proc_packets_from_port()  # main loop

        await self.shutdown()

    async def _dispatch_packet(self, destination=None) -> None:
        """Send a command unless in listen_only mode."""
        if not self.command_queue.empty():
            cmd = self.command_queue.get()

            if not (destination is None or self.config.get("listen_only")):
                # TODO: if not cmd.entity._pkts.get(cmd.code):
                destination.write(bytearray(f"{cmd}\r\n".encode("ascii")))
                # _LOGGER.warning("# A write was done to %s: %s", self.serial_port, cmd)

            self.command_queue.task_done()

    async def _process_packet(self, ts_packet_line, raw_packet_line=None) -> None:
        """Receive a packet and optionally validate it as a message."""

        def has_wanted_device(pkt, dev_whitelist=None, dev_blacklist=None) -> bool:
            """Return True only if a packet contains 'wanted' devices."""
            if " 18:" in pkt.packet:  # TODO: should we respect backlisting of a HGI80?
                return True
            if dev_whitelist:
                return any(device in pkt.packet for device in dev_whitelist)
            return not any(device in pkt.packet for device in dev_blacklist)

        if self.config.get("debug_mode") == 1:  # TODO: mem leak
            self._debug_info()

        if ts_packet_line is None:
            return

        try:
            pkt = Packet(ts_packet_line[:26], ts_packet_line[27:], raw_packet_line)
        except AssertionError:
            _LOGGER.exception("%s", raw_packet_line)
            return
        except ValueError:  # (LookupError, TypeError, ValueError)
            return  # null packet line
        if not pkt.is_valid:  # this will trap/log all exceptions appropriately
            return

        if not has_wanted_device(pkt, self.device_whitelist, self.device_blacklist):
            return  # silently drop packets with unwanted (e.g. neighbour's) devices

        # any remaining packets are both valid & wanted, so: log them
        pkt_logger.info("%s ", pkt, extra=pkt.__dict__)

        if self._output_db:  # archive all valid packets, even those not to be parsed
            ts_pkt = f"{pkt.timestamp} {pkt.packet}"
            w = [0, 27, 31, 34, 38, 48, 58, 68, 73, 77, 165]  # 165? 199 works
            data = tuple([ts_pkt[w[i - 1] : w[i] - 1] for i in range(1, len(w))])
            await self._db_cursor.execute(INSERT_SQL, data)
            await self._output_db.commit()

        # finally, process packet payloads as messages
        if self.config.get("raw_output") < 2:
            self._process_payload(pkt)

    def _process_payload(self, pkt: Packet) -> None:
        """Decode the packet and its payload."""
        # if any(x in pkt.packet for x in self.config.get("blacklist", [])):
        #     return  # silently drop packets with blacklisted text

        try:
            msg = Message(pkt, self)
        except AssertionError:
            _LOGGER.exception("%s", pkt.packet)
            return
        if not msg.is_valid:  # trap/logs all exceptions appropriately
            return

        # finally, only certain packets should become part of the state data
        if self.config.get("raw_output") > 0:
            return

        try:
            msg.update_entities()
        except AssertionError:  # TODO: AssertionError should be enough!
            _LOGGER.exception("%s", msg)
        except (LookupError, TypeError, ValueError):
            _LOGGER.exception("%s", msg)

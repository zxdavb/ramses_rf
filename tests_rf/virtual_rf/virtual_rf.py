#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""A virtual RF network useful for testing."""

# NOTE: does not rely on ramses_rf library (except StrEnum)

import asyncio
import logging
import os
import pty
import signal
import tty
from collections import deque
from contextlib import ExitStack
from io import FileIO
from selectors import EVENT_READ, DefaultSelector
from typing import TypeAlias

from serial import Serial, serial_for_url  # type: ignore[import]

from ramses_rf.protocol.backports import StrEnum  # TODO: enum.StrEnum

_FD: TypeAlias = int  # file descriptor
_PN: TypeAlias = str  # port name

# _FILEOBJ: TypeAlias = int | Any  # int | HasFileno


_LOGGER = logging.getLogger(__name__)
_LOGGER.setLevel(logging.DEBUG)

DEFAULT_GWY_ID = bytes("18:000730", "ascii")
DEVICE_ID = "device_id"
DEVICE_ID_BYTES = "device_id_bytes"
FW_VERSION = "fw_version"

MAX_NUM_PORTS = 32


class HgiFwTypes(StrEnum):  # TODO: when Python >= 3.11.x, use: HgiFwTypes(enum.StrEnum)
    EVOFW3 = "ghoti57/evofw3 atmega32u4 v0.7.1"  # SparkFun atmega32u4
    NATIVE = "Texas Instruments TUSB3410"  # Honeywell HGI80


class VirtualComPortInfo:
    """A container for emulating pyserial's PortInfo (SysFS) objects."""

    def __init__(self, port_name: _PN, dev_type: None | HgiFwTypes = None) -> None:
        """Supplies a useful subset of PortInfo attrs according to gateway type."""

        self.device = port_name  # # e.g. /dev/pts/2 (a la /dev/ttyUSB0)
        self.name = port_name[5:]  # e.g.      pts/2 (a la      ttyUSB0)

        self.description: None | str = None
        self.product: None | str = None
        self.serial_number: None | str = None
        self.manufacturer: None | str = None
        self.subsystem: None | str = None

        if dev_type is not None:
            self._set_attrs(dev_type)

    def _set_attrs(self, dev_type: HgiFwTypes) -> None:
        if dev_type == HgiFwTypes.EVOFW3:
            self.description = "evofw3 atmega32u4"
            self.product = "evofw3 atmega32u4"
            self.serial_number = None
            self.manufacturer = "SparkFun"
            self.subsystem = "usb-serial"

        elif dev_type == HgiFwTypes.NATIVE:
            self.description = "TUSB3410 Boot Device"
            self.product = "TUSB3410 Boot Device"
            self.serial_number = "TUSB3410"
            self.manufacturer = "Texas Instruments"
            self.subsystem = "usb"

        else:
            raise ValueError(f"Unknown type of gateway {dev_type}")


class VirtualRfBase:
    """A virtual many-to-many network of serial port (a la RF network).

    Creates a collection of serial ports. When data frames are received from any one
    port, they are sent to all the other ports.

    The data frames are in the RAMSES_II format, terminated by `\\r\\n`.
    """

    def __init__(self, num_ports: int, log_size: int = 100) -> None:
        """Create `num_ports` virtual serial ports."""

        if os.name != "posix":
            raise RuntimeError(f"Unsupported OS: {os.name} (requires termios)")

        if 0 > num_ports > MAX_NUM_PORTS:
            raise ValueError(f"Port limit exceeded: {num_ports}")

        self._port_info_list: dict[_PN, VirtualComPortInfo] = {}

        self._loop = asyncio.get_running_loop()
        self.tx_log: deque[tuple[str, bytes]] = deque([], log_size)  # as sent to Device
        self.rx_log: deque[tuple[str, bytes]] = deque([], log_size)  # as sent to RF

        self._file_objs: dict[_FD, FileIO] = {}  # master fd to port object, for I/O
        self._pty_names: dict[_FD, _PN] = {}  # master fd to slave port name, for logger
        self._tty_names: dict[_PN, _FD] = {}  # slave port name to slave fd, for cleanup

        # self._setup_event_handlers()  # TODO: needs fixing/testing
        for idx in range(num_ports):
            self._create_port(idx)

        self._task: asyncio.Task = None  # type: ignore[assignment]

    def _create_port(self, port_idx: int) -> None:
        """Create a port without a HGI80 attached."""
        master_fd, slave_fd = pty.openpty()  # pty, tty

        tty.setraw(master_fd)  # requires termios module, so: works only on *nix
        os.set_blocking(master_fd, False)  # make non-blocking

        self._file_objs[master_fd] = open(master_fd, "rb+", buffering=0)
        self._pty_names[master_fd] = os.ttyname(slave_fd)
        self._tty_names[os.ttyname(slave_fd)] = slave_fd

        self._set_comport_info(self._pty_names[master_fd])

    def comports(self, include_links=False) -> list[VirtualComPortInfo]:  # unsorted
        """Use this method to monkey patch serial.tools.list_ports.comports()."""
        return list(self._port_info_list.values())

    def _set_comport_info(
        self, port_name: _PN, dev_type: None | HgiFwTypes = None
    ) -> VirtualComPortInfo:
        """Add comport info to the list (wont fail if the entry already exists)"""
        self._port_info_list.pop(port_name, None)
        self._port_info_list[port_name] = VirtualComPortInfo(
            port_name, dev_type=dev_type
        )
        return self._port_info_list[port_name]

    @property
    def ports(self) -> list[_PN]:
        """Return a list of the names of the serial ports."""
        return list(self._tty_names)  # [p.name for p in self.comports]

    async def stop(self) -> None:
        """Stop polling ports and distributing data."""

        if not self._task or self._task.done():
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass

        self._cleanup()

    def _cleanup(self):
        """Destroy file objects and file descriptors."""

        for f in self._file_objs.values():
            f.close()  # also closes corresponding master fd
        for fd in self._tty_names.values():
            os.close(fd)  # else this slave fd will persist

    def start(self) -> asyncio.Task:
        """Start polling ports and distributing data, calls `pull_data_from_port()`."""

        self._task = self._loop.create_task(self._poll_ports_for_data())
        return self._task

    async def _poll_ports_for_data(self) -> None:
        """Send data received from any one port (as .write(data)) to all other ports."""

        with DefaultSelector() as selector, ExitStack() as stack:
            for fd, f in self._file_objs.items():
                stack.enter_context(f)
                selector.register(fd, EVENT_READ)

            while True:
                for key, event_mask in selector.select(timeout=0):
                    if not event_mask & EVENT_READ:
                        continue
                    self._pull_data_from_src_port(key.fileobj)  # type: ignore[arg-type]  # fileobj type is int | HasFileno
                    await asyncio.sleep(0)
                else:
                    await asyncio.sleep(0.001)

    def _pull_data_from_src_port(self, master: _FD) -> None:
        """Pull the data from the sending port and process any frames."""

        data = self._file_objs[master].read()  # read the Tx'd data
        self.tx_log.append((self._pty_names[master], data))

        # this assumes all .write(data) are 1+ whole frames terminated with \r\n
        for frame in (d + b"\r\n" for d in data.split(b"\r\n") if d):  # ignore b""
            if f := self._proc_before_tx(frame, master):
                self._cast_frame_to_all_ports(f, master)  # can cast (is not echo only)

    def _cast_frame_to_all_ports(self, frame: bytes, master: _FD) -> None:
        """Pull the frame from the sending port and cast it to the RF."""

        _LOGGER.error(f"{self._pty_names[master]:<11} cast:  {frame!r}")
        for fd in self._file_objs:
            self._push_frame_to_dst_port(frame, fd)

    def _push_frame_to_dst_port(self, frame: bytes, master: _FD) -> None:
        """Push the frame to a single destination port."""

        if f := self._proc_after_rx(frame, master):
            self.rx_log.append((self._pty_names[master], f))
            self._file_objs[master].write(f)

    def _proc_after_rx(self, frame: bytes, master: _FD) -> None | bytes:
        """Allow the device to modify the frame after receiving (e.g. adding RSSI)."""
        return frame

    def _proc_before_tx(self, frame: bytes, master: _FD) -> None | bytes:
        """Allow the device to modify the frame before sending (e.g. changing addr0)."""
        return frame

    def _setup_event_handlers(self) -> None:
        def handle_exception(loop, context):
            """Handle exceptions on any platform."""
            _LOGGER.error("Caught an exception: %s, cleaning up...", context["message"])
            self._cleanup()
            exc = context.get("exception")
            if exc:
                raise exc

        async def handle_sig_posix(sig) -> None:
            """Handle signals on posix platform."""
            _LOGGER.error("Received a signal: %s, cleaning up...", sig.name)
            self._cleanup()
            signal.raise_signal(sig)

        _LOGGER.debug("Creating exception handler...")
        self._loop.set_exception_handler(handle_exception)

        _LOGGER.debug("Creating signal handlers...")
        if os.name == "posix":  # signal.SIGKILL people?
            for sig in (signal.SIGABRT, signal.SIGINT, signal.SIGTERM):
                self._loop.add_signal_handler(
                    sig, lambda sig=sig: self._loop.create_task(handle_sig_posix(sig))
                )
        else:  # unsupported OS
            raise RuntimeError(f"Unsupported OS for this module: {os.name} (termios)")


class VirtualRf(VirtualRfBase):
    """A virtual many-to-many network of serial port with HGI80s (or compatible).

    If the HGI itself is the source of a frame, its addr0 (+/- addr1, addr2) will be
    changed according to the expected behaviours of of that firmware.
    """

    def __init__(self, num_ports: int, log_size: int = 100, start: bool = True) -> None:
        """Create `num_ports` virtual serial ports.

        If addr0 of the frame is '18:000730', the frame will be modified appropriately.
        """
        self._gateways: dict[_PN, dict] = {}

        super().__init__(num_ports, log_size)

        if start:
            self.start()

    @property
    def gateways(self) -> dict[str, _PN]:
        return {v[DEVICE_ID]: k for k, v in self._gateways.items()}

    def set_gateway(
        self,
        port_name: _PN,
        device_id: str,
        fw_version: HgiFwTypes = HgiFwTypes.EVOFW3,
    ) -> None:
        if port_name not in self.ports:
            raise LookupError(f"Port does not exist: {port_name}")

        if [v for k, v in self.gateways.items() if k != port_name and v == device_id]:
            raise LookupError(f"Gateway exists on another port: {device_id}")

        # if fw_version is None:
        #     self._gateways[port_name] = {}
        #     self._set_comport_info(port_name, dev_type=None)
        #     return

        if fw_version not in HgiFwTypes:
            raise LookupError(f"Unknown FW specified for gateway: {fw_version}")

        self._gateways[port_name] = {
            DEVICE_ID: device_id,
            FW_VERSION: fw_version,
            DEVICE_ID_BYTES: bytes(device_id, "ascii"),
        }

        self._set_comport_info(port_name, dev_type=fw_version)

    def _proc_after_rx(self, frame: bytes, master: _FD) -> None | bytes:
        """The RSSI is added by the receiving HGI80-compatible device after Rx.

        Return None if the bytes are not to be Rx by this device.
        """

        if frame[:1] != b"!":
            return b"000 " + frame

        if (gwy := self._gateways.get(self._pty_names[master])) and (
            gwy[FW_VERSION] != HgiFwTypes.EVOFW3
        ):
            return None

        return frame  # TODO: append the ! response

    def _proc_before_tx(self, frame: bytes, master: _FD) -> None | bytes:
        """The addr0 may be changed by the sending HGI80-compatible device before Tx.

        Return None if the bytes are not to be Tx to the RF ether (e.g. to echo only).
        """

        if frame[:1] == b"!":  # never to be cast, but may be echo'd, or other response
            self._push_frame_to_dst_port(frame, master)
            return None

        # The type of Gateway will tell us what to do next
        gwy = self._gateways.get(self._pty_names[master])  # here, gwy is not a Gateway

        if gwy and frame[7:16] == DEFAULT_GWY_ID:  # confirmed for evofw3
            return frame[:7] + gwy[DEVICE_ID_BYTES] + frame[16:]

        return frame


async def main():
    """ "Demonstrate the class functionality."""

    num_ports = 3

    rf = VirtualRf(num_ports)
    print(f"Ports are: {rf.ports}")

    sers: list[Serial] = [serial_for_url(rf.ports[i]) for i in range(num_ports)]  # type: ignore[annotation-unchecked]

    for i in range(num_ports):
        sers[i].write(bytes(f"Hello World {i}! ", "utf-8"))
        await asyncio.sleep(0.005)  # give the write a chance to effect

        print(f"{sers[i].name}: {sers[i].read(sers[i].in_waiting)}")
        sers[i].close()

    await rf.stop()


if __name__ == "__main__":
    asyncio.run(main())

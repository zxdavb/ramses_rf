#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""A virtual RF network useful for testing."""

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
from typing import Generator, TypeAlias

from serial import Serial, serial_for_url  # type: ignore[import]

from ramses_rf.protocol.backports import StrEnum  # when Python >= 3.11.x, use from enum

_FD: TypeAlias = int  # file descriptor
_PN: TypeAlias = str  # port name

# _FILEOBJ: TypeAlias = int | Any  # int | HasFileno


_LOGGER = logging.getLogger(__name__)
_LOGGER.setLevel(logging.DEBUG)


FW_VERSION = "FW version"


class HgiFwTypes(StrEnum):
    EVOFW3 = "ghoti57/evofw3 v0.7.1"
    NATIVE = "Honeywell HGI80"


class VirtualRF:
    """A virtual many-to-many network of serial port (a la RF network).

    Creates a collection of serial ports. When data is received from any one port, it is
    sent to all the other ports.

    If a HGI sends a frame, its addr0 will be changed according to the expected
    behaviours of real HGI80s: 0th port will be 18:018000, 34th port  will be 18:018034.
    """

    def __init__(self, num_ports: int, log_size: int = 100, **kwargs: dict) -> None:
        """Create `num_ports` virtual serial ports.

        If addr0 of the frame is '18:000730', it will be modified appropriately.
        """

        self._loop = asyncio.get_running_loop()
        self.rx_log: deque[tuple[str, bytes]] = deque([], log_size)
        self.tx_log: deque[tuple[str, bytes]] = deque([], log_size)

        self._file_objs: dict[_FD, FileIO] = {}  # master fd to file (port) object
        self._pty_names: dict[_FD, _PN] = {}  # master fd to slave port name, for logger
        self._tty_names: dict[_FD, _PN] = {}  # slave fd to its port name

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
        self._pty_names[master_fd] = self._tty_names[slave_fd] = os.ttyname(slave_fd)
        # self._hgi_names[master_fd] = bytes(f"18:018{port_idx:03d}", "ascii")

    @property
    def ports(self) -> list[str]:
        return list(self._tty_names.values())

    # def set_gateway(
    #         self, port_idx: int, fw_version: HgiFwTypes = HgiFwTypes.EVOFW3
    # ) -> None:
    #     if fw_version not in HgiFwTypes:
    #         raise LookupError
    #     self._gateways[port_idx][FW_VERSION] = fw_version

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
        for fd in self._tty_names:
            os.close(fd)  # else this slave fd will persist

    async def start(self) -> asyncio.Task:
        """Start polling ports and distributing data."""

        self._task = self._loop.create_task(self._poll_ports_for_data_and_pull())
        return self._task

    async def _poll_ports_for_data_and_pull(self) -> None:
        """Send data received from any one port (as .write(data)) to all other ports."""

        with DefaultSelector() as selector, ExitStack() as stack:
            for fd, f in self._file_objs.items():
                stack.enter_context(f)
                selector.register(fd, EVENT_READ)

            while True:
                for key, event_mask in selector.select(timeout=0):
                    if not event_mask & EVENT_READ:
                        continue
                    self._pull_data_from_port_and_cast_as_frames(key.fileobj)  # type: ignore[arg-type]  # fileobj type is int | HasFileno
                    await asyncio.sleep(0)
                else:
                    await asyncio.sleep(0.001)

    def _pull_data_from_port_and_cast_as_frames(self, master: _FD) -> None:
        """Pull the data from the sending port and cast any frames to all ports."""

        data = self._file_objs[master].read()  # read the Tx'd data
        self.tx_log.append((self._pty_names[master], data))

        # this assumes all .write(data) are 1+ whole frames terminated with \r\n
        self._cast_frames_to_all_ports(
            master, (d + b"\r\n" for d in data.split(b"\r\n") if d and d[:1] != b"!")
        )

    def _cast_frames_to_all_ports(
        self, master: _FD, frames: Generator[bytes, None, None]
    ) -> None:
        """Cast each frame to all ports in the RSSI + frame format."""

        for frame in frames:
            # changing addr0 is performed by the sending serial device
            # if frame[7:16] == b"18:000730":
            #     frame = frame[:7] + self._hgi_names[master] + frame[16:]

            _LOGGER.error(f"{self._pty_names[master]:<11} cast:  {frame!r}")

            # adding the RSSI is performed by the receiving serial device
            self.rx_log.append((self._pty_names[master], frame))
            _ = [f.write(b"000 " + frame) for f in self._file_objs.values()]

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
            raise RuntimeError(f"Unsupported OS for this module: {os.name}")


async def main():
    """ "Demonstrate the class functionality."""

    num_ports = 3

    rf = VirtualRF(num_ports)
    print(f"Ports are: {rf.ports}")

    sers: list[Serial] = [serial_for_url(rf.ports[i]) for i in range(num_ports)]  # type: ignore[annotation-unchecked]

    await rf.start()

    for i in range(num_ports):
        sers[i].write(bytes(f"Hello World {i}! ", "utf-8"))
        await asyncio.sleep(0.005)  # give the write a chance to effect

        print(f"{sers[i].name}: {sers[i].read(sers[i].in_waiting)}")
        sers[i].close()

    await rf.stop()


if __name__ == "__main__":
    asyncio.run(main())

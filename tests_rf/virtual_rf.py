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

_FD: TypeAlias = int  # file descriptor
_PN: TypeAlias = str  # port name

# _FILEOBJ: TypeAlias = int | Any  # int | HasFileno


_LOGGER = logging.getLogger(__name__)
_LOGGER.setLevel(logging.DEBUG)


class VirtualRF:
    """A virtual many-to-many network of serial port (a la RF network).

    Creates a collection of serial ports. When data is received from any one port, it is
    sent to all the other ports."""

    def __init__(self, num_ports: int, log_size=100) -> None:
        """Create `num_ports` virtual serial ports."""

        self._loop = asyncio.get_running_loop()
        self.tx_log: deque[tuple[str, bytes]] = deque([], log_size)

        self._file_objs: dict[_FD, FileIO] = {}  # master fd to file (port) object
        self._pty_names: dict[_FD, _PN] = {}  # master fd to slave port name, for logger
        self._tty_names: dict[_FD, _PN] = {}  # slave fd to its port name

        # self._setup_event_handlers()  # TODO: needs fixing/testing

        for _ in range(num_ports):
            master_fd, slave_fd = pty.openpty()  # pty, tty

            tty.setraw(master_fd)  # requires termios module, so: works only on *nix
            os.set_blocking(master_fd, False)  # make non-blocking

            self._file_objs[master_fd] = open(master_fd, "rb+", buffering=0)
            self._pty_names[master_fd] = self._tty_names[slave_fd] = os.ttyname(
                slave_fd
            )

        self._task: asyncio.Task = None  # type: ignore[assignment]

    @property
    def ports(self) -> list[str]:
        return list(self._tty_names.values())

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
            _LOGGER.error(f"{self._pty_names[master]:<11} cast:  {frame!r}")
            # adding the RSSI is performed by the receiving serial device
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

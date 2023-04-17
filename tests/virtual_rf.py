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
from typing import TypeAlias

from serial import serial_for_url

_FD: TypeAlias = int  # file descriptor
_PN: TypeAlias = str  # port name


_LOGGER = logging.getLogger(__name__)
_LOGGER.setLevel(logging.DEBUG)


class VirtualRF:
    """A virtual many-to-many network of serial port (a la RF network).

    Creates a collection of serial ports. When data is received from any one port, it is
    sent to all the other ports."""

    def __init__(self, num_ports: int, log_size=100) -> None:
        """Create `num_ports` virtual serial ports."""

        self._loop = asyncio.get_running_loop()
        self.log = deque([], log_size)

        self._files: dict[_FD, FileIO] = {}  # master fd to file (port)
        self._names: dict[_FD, _PN] = {}  # slave fd to port name
        self._ports: dict[_FD, _PN] = {}  # master fd to port name, used for logging

        # self._setup_event_handlers()  # TODO: needs testing

        for _ in range(num_ports):
            master_fd, slave_fd = pty.openpty()  # type: tuple[_FD, _FD]  # pty, tty

            tty.setraw(master_fd)  # requires termios module, so: works only on Unix
            os.set_blocking(master_fd, False)  # non-blocking

            self._files[master_fd] = open(master_fd, "r+b", buffering=0)
            self._ports[master_fd] = self._names[slave_fd] = os.ttyname(slave_fd)

        self._task: asyncio.Task = None  # type: ignore[assignment]

    @property
    def ports(self) -> list[str]:
        return list(self._names.values())

    async def stop(self) -> None:
        """Stop polling ports and distributing data."""

        if not self._task or self._task.done():
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass

    async def start(self) -> asyncio.Task:
        """Start polling ports and distributing data."""

        self._task = self._loop.create_task(self._poll_ports())
        return self._task

    async def _poll_ports(self) -> None:
        """Send data received from any one port to all the other ports."""

        with DefaultSelector() as selector, ExitStack() as stack:
            for fd, f in self._files.items():
                stack.enter_context(f)
                selector.register(fd, EVENT_READ)

            while True:
                for key, event_mask in selector.select(timeout=0):
                    if not event_mask & EVENT_READ:
                        continue
                    self._pull_port(key)
                    await asyncio.sleep(0)
                else:
                    await asyncio.sleep(0.001)

    def _pull_port(self, key) -> tuple:
        data = self._files[key.fileobj].read()  # read the Tx'd data

        self.log.append((self._ports[key.fileobj], data))

        for d in data.split(b"\r\n"):
            if d == b"":
                continue
            d = d + b"\r\n"
            self._push_data(self._ports[key.fileobj], d)

    def _push_data(self, src_port: str, data: bytes) -> None:
        while data:
            if b"\r\n" in data:
                pkt, data = data.split(b"\r\n", maxsplit=1)
                self._push_pkt(src_port, pkt + b"\r\n")

    def _push_pkt(self, src_port: str, data: bytes) -> None:
        _LOGGER.error(f"{src_port:<11} sent: {data}")
        if not data.startswith(b"!"):
            # adding the RSSI is usually performed by the receiving serial device
            _ = [f.write(b"000 " + data) for f in self._files.values()]

    def _setup_event_handlers(self) -> None:
        def cleanup():
            _ = [f.close() for f in self._files.values()]  # also cloes fd
            _ = [os.close(fd) for fd in self._names]  # tty will persist, otherwise

        def handle_exception(loop, context):
            """Handle exceptions on any platform."""
            _LOGGER.error("Caught an exception: %s, cleaning up...", context["message"])
            cleanup()
            exc = context.get("exception")
            if exc:
                raise exc

        async def handle_sig_posix(sig):
            """Handle signals on posix platform."""
            _LOGGER.error("Received a signal: %s, cleaning up...", sig.name)
            cleanup()
            signal.raise_signal(sig)

        _LOGGER.debug("Creating exception handler...")
        self._loop.set_exception_handler(handle_exception)

        _LOGGER.debug("Creating signal handlers...")
        if os.name == "posix":
            for sig in (signal.SIGABRT, signal.SIGINT, signal.SIGTERM):
                self._loop.add_signal_handler(
                    sig, lambda sig=sig: self._loop.create_task(handle_sig_posix(sig))
                )
        else:  # unsupported OS
            raise RuntimeError(f"Unsupported OS for this module: {os.name}")


async def main():
    NUM_PORTS = 3
    rf = VirtualRF(NUM_PORTS)
    print(f"Ports are: {rf.ports}")

    sers = [serial_for_url(rf.ports[i]) for i in range(NUM_PORTS)]

    await rf.start()

    for i in range(NUM_PORTS):
        sers[i].write(bytes(f"Hello World {i}! ", "utf-8"))
        await asyncio.sleep(0.005)  # give the write a chance to effect

        print(f"{sers[i].name}: {sers[i].read(sers[i].in_waiting)}")
        sers[i].close()

    await rf.stop()


if __name__ == "__main__":
    asyncio.run(main())

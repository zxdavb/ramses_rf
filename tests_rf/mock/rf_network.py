#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""A virtual RF network useful for testing."""

import asyncio
import os
import pty
import tty
from contextlib import ExitStack
from io import FileIO
from selectors import EVENT_READ, DefaultSelector
from typing import TypeAlias

from serial import serial_for_url

_FD: TypeAlias = int  # file descriptor
_PN: TypeAlias = str  # port name


class VirtualRF:
    """A virtual many-to-many network of serial port (a la RF network).

    Creates a collection of serial ports. When data is received from any one port, it is
    sent to all the other ports."""

    def __init__(self, num_ports: int) -> None:
        """Create `num_ports` virtual serial ports."""

        self._loop = asyncio.get_running_loop()

        self._files: dict[_FD, FileIO] = {}  # fd to file (port)
        self._names: dict[_PN, _FD] = {}  # port name to fd

        for _ in range(num_ports):
            master_fd, slave_fd = pty.openpty()  # type: tuple[_FD, _FD]

            tty.setraw(master_fd)  # requires termios module, so: works only on Unix
            os.set_blocking(master_fd, False)  # non-blocking

            self._files[master_fd] = open(
                master_fd, "r+b", buffering=0
            )  # unbuffered binary mode
            self._names[os.ttyname(slave_fd)] = master_fd

        self._task: asyncio.Task = None  # type: ignore[assignment]

    @property
    def ports(self) -> list[str]:
        return list(self._names)

    async def stop(self) -> None:
        """Stop polling ports and distributing data."""

        if not self._task or self._task.done():
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            return

    async def start(self) -> asyncio.Task:
        """Start polling ports and distributing data."""

        self._task = self._loop.create_task(self._run())
        return self._task

    async def _run(self) -> None:
        """Send data received from any one port to all the other ports."""

        with DefaultSelector() as selector, ExitStack() as stack:
            for fd, f in self._files.items():
                stack.enter_context(f)
                selector.register(fd, EVENT_READ)

            while True:
                for key, event_mask in selector.select(timeout=0):
                    if not event_mask & EVENT_READ:
                        continue

                    data = self._files[key.fileobj].read()  # read the Tx'd data
                    for fd, f in self._files.items():
                        f.write(data)  # send the data to each port

                    await asyncio.sleep(0.005)


async def main():
    NUM_PORTS = 3
    rf = VirtualRF(NUM_PORTS)
    print(f"Ports are: {rf.ports}")

    sers = [serial_for_url(rf.ports[i]) for i in range(NUM_PORTS)]

    await rf.start()

    for i in range(NUM_PORTS):
        sers[i].write(bytes(f"Hello World {i}! ", "utf-8"))
        await asyncio.sleep(0.005)

    for i in range(NUM_PORTS):
        print(f"{sers[i].name}: {sers[i].read(sers[i].in_waiting)}")
        sers[i].close()

    await rf.stop()


if __name__ == "__main__":
    asyncio.run(main())

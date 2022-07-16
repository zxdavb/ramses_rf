#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

A pseudo-mocked serial port used for testing.

Will provide a fixed Tx for a given Rx.
"""

import asyncio
import logging
from datetime import datetime as dt
from queue import Empty, Full, PriorityQueue

from ramses_rf.protocol import Command, InvalidPacketError
from ramses_rf.protocol.transport import PacketProtocolPort, SerTransportPoll

from .const import GWY_ID, __dev_mode__

DEV_MODE = __dev_mode__

RUNNING = True


_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class MockSerial:  # all the 'mocking' is done here
    """A pseudo-mocked serial port used for testing.

    Will periodically Rx a sync_cycle set that will be available via `read()`.
    Will use a reponse table to provide a known Rx for a given Tx sent via `write()`.
    """

    def __init__(self, gwy, port=None, **kwargs) -> None:
        self._loop = gwy._loop

        self.port = port
        self._rx_buffer = bytes()
        self._out_waiting = 0
        self.is_open = None

        self.mock_devices = []

        self._que = PriorityQueue(maxsize=24)
        self._next_bytes = self._loop.create_task(self._rx_bytes_from_ether())

    def close(self, exc=None):
        """Close the port."""
        if self.is_open is False:
            return
        self.is_open = False

        for device in self.mock_devices:
            for task in device._tasks:
                task.cancel()
        if task := self._next_bytes:
            task.cancel()

    @property
    def in_waiting(self) -> int:
        """Return the number of bytes currently in the input buffer."""
        return len(self._rx_buffer)

    def read_all(self) -> bytes:
        """Read max size bytes from the serial port."""
        return self.read(size=self.in_waiting)

    def read(self, size: int = 1) -> bytes:
        """Read max size bytes from the serial port."""
        data, self._rx_buffer = self._rx_buffer[:size], self._rx_buffer[size:]
        return data

    async def _rx_bytes_from_ether(self) -> None:
        """Poll the queue and add bytes to the Rx buffer.

        Also pass on the pkt header to any other devices on the ether.
        """

        self.is_open = True

        while RUNNING:
            await asyncio.sleep(0.001)

            try:
                klass, _, data, rp_header = self._que.get_nowait()
            except Empty:
                continue

            if klass == 3:
                self._out_waiting -= len(data)
            self._rx_buffer += b"000 " + data

            if rp_header:
                for device in self.mock_devices:
                    try:
                        device.rx_frame_by_header(rp_header)
                    except (AttributeError, TypeError, ValueError) as exc:
                        _LOGGER.exception(exc)
            self._que.task_done()

    @property
    def out_waiting(self) -> int:
        """Return the number of bytes currently in the output buffer."""
        return self._out_waiting

    def write(self, data: bytes) -> int:
        """Output the given byte string over the serial port."""

        if data[:1] == b"!":  # an evofw3 flag
            return 0
        if data[7:16] == b"18:000730":
            data = data[:7] + bytes(GWY_ID, "ascii") + data[16:]
        try:
            self._tx_data_to_ether(data, Command(data.decode("ascii")[:-2]))
        except InvalidPacketError:
            pass
        return 0

    def _tx_data_to_ether(self, data: str, cmd: Command) -> None:
        """Transmit a packet to the ether from the gateway, usually an RQ."""

        try:
            self._que.put_nowait((3, dt.now(), data, cmd.rx_header))
        except Full:
            return
        self._out_waiting += len(data)


class SerTransportMock(SerTransportPoll):  # to gracefully close the mocked port
    def close(self) -> None:
        super().close()

        if self.serial:
            self.serial.close()


def create_pkt_stack(  # to use a mocked Serial port (and a sympathetic Transport)
    gwy, pkt_callback, *, ser_port: str = None
) -> tuple[asyncio.Protocol, asyncio.Transport]:
    """Return a mocked packet stack.

    Must use SerTransportPoll and not SerTransportAsync.
    """

    pkt_protocol = PacketProtocolPort(gwy, pkt_callback)

    ser_instance = MockSerial(gwy, port=ser_port)
    pkt_transport = SerTransportMock(gwy._loop, pkt_protocol, ser_instance)

    return (pkt_protocol, pkt_transport)

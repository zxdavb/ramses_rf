#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

A pseudo-mocked serial port used for testing.

Will provide a fixed Tx for a given Rx.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime as dt
from queue import Empty, Full, PriorityQueue
from typing import Callable

from ramses_rf.protocol import Command, InvalidPacketError
from ramses_rf.protocol.protocol import create_protocol_factory
from ramses_rf.protocol.transport import (
    PacketProtocolFile,
    PacketProtocolPort,
    SerTransportPoll,
    SerTransportRead,
    _PacketProtocolT,
    _PacketTransportT,
)

from .const import GWY_ID, __dev_mode__

DEV_MODE = __dev_mode__

RUNNING = True


_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class MockSerial:  # most of the 'mocking' is done here
    """A pseudo-mocked serial port used for testing.

    Will periodically Rx a sync_cycle set that will be available via `read()`.
    Will use a reponse table to provide a known Rx for a given Tx sent via `write()`.
    """

    def __init__(self, port, loop, **kwargs) -> None:
        self._loop = loop

        self.port = port
        self._rx_buffer = bytes()
        self._out_waiting = 0
        self.is_open = None

        self.mock_devices = []

        self._que = PriorityQueue(maxsize=24)
        self._rx_bytes_from_ether_task = self._loop.create_task(
            self._rx_bytes_from_ether()
        )

    def close(self, exc=None):
        """Close the port."""
        if self.is_open is False:
            return
        self.is_open = False

        for device in self.mock_devices:
            for task in device._tasks:
                task.cancel()
        if task := self._rx_bytes_from_ether_task:
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
                priority, _, cmd = self._que.get_nowait()
            except Empty:
                continue

            # this is the mocked HGI80 receiving the frame
            if priority == 3:  # only from HGI80
                self._out_waiting -= len(str(cmd)) + 2
            self._rx_buffer += b"000 " + bytes(f"{cmd}\r\n", "ascii")

            # this is the mocked devices receiving the frame
            for device in self.mock_devices:
                try:
                    device.rx_frame_as_cmd(cmd)
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
            self._tx_bytes_to_ether(data)
        except InvalidPacketError:
            pass
        return 0

    def _tx_bytes_to_ether(self, data: bytes) -> None:
        """Transmit a packet from the gateway to the ether."""

        cmd = Command(data.decode("ascii")[:-2])  # rx_header
        try:
            self._que.put_nowait((3, dt.now(), cmd))
        except Full:
            return
        self._out_waiting += len(str(cmd)) + 2


class SerTransportMock(SerTransportPoll):  # to gracefully close the mocked port
    def write(self, cmd) -> None:  # Does nothing, here as a convenience
        super().write(cmd)

    def close(self) -> None:
        super().close()

        if self.serial:
            self.serial.close()


def create_pkt_stack(  # to use a mocked Serial port (and a sympathetic Transport)
    gwy,
    pkt_callback: Callable,
    /,
    *,
    protocol_factory: Callable = None,
    ser_port: str = None,
    packet_log=None,
    packet_dict: dict = None,
) -> tuple[_PacketProtocolT, _PacketTransportT]:
    """Return a mocked packet stack.

    Must use SerTransportPoll and not SerTransportAsync.
    """

    def get_serial_instance(ser_name: str, loop) -> MockSerial:
        return MockSerial(ser_name, loop)

    def protocol_factory_() -> type[_PacketProtocolT]:
        if packet_log or packet_dict is not None:
            return create_protocol_factory(PacketProtocolFile, gwy, pkt_callback)()
        return create_protocol_factory(PacketProtocolPort, gwy, pkt_callback)()

    if len([x for x in (packet_dict, packet_log, ser_port) if x is not None]) != 1:
        raise TypeError("serial port, log file & dict should be mutually exclusive")

    pkt_protocol = protocol_factory_()

    if (pkt_source := packet_log or packet_dict) is not None:  # {} is a processable log
        return pkt_protocol, SerTransportRead(gwy._loop, pkt_protocol, pkt_source)  # type: ignore[arg-type, assignment]

    ser_instance = get_serial_instance(ser_port, gwy._loop)

    return pkt_protocol, SerTransportMock(gwy._loop, pkt_protocol, ser_instance)

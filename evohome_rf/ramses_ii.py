#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES-II compatble Transport/Protocol processor."""

import asyncio
import logging
from queue import PriorityQueue, Empty
from typing import Optional, Tuple  # Any

from serial import serial_for_url  # SerialException,
from serial_asyncio import SerialTransport

from .const import __dev_mode__
from .packet import GatewayProtocol, SERIAL_CONFIG  # Packet,

MAX_SIZE = 200

_LOGGER = logging.getLogger(__name__)
if True or __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)


class Ramses2Transport(asyncio.Protocol):
    def __init__(self, gwy, protocol, gateway, extra=None):
        _LOGGER.debug("RamsesTransport.__init__()")

        self._extra = {} if extra is None else extra

        self._is_closing = None
        self._protocol = protocol
        self._gateway = gateway  # the gateway interface (a protocol)

        self._que = PriorityQueue()  # maxsize=MAX_SIZE)
        self._extra["writer"] = asyncio.create_task(self._port_writer())

    async def _port_writer(self):
        while True:
            if self._que.empty():
                await asyncio.sleep(0.05)
                continue

            try:
                cmd = self._que.get(False)
            except Empty:
                continue

            if self._gwy_protocol:  # or not self.config["disable_sending"]
                await self._gateway.send_data(cmd)

            self._que.task_done()

    def get_extra_info(self, name, default=None):
        """Get optional transport information."""
        _LOGGER.debug("RamsesTransport.get_extra_info()")

        return self._extra.get(name, default)

    def is_closing(self) -> Optional[bool]:
        """Return True if the transport is closing or closed."""
        _LOGGER.debug("RamsesTransport.is_closing()")

        return self._is_closing

    def close(self):
        """Close the transport.

        Buffered data will be flushed asynchronously. No more data will be received.
        After all buffered data is flushed, the protocol's connection_lost() method will
        (eventually) be called with None as its argument.
        """
        _LOGGER.debug("RamsesTransport.close()")

        self._is_closing = True
        self._extra["writer"].cancel()
        # self._extra["writer"] = None

    def set_protocol(self, protocol):
        """Set a new protocol."""
        _LOGGER.debug("RamsesTransport.set_protocol(%s)", protocol)

        # self._protocol = protocol
        raise NotImplementedError

    def get_protocol(self):
        """Return the current protocol."""
        _LOGGER.debug("RamsesTransport.get_protocol()")

        # return self._protocol
        raise NotImplementedError

    def is_reading(self) -> Optional[bool]:
        """Return True if the transport is receiving."""
        _LOGGER.debug("RamsesTransport.is_reading()")

        raise NotImplementedError

    def pause_reading(self):
        """Pause the receiving end.

        No data will be passed to the protocol's data_received() method until
        resume_reading() is called.
        """
        _LOGGER.debug("RamsesTransport.pause_reading()")

        raise NotImplementedError

    def resume_reading(self):
        """Resume the receiving end.

        Data received will once again be passed to the protocol's data_received()
        method.
        """
        _LOGGER.debug("RamsesTransport.resume_reading()")

        raise NotImplementedError

    def set_write_buffer_limits(self, high=None, low=None):
        """Set the high- and low-water limits for write flow control.

        These two values control when to call the protocol's pause_writing() and
        resume_writing() methods. If specified, the low-water limit must be less than
        or equal to the high-water limit. Neither value can be negative. The defaults
        are implementation-specific. If only the high-water limit is given, the
        low-water limit defaults to an implementation-specific value less than or equal
        to the high-water limit. Setting high to zero forces low to zero as well, and
        causes pause_writing() to be called whenever the buffer becomes non-empty.
        Setting low to zero causes resume_writing() to be called only once the buffer is
        empty. Use of zero for either limit is generally sub-optimal as it reduces
        opportunities for doing I/O and computation concurrently.
        """
        _LOGGER.debug("RamsesTransport.set_write_buffer_limits()")

        raise NotImplementedError

    def get_write_buffer_size(self):
        """Return the current size of the write buffer."""
        _LOGGER.debug("RamsesTransport.get_write_buffer_size()")

        raise NotImplementedError

    async def write(self, cmd):
        """Write some data bytes to the transport.

        This does not block; it buffers the data and arranges for it to be sent out
        asynchronously.
        """
        _LOGGER.debug("RamsesTransport.write(%s)", cmd)

        if not self._is_closing:
            self._que.put_nowait(cmd)

    def writelines(self, list_of_cmds):
        """Write a list (or any iterable) of data bytes to the transport.

        The default implementation concatenates the arguments and calls write() on the
        result.list_of_cmds
        """
        _LOGGER.debug("RamsesTransport.writelines(%s)", list_of_cmds)

        for cmd in list_of_cmds:
            self.write(cmd)

    def write_eof(self):
        """Close the write end after flushing buffered data.

        This is like typing ^D into a UNIX program reading from stdin. Data may still be
        received.
        """
        _LOGGER.debug("RamsesTransport.write_eof()")

        raise NotImplementedError

    def can_write_eof(self):
        """Return True if this transport supports write_eof(), False if not."""
        _LOGGER.debug("RamsesTransport.can_write_eof()")

        raise NotImplementedError

    def abort(self):
        """Close the transport immediately.

        Buffered data will be lost. No more data will be received. The protocol's
        connection_lost() method will (eventually) be called with None as its argument.
        """
        _LOGGER.debug("RamsesTransport.abort()")

        self._que = PriorityQueue()
        self.close()

        self._protocol.connection_lost(None)


class Ramses2Protocol(asyncio.Protocol):
    def __init__(self, gwy, callback) -> None:
        _LOGGER.debug("RamsesProtocol.__init__()")

        self._transport = None
        self._pause_writing = None
        self._callback = callback

    def connection_made(self, transport: Ramses2Transport) -> None:
        """Called when a connection is made."""
        _LOGGER.debug("RamsesProtocol.connection_made()")

        self._transport = transport

    def data_received(self, msg):
        """Called when some data is received."""
        _LOGGER.debug("RamsesProtocol.data_received()")

        self._callback(msg)

    async def send_data(self, command) -> None:
        """Called when some data is to be sent (not a callaback)."""
        _LOGGER.debug("RamsesProtocol.send_data()")

        while self._pause_writing:
            asyncio.sleep(0.1)

        await self._transport.write(command)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when the connection is lost or closed."""
        _LOGGER.debug("RamsesProtocol.connection_lost()")

        if exc is not None:
            pass
        self._transport.loop.stop()

    def pause_writing(self) -> None:
        """Called when the transport's buffer goes over the high-water mark."""
        _LOGGER.debug("RamsesProtocol.pause_writing()")

        self._pause_writing = True

    def resume_writing(self) -> None:
        """Called when the transport's buffer drains below the low-water mark."""
        _LOGGER.debug("RamsesProtocol.resume_writing()")

        self._pause_writing = False


def create_ramses_interface(gwy, serial_port, msg_handler) -> Tuple:
    # The architecture is: msg -> pkt -> ser

    ser_instance = serial_for_url(serial_port, **SERIAL_CONFIG)

    # create_pkt_interface(ser_instance, callback) -> Tuple[Any, Any]:
    pkt_protocol = GatewayProtocol(gwy, msg_handler)  # used for gwy._callbacks
    pkt_transport = SerialTransport(gwy._loop, pkt_protocol, ser_instance)

    # create_msg_interface(ser_instance, callback) -> Tuple[Any, Any]:
    msg_protocol = Ramses2Protocol(gwy, msg_handler)
    msg_transport = Ramses2Transport(gwy, pkt_protocol, None)

    return (pkt_transport, pkt_protocol, msg_transport, msg_protocol)

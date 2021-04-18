#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome RF - RAMSES-II compatble Message processor.

Operates at the msg layer of: app - msg - pkt - h/w
"""

import asyncio
import logging
from datetime import datetime as dt
from datetime import timedelta as td
from queue import Empty, PriorityQueue, SimpleQueue
from typing import Callable, List, Optional, Tuple

from .command import ARGS, DEAMON, EXPIRES, FUNC, TIMEOUT, Command
from .const import __dev_mode__
from .message import Message
from .schema import DISABLE_SENDING, DONT_CREATE_MESSAGES, REDUCE_PROCESSING

DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
_LOGGER.setLevel(logging.WARNING)  # TODO: needs fixing - this should be the default
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class MakeCallbackAwaitable:
    DEFAULT_TIMEOUT = 3  # in seconds

    def __init__(self, loop):
        self._loop = loop or asyncio.get_event_loop()
        self._queue = None

    def create_pair(self) -> Tuple[Callable, Callable]:
        self._queue = SimpleQueue()  # maxsize=1)

        def putter(*args):  # callback
            self._loop.call_soon_threadsafe(self._queue.put_nowait, args)

        async def getter(timeout=self.DEFAULT_TIMEOUT) -> Tuple:
            timeout = self.DEFAULT_TIMEOUT if timeout is None else timeout
            dt_expired = dt.now() + td(seconds=timeout)
            while dt.now() < dt_expired:
                try:
                    return self._queue.get_nowait()
                except Empty:
                    await asyncio.sleep(0.005)
            raise TimeoutError

        return getter, putter  # awaitable, callback


class MessageTransport(asyncio.Transport):
    """Interface for a message transport.

    There may be several implementations, but typically, the user does not implement
    new transports; rather, the platform provides some useful transports that are
    implemented using the platform's best practices.

    The user never instantiates a transport directly; they call a utility function,
    passing it a protocol factory and other information necessary to create the
    transport and protocol.  (E.g. EventLoop.create_connection() or
    EventLoop.create_server().)

    The utility function will asynchronously create a transport and a protocol and
    hook them up by calling the protocol's connection_made() method, passing it the
    transport.
    """

    MAX_BUFFER_SIZE = 200
    MAX_SUBSCRIBERS = 3
    WRITER_TASK = "writer_task"

    def __init__(self, gwy, protocol, extra=None):
        _LOGGER.debug("MsgTransport.__init__()")

        self._loop = gwy._loop

        self._gwy = gwy
        self._protocols = []
        self.add_protocol(protocol)

        self._extra = {} if extra is None else extra
        self._is_closing = None

        self._write_buffer_limit_high = None
        self._write_buffer_limit_low = None
        self._write_buffer_paused = None

        self._callbacks = {}
        self._dispatcher = None  # the HGI80 interface (is a asyncio.protocol)

        self._que = PriorityQueue(maxsize=self.MAX_BUFFER_SIZE)
        self.set_write_buffer_limits()

    def _set_dispatcher(self, dispatcher: Callable):
        _LOGGER.debug("MsgTransport._set_dispatcher(%s)", dispatcher)

        async def call_send_data(cmd):
            _LOGGER.debug("MsgTransport.pkt_dispatcher(%s): send_data", cmd)
            if cmd.callback:
                cmd.callback[EXPIRES] = (
                    dt.max
                    if cmd.callback.get(DEAMON)
                    else dt.now() + td(cmd.callback.get(TIMEOUT, 1))
                )
                self._callbacks[cmd.rx_header] = cmd.callback

            await self._dispatcher(cmd)  # send_data, *once* callback registered

        async def pkt_dispatcher():
            while True:
                try:
                    cmd = self._que.get_nowait()
                except Empty:
                    if not self._is_closing:
                        await asyncio.sleep(0.05)
                        continue
                except AttributeError:  # when self._que == None, from abort()
                    break
                else:
                    if self._dispatcher:
                        await call_send_data(cmd)
                    self._que.task_done()
                    # if self._write_buffer_paused:
                    self.get_write_buffer_size()

            _LOGGER.debug("MsgTransport.pkt_dispatcher(): connection_lost(None)")
            [p.connection_lost(None) for p in self._protocols]

        self._dispatcher = dispatcher
        self._extra[self.WRITER_TASK] = self._loop.create_task(pkt_dispatcher())

        return self._extra[self.WRITER_TASK]

    def _pkt_receiver(self, pkt):
        # _LOGGER.debug("MsgTransport._pkt_receiver(%s)", pkt)

        for (
            hdr,
            callback,
        ) in self._callbacks.items():  # 1st, notify all expired callbacks
            if callback.get(EXPIRES, dt.max) < pkt._dtm:
                _LOGGER.error("MsgTransport._pkt_receiver(%s): Expired callback", hdr)
                callback[FUNC](False, *callback.get(ARGS, tuple()))

        self._callbacks = {  # 2nd, discard any expired callbacks
            hdr: callback
            for hdr, callback in self._callbacks.items()
            if callback.get(DEAMON) or callback[EXPIRES] >= pkt._dtm
        }

        if len(self._protocols) == 0:
            return

        if self._gwy.config[REDUCE_PROCESSING] >= DONT_CREATE_MESSAGES:
            return

        try:
            msg = Message(self._gwy, pkt)  # trap/logs all invalid msgs appropriately
        except ValueError:  # not a valid message
            return

        # _LOGGER.info("MsgTransport._pkt_receiver(pkt): %s", msg)
        # NOTE: msg._pkt._header is expensive - don't call it unless there's callbacks
        if self._callbacks and msg._pkt._header in self._callbacks:
            callback = self._callbacks[msg._pkt._header]  # 3rd, invoke any callback
            callback[FUNC](msg, *callback.get(ARGS, tuple()))
            if not callback.get(DEAMON):
                del self._callbacks[msg._pkt._header]

        # TODO: wrap in an exception handler because can't trust them...
        # [p.data_received(msg) for p in self._protocols]
        for p in self._protocols:
            try:
                p.data_received(msg)
            except AttributeError:
                pass

        # NOTE: this doesn't work...
        # [
        #     self._gwy._loop.run_in_executor(None, p.data_received, msg)
        #     for p in self._protocols
        # ]

    def close(self):
        """Close the transport.

        Buffered data will be flushed asynchronously. No more data will be received.
        After all buffered data is flushed, the protocol's connection_lost() method will
        (eventually) be called with None as its argument.
        """
        _LOGGER.debug("MsgTransport.close()")

        self._is_closing = True

    def abort(self):
        """Close the transport immediately.

        Buffered data will be lost. No more data will be received. The protocol's
        connection_lost() method will (eventually) be called with None as its argument.
        """
        _LOGGER.debug("MsgTransport.abort(): clearing buffered data")

        self._is_closing = True
        self._que = None

    def is_closing(self) -> Optional[bool]:
        """Return True if the transport is closing or closed."""
        _LOGGER.debug("MsgTransport.is_closing()")

        return self._is_closing

    def get_extra_info(self, name, default=None):
        """Get optional transport information."""
        _LOGGER.debug("MsgTransport.get_extra_info(%s, %s)", name, default)

        return self._extra.get(name, default)

    def add_protocol(self, protocol):
        """Set a new protocol.

        Allow multiple protocols per transport.
        """
        _LOGGER.debug("MsgTransport.add_protocol(%s)", protocol)

        if protocol not in self._protocols:
            if len(self._protocols) > self.MAX_SUBSCRIBERS - 1:
                raise ValueError("Exceeded maximum number of subscribing protocols")

            self._protocols.append(protocol)
            protocol.connection_made(self)

    def get_protocol(self) -> Optional[List]:
        """Return the list of active protocols.

        There can be multiple protocols per transport.
        """
        _LOGGER.debug("MsgTransport.get_protocol()")

        return self._protocols

    def is_reading(self) -> Optional[bool]:
        """Return True if the transport is receiving."""
        _LOGGER.debug("MsgTransport.is_reading()")

        raise NotImplementedError

    def pause_reading(self):
        """Pause the receiving end.

        No data will be passed to the protocol's data_received() method until
        resume_reading() is called.
        """
        _LOGGER.debug("MsgTransport.pause_reading()")

        raise NotImplementedError

    def resume_reading(self):
        """Resume the receiving end.

        Data received will once again be passed to the protocol's data_received()
        method.
        """
        _LOGGER.debug("MsgTransport.resume_reading()")

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
        _LOGGER.debug("MsgTransport.set_write_buffer_limits()")

        self._write_buffer_limit_high = 10 if high is None else high
        self._write_buffer_limit_low = (
            int(self._write_buffer_limit_high * 0.8) if low is None else low
        )

        assert 0 <= self._write_buffer_limit_low <= self._write_buffer_limit_high

        self.get_write_buffer_size()

    def get_write_buffer_size(self):
        """Return the current size of the write buffer."""
        _LOGGER.debug("MsgTransport.get_write_buffer_size()")

        qsize = self._que.qsize()

        if not self._write_buffer_paused:
            if qsize >= self._write_buffer_limit_high:
                self._write_buffer_paused = True
                [p.pause_writing() for p in self._protocols]

        elif qsize <= self._write_buffer_limit_high:
            self._write_buffer_paused = False
            [p.resume_writing() for p in self._protocols]

        return qsize

    def write(self, cmd):
        """Write some data bytes to the transport.

        This does not block; it buffers the data and arranges for it to be sent out
        asynchronously.
        """
        _LOGGER.debug("MsgTransport.write(%s)", cmd)

        if self._is_closing:
            raise RuntimeError("MsgTransport is closing or has closed")

        if self._gwy.config[DISABLE_SENDING]:
            message = "MsgTransport.write(%s): sending disabled: discarded"
            if DEV_MODE:
                _LOGGER.warning(message, cmd)
            else:
                _LOGGER.debug(message, cmd)

        else:
            if not self._dispatcher:  # TODO: do better?
                _LOGGER.debug("MsgTransport.write(%s): no dispatcher", cmd)

            self._que.put_nowait(cmd)  # was: self._que.put_nowait(cmd)

        self.get_write_buffer_size()

    def writelines(self, list_of_cmds):
        """Write a list (or any iterable) of data bytes to the transport.

        The default implementation concatenates the arguments and calls write() on the
        result.list_of_cmds
        """
        _LOGGER.debug("MsgTransport.writelines(%s)", list_of_cmds)

        for cmd in list_of_cmds:
            self.write(cmd)

    def write_eof(self):
        """Close the write end after flushing buffered data.

        This is like typing ^D into a UNIX program reading from stdin. Data may still be
        received.
        """
        _LOGGER.debug("MsgTransport.write_eof()")

        raise NotImplementedError

    def can_write_eof(self) -> bool:
        """Return True if this transport supports write_eof(), False if not."""
        _LOGGER.debug("MsgTransport.can_write_eof()")

        return False


class MessageProtocol(asyncio.Protocol):
    """Interface for a message protocol.

    The user should implement this interface.  They can inherit from this class but
    don't need to.  The implementations here do nothing (they don't raise
    exceptions).

    When the user wants to requests a transport, they pass a protocol factory to a
    utility function (e.g., EventLoop.create_connection()).

    When the connection is made successfully, connection_made() is called with a
    suitable transport object.  Then data_received() will be called 0 or more times
    with data (bytes) received from the transport; finally, connection_lost() will
    be called exactly once with either an exception object or None as an argument.

    State machine of calls:

    start -> CM [-> DR*] [-> ER?] -> CL -> end

    * CM: connection_made()
    * DR: data_received()
    * ER: eof_received()
    * CL: connection_lost()
    """

    def __init__(self, gwy, callback: Callable) -> None:
        _LOGGER.debug("MsgProtocol.__init__(%s)", callback)
        self._loop = gwy._loop  # self._gwy = gwy is not used
        self._callback = callback
        self._transport = None
        self._pause_writing = None

    def connection_made(self, transport: MessageTransport) -> None:
        """Called when a connection is made."""
        _LOGGER.debug("MsgProtocol.connection_made(%s)", transport)
        self._transport = transport

    def data_received(self, msg: Message) -> None:
        """Called by the transport when some data is received."""
        # NOTE: will get double-logging if >1 subscribers to msg transport
        # _LOGGER.info("MsgProtocol.data_received(%s)", msg)  # or: use repr(msg)?
        self._callback(msg)

    async def send_data(
        self, cmd: Command, awaitable=None, callback=None, **kwargs
    ) -> Optional[Message]:
        """Called when a command is to be sent."""
        _LOGGER.debug("MsgProtocol.send_data(%s)", cmd)

        if awaitable is not None and callback is not None:
            raise ValueError("only one of `awaitable` and `callback` can be provided")

        if awaitable:
            awaitable, callback = MakeCallbackAwaitable(self._loop).create_pair()
        if callback:
            cmd.callback = {
                FUNC: callback,
                TIMEOUT: 3,
            }  # func, args, daemon, timeout (& expired)

        while self._pause_writing:
            await asyncio.sleep(0.005)

        self._transport.write(cmd)

        if awaitable:
            result = await awaitable(timeout=kwargs.get(TIMEOUT))  # may: TimeoutError
            return result[0]  # a Message (or None/False?)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when the connection is lost or closed."""
        _LOGGER.debug("MsgProtocol.connection_lost(%s)", exc)
        if exc is not None:
            raise exc

    def pause_writing(self) -> None:
        """Called by the transport when it's buffer goes over the high-water mark."""
        _LOGGER.debug("MsgProtocol.pause_writing()")
        self._pause_writing = True

    def resume_writing(self) -> None:
        """Called by the transport when it's buffer drains below the low-water mark."""
        _LOGGER.debug("MsgProtocol.resume_writing()")
        self._pause_writing = False


def create_protocol_factory(protocol: asyncio.Protocol, *args, **kwargs) -> Callable:
    def _protocol_factory():
        return protocol(*args, **kwargs)

    return _protocol_factory


def create_msg_stack(
    gwy, msg_handler, protocol_factory=None
) -> Tuple[asyncio.Protocol, asyncio.Transport]:
    """Utility function to provide a transport to a client protocol.

    The architecture is: app (client) -> msg -> pkt -> ser (HW interface).
    """

    def _protocol_factory():
        return create_protocol_factory(MessageProtocol, gwy, msg_handler)()

    msg_protocol = protocol_factory() if protocol_factory else _protocol_factory()

    if gwy.msg_transport:  # HACK: a little messy?
        msg_transport = gwy.msg_transport
        msg_transport.add_protocol(msg_protocol)
    else:
        msg_transport = MessageTransport(gwy, msg_protocol)

    return (msg_protocol, msg_transport)

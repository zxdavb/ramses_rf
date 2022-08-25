#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - RAMSES-II compatible Message processor.

Operates at the msg layer of: app - msg - pkt - h/w
"""
from __future__ import annotations

import asyncio
import logging
import signal
from datetime import datetime as dt
from datetime import timedelta as td
from queue import Empty, Full, PriorityQueue, SimpleQueue
from typing import Awaitable, Callable, Dict, Iterable, List, Optional, TypeVar

from .command import Command
from .const import SZ_DAEMON, SZ_EXPIRED, SZ_EXPIRES, SZ_FUNC, SZ_TIMEOUT, __dev_mode__
from .exceptions import CorruptStateError, InvalidPacketError
from .message import Message
from .packet import Packet

DONT_CREATE_MESSAGES = 3  # duplicate

SZ_WRITER_TASK = "writer_task"

DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
# _LOGGER.setLevel(logging.WARNING)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


_MessageProtocolT = TypeVar("_MessageProtocolT", bound="MessageProtocol")
_MessageTransportT = TypeVar("_MessageTransportT", bound="MessageTransport")


class CallbackAsAwaitable:
    """Create an pair of functions so that the callback can be awaited.

    The awaitable (getter) starts its `timeout` timer only when it is invoked.
    It may raise a `TimeoutError` or a `TypeError`.

    The callback (putter) may put the message in the queue before the getter is invoked.
    """

    SAFETY_TIMEOUT_DEFAULT = 30.0  # used to prevent waiting forever
    SAFETY_TIMEOUT_MINIMUM = 10.0
    HAS_TIMED_OUT = False
    SHORT_WAIT = 0.001  # seconds

    def __init__(self, loop) -> None:
        self._loop = loop or asyncio.get_event_loop()
        self._queue: SimpleQueue = SimpleQueue()  # unbounded, but we use only 1 entry

        self.expires: dt = None  # type: ignore[assignment]

    # the awaitable...
    async def getter(self, timeout: float = SAFETY_TIMEOUT_DEFAULT) -> Message:
        """Poll the queue until the message arrives, or the timer expires."""

        if timeout is None or timeout <= self.SAFETY_TIMEOUT_MINIMUM:
            timeout = self.SAFETY_TIMEOUT_DEFAULT
        self.expires = dt.now() + td(seconds=timeout)

        while dt.now() < self.expires:
            try:
                msg = self._queue.get_nowait()
                break
            except Empty:
                await asyncio.sleep(self.SHORT_WAIT)
        else:
            raise TimeoutError(f"Safety timer expired (timeout={timeout}s)")

        if msg is self.HAS_TIMED_OUT:
            raise TimeoutError("Command timer expired")
        if not isinstance(msg, Message):
            raise TypeError(f"Response is not a message: {msg}")
        return msg

    # the callback...
    def putter(self, msg: Message, timeout: float = SAFETY_TIMEOUT_DEFAULT) -> None:
        """Put the message in the queue (when invoked)."""

        if timeout is None or timeout <= self.SAFETY_TIMEOUT_MINIMUM:
            timeout = self.SAFETY_TIMEOUT_DEFAULT
        self.expires = dt.now() + td(seconds=timeout)

        # self._queue.put_nowait(msg)  # ...so should not raise Full
        self._loop.call_soon_threadsafe(self._queue.put_nowait, msg)


def awaitable_callback(loop) -> tuple[Callable[..., Awaitable[Message]], Callable]:
    """Create a pair of functions, so that a callback can be awaited."""
    obj = CallbackAsAwaitable(loop)
    return obj.getter, obj.putter  # awaitable, callback


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

    READER = "receiver_callback"
    WRITER = SZ_WRITER_TASK

    _extra: dict  # asyncio.BaseTransport

    def __init__(self, gwy, protocol: MessageProtocol, extra: dict = None) -> None:
        super().__init__(extra=extra)

        self._loop = gwy._loop

        self._gwy = gwy
        self._protocols: List[MessageProtocol] = []
        self._extra[self.READER] = self._pkt_receiver
        self._dispatcher: Callable = None  # type: ignore[assignment]

        self._callbacks: Dict[str, dict] = {}

        self._que: PriorityQueue = PriorityQueue(maxsize=self.MAX_BUFFER_SIZE)
        self._write_buffer_limit_high: int = self.MAX_BUFFER_SIZE
        self._write_buffer_limit_low: int = 0
        self._write_buffer_paused = False
        self.set_write_buffer_limits()

        # self._extra[self.WRITER] = self._loop.create_task(self._polling_loop())

        for sig in (signal.SIGINT, signal.SIGTERM):
            self._loop.add_signal_handler(sig, self.abort)

        self._is_closing = False

        self.add_protocol(protocol)  # calls protocol.commection_made()

    def _set_dispatcher(self, dispatcher: Callable) -> None:
        _LOGGER.debug("MsgTransport._set_dispatcher(%s)", dispatcher)

        async def call_send_data(cmd):
            _LOGGER.debug("MsgTransport.pkt_dispatcher(%s): send_data", cmd)
            if cmd._cbk:
                self._add_callback(cmd.rx_header, cmd._cbk)

            if _LOGGER.getEffectiveLevel() == logging.INFO:  # i.e. don't log for DEBUG
                _LOGGER.info("SENT: %s", cmd)

            await self._dispatcher(cmd)  # send_data, *once* callback registered

        async def pkt_dispatcher():
            """Poll the queue and send any command packets to the lower layer."""
            while True:
                try:
                    cmd = self._que.get_nowait()
                except Empty:
                    if self._is_closing:
                        break
                    await asyncio.sleep(0.05)
                    continue
                except AttributeError:  # when self._que == None, from abort()
                    break

                try:
                    if self._dispatcher:
                        await call_send_data(cmd)
                except (AssertionError, NotImplementedError):  # TODO: needs checking
                    pass
                # except:
                #     _LOGGER.exception("")
                #     continue

                self._que.task_done()
                self.get_write_buffer_size()

            _LOGGER.error("MsgTransport.pkt_dispatcher(): connection_lost(None)")
            [p.connection_lost(None) for p in self._protocols]

        self._dispatcher = dispatcher  # type: ignore[assignment]
        self._extra[self.WRITER] = self._loop.create_task(pkt_dispatcher())

        return self._extra[self.WRITER]

    def _add_callback(self, header: str, callback: dict) -> None:
        callback[SZ_EXPIRES] = (
            dt.max
            if callback.get(SZ_DAEMON)
            else dt.now() + td(seconds=callback.get(SZ_TIMEOUT, 1))
        )
        self._callbacks[header] = callback

    def _pkt_receiver(self, pkt: Packet) -> None:
        _LOGGER.debug("MsgTransport._pkt_receiver(%s)", pkt)

        if _LOGGER.getEffectiveLevel() == logging.INFO:  # i.e. don't log for DEBUG
            _LOGGER.info("rcvd: %s", pkt)

        # HACK: 1st, notify all expired callbacks
        for (
            hdr,
            callback,
        ) in self._callbacks.items():
            if callback.get(SZ_EXPIRES, dt.max) < pkt.dtm and not callback.get(
                SZ_EXPIRED
            ):
                # see also: PktProtocolQos.send_data()
                (_LOGGER.warning if DEV_MODE else _LOGGER.info)(
                    "MsgTransport._pkt_receiver(%s): Expired callback", hdr
                )
                callback[SZ_FUNC](CallbackAsAwaitable.HAS_TIMED_OUT)  # ZX: 1/3
                callback[SZ_EXPIRED] = not callback.get(SZ_DAEMON, False)  # HACK:

        # HACK: 2nd, discard any expired callbacks
        self._callbacks = {
            hdr: callback
            for hdr, callback in self._callbacks.items()
            if callback.get(SZ_DAEMON)
            or (callback[SZ_EXPIRES] >= pkt.dtm and not callback.get(SZ_EXPIRED))
        }

        if len(self._protocols) == 0 or (
            self._gwy.config.reduce_processing >= DONT_CREATE_MESSAGES
        ):
            return

        # BUG: all InvalidPacketErrors are not being raised here (see below)
        try:
            msg = Message(self._gwy, pkt)  # should log all invalid msgs appropriately
        except InvalidPacketError:
            return

        # HACK: 3rd, invoke any callback
        # NOTE: msg._pkt._hdr is expensive - don't call it unless there's callbacks
        if self._callbacks and msg._pkt._hdr in self._callbacks:
            callback = self._callbacks[msg._pkt._hdr]
            callback[SZ_FUNC](msg)  # ZX: 2/3
            if not callback.get(SZ_DAEMON):
                del self._callbacks[msg._pkt._hdr]

        # BUG: the InvalidPacketErrors here should have been caught above
        # BUG: should only need to catch CorruptStateError
        for p in self._protocols:
            try:
                self._loop.call_soon(p.data_received, msg)

            except InvalidPacketError:
                return

            except CorruptStateError as exc:
                _LOGGER.error("%s < %s", pkt, exc)

            except (  # protect this code from the upper-layer callback
                AssertionError,
            ) as exc:
                if p is not self._protocols[0]:
                    raise
                _LOGGER.error("%s < exception from app layer: %s", pkt, exc)

            except (  # protect this code from the upper-layer callback
                ArithmeticError,  # incl. ZeroDivisionError,
                AttributeError,
                LookupError,  # incl. IndexError, KeyError
                NameError,  # incl. UnboundLocalError
                RuntimeError,  # incl. RecursionError
                TypeError,
                ValueError,
            ) as exc:
                if p is self._protocols[0]:
                    raise
                _LOGGER.error("%s < exception from app layer: %s", pkt, exc)

    def get_extra_info(self, name: str, default=None):
        """Get optional transport information."""

        return self._extra.get(name, default)

    def abort(self) -> None:
        """Close the transport immediately.

        Buffered data will be lost. No more data will be received. The protocol's
        connection_lost() method will (eventually) be called with None as its argument.
        """

        self._is_closing = True
        self._clear_write_buffer()
        self.close()

    def close(self) -> None:
        """Close the transport.

        Buffered data will be flushed asynchronously. No more data will be received.
        After all buffered data is flushed, the protocol's connection_lost() method will
        (eventually) be called with None as its argument.
        """

        if self._is_closing:
            return
        self._is_closing = True

        self._pause_protocols()
        if task := self._extra.get(self.WRITER):
            task.cancel()

        [self._loop.call_soon(p.connection_lost, None) for p in self._protocols]

    def is_closing(self) -> bool:
        """Return True if the transport is closing or closed."""
        return self._is_closing

    def add_protocol(self, protocol: MessageProtocol) -> None:
        """Attach a new protocol.

        Allow multiple protocols per transport.
        """

        if protocol not in self._protocols:
            if len(self._protocols) > self.MAX_SUBSCRIBERS - 1:
                raise ValueError("Exceeded maximum number of subscribing protocols")

            self._protocols.append(protocol)
            protocol.connection_made(self)

    def get_protocols(self) -> list:
        """Return the list of active protocols.

        There can be multiple protocols per transport.
        """

        return self._protocols

    def is_reading(self) -> bool:
        """Return True if the transport is receiving new data."""

        raise NotImplementedError

    def pause_reading(self) -> None:
        """Pause the receiving end.

        No data will be passed to the protocol's data_received() method until
        resume_reading() is called.
        """

        raise NotImplementedError

    def resume_reading(self) -> None:
        """Resume the receiving end.

        Data received will once again be passed to the protocol's data_received()
        method.
        """

        raise NotImplementedError

    def _clear_write_buffer(self) -> None:
        """Empty the dispatch queue.

        Should not call `get_write_buffer_size()`.
        """

        while not self._que.empty():
            try:
                self._que.get_nowait()
            except Empty:
                continue
            self._que.task_done()

    def _pause_protocols(self, force: bool = None) -> None:
        """Pause the other end."""

        if not self._write_buffer_paused or force:
            self._write_buffer_paused = True
            for p in self._protocols:
                p.pause_writing()

    def _resume_protocols(self, force: bool = None) -> None:
        """Resume the other end."""

        if self._write_buffer_paused or force:
            self._write_buffer_paused = False
            for p in self._protocols:
                p.resume_writing()

    def get_write_buffer_limits(self) -> tuple[int, int]:
        """Get the high and low watermarks for write flow control.

        Return a tuple (low, high) where low and high are positive number of bytes.
        """

        return self._write_buffer_limit_low, self._write_buffer_limit_high

    def set_write_buffer_limits(self, high: int = None, low: int = None) -> None:
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

        high = self.MAX_BUFFER_SIZE if high is None else high
        low = int(self._write_buffer_limit_high * 0.8) if low is None else low

        self._write_buffer_limit_high = max((min((high, self.MAX_BUFFER_SIZE)), 0))
        self._write_buffer_limit_low = min((max((low, 0)), high))

        self.get_write_buffer_size()

    def get_write_buffer_size(self) -> int:
        """Return the current size of the write buffer.

        If required, pause or resume the protocols.
        """

        qsize = self._que.qsize()

        if qsize >= self._write_buffer_limit_high:
            self._pause_protocols()

        elif qsize <= self._write_buffer_limit_low:
            self._resume_protocols()

        return qsize

    def write(self, cmd: Command) -> None:
        """Write some data bytes to the transport.

        This does not block; it buffers the data and arranges for it to be sent out
        asynchronously.
        """
        _LOGGER.debug("MsgTransport.write(%s)", cmd)

        if self._is_closing:
            raise RuntimeError("MsgTransport is closing or has closed")

        if self._write_buffer_paused:
            raise RuntimeError("MsgTransport write buffer is paused")

        if self._gwy.config.disable_sending:
            raise RuntimeError("MsgTransport sending is disabled (cmd discarded)")

        else:
            # if not self._dispatcher:  # TODO: do better?
            #     _LOGGER.debug("MsgTransport.write(%s): no dispatcher", cmd)

            try:
                self._que.put_nowait(cmd)
            except Full:
                pass  # TODO: why? - consider restarting the dispatcher

        self.get_write_buffer_size()

    def writelines(self, list_of_cmds: Iterable[Command]) -> None:
        """Write a list (or any iterable) of data bytes to the transport.

        The default implementation concatenates the arguments and calls write() on the
        result.list_of_cmds
        """

        for cmd in list_of_cmds:
            self.write(cmd)

    def write_eof(self) -> None:
        """Close the write end after flushing buffered data.

        This is like typing ^D into a UNIX program reading from stdin. Data may still be
        received.
        """

        raise NotImplementedError

    def can_write_eof(self) -> bool:
        """Return True if this transport supports write_eof(), False if not."""

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

        # self._gwy = gwy  # is not used
        self._loop = gwy._loop
        self._callback = callback

        self._transport: MessageTransport = None  # type: ignore[assignment]
        self._prev_msg: None | Message = None
        self._this_msg: None | Message = None

        self._pause_writing = True

    def connection_made(self, transport: MessageTransport) -> None:  # type: ignore[override]
        """Called when a connection is made."""
        self._transport = transport
        self.resume_writing()

    def data_received(self, msg: Message) -> None:  # type: ignore[override]
        """Called by the transport when a message is received."""
        _LOGGER.debug("MsgProtocol.data_received(%s)", msg)

        self._this_msg, self._prev_msg = msg, self._this_msg
        self._callback(self._this_msg, prev_msg=self._prev_msg)

    async def send_data(
        self, cmd: Command, callback: Callable = None, _make_awaitable: bool = None
    ) -> Optional[Message]:
        """Called when a command is to be sent."""
        _LOGGER.debug("MsgProtocol.send_data(%s)", cmd)

        if _make_awaitable and callback is not None:
            raise ValueError("only one of `awaitable` and `callback` can be provided")

        if _make_awaitable:  # and callback is None:
            awaitable, callback = awaitable_callback(self._loop)  # ZX: 3/3
        if callback:  # func, args, daemon, timeout (& expired)
            cmd._cbk = {SZ_FUNC: callback, SZ_TIMEOUT: 3}

        while self._pause_writing:
            await asyncio.sleep(0.005)

        self._transport.write(cmd)

        if _make_awaitable:
            return await awaitable()  # CallbackAsAwaitable.getter(timeout: float = ...)
        return None

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when the connection is lost or closed."""
        if exc is not None:
            raise exc

    def pause_writing(self) -> None:
        """Called by the transport when its buffer goes over the high-water mark."""
        self._pause_writing = True

    def resume_writing(self) -> None:
        """Called by the transport when its buffer drains below the low-water mark."""
        self._pause_writing = False


def create_protocol_factory(
    protocol_class: type[asyncio.Protocol], *args, **kwargs
) -> Callable:
    def _protocol_factory() -> asyncio.Protocol:
        return protocol_class(*args, **kwargs)

    return _protocol_factory


def create_msg_stack(
    gwy, msg_callback: Callable, protocol_factory: Callable = None
) -> tuple[_MessageProtocolT, _MessageTransportT]:
    """Utility function to provide a transport to a client protocol.

    The architecture is: app (client) -> msg -> pkt -> ser (HW interface).
    """

    def _protocol_factory():
        return create_protocol_factory(MessageProtocol, gwy, msg_callback)()

    msg_protocol = protocol_factory() if protocol_factory else _protocol_factory()

    if gwy.msg_transport:  # TODO: a little messy?
        msg_transport = gwy.msg_transport
        msg_transport.add_protocol(msg_protocol)
    else:
        msg_transport = MessageTransport(gwy, msg_protocol)

    return (msg_protocol, msg_transport)

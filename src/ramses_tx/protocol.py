#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - RAMSES-II compatible packet protocol."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import datetime as dt
from typing import TYPE_CHECKING, Final

from . import exceptions as exc
from .address import ALL_DEV_ADDR, HGI_DEV_ADDR, NON_DEV_ADDR
from .command import Command
from .const import (
    DEFAULT_GAP_DURATION,
    DEFAULT_NUM_REPEATS,
    DEV_TYPE_MAP,
    SZ_ACTIVE_HGI,
    SZ_IS_EVOFW3,
    DevType,
    Priority,
)
from .logger import set_logger_timesource
from .message import Message
from .packet import Packet
from .protocol_fsm import ProtocolContext
from .schemas import SZ_BLOCK_LIST, SZ_CLASS, SZ_KNOWN_LIST, SZ_PORT_NAME
from .transport import transport_factory
from .typing import ExceptionT, MsgFilterT, MsgHandlerT, QosParams

from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    Code,
)

if TYPE_CHECKING:
    from .address import DeviceIdT
    from .transport import RamsesTransportT

TIP = f", configure the {SZ_KNOWN_LIST}/{SZ_BLOCK_LIST} as required"

_LOGGER = logging.getLogger(__name__)
# _LOGGER.setLevel(logging.WARNING)

# All debug flags (used for dev/test) should be False for published code
_DBG_DISABLE_IMPERSONATION_ALERTS: Final[bool] = False
_DBG_DISABLE_QOS: Final[bool] = False
_DBG_FORCE_LOG_PACKETS: Final[bool] = False


class _BaseProtocol(asyncio.Protocol):
    """Base class for RAMSES II protocols."""

    WRITER_TASK = "writer_task"

    _this_msg: Message | None = None
    _prev_msg: Message | None = None

    def __init__(self, msg_handler: MsgHandlerT) -> None:
        self._msg_handler = msg_handler
        self._msg_handlers: list[MsgHandlerT] = []

        self._transport: RamsesTransportT = None  # type: ignore[assignment]
        self._loop = asyncio.get_running_loop()

        # FIXME: Should start in read-only mode as no connection yet
        self._pause_writing = False
        self._wait_connection_lost = self._loop.create_future()

    @property
    def hgi_id(self) -> DeviceIdT:
        return HGI_DEV_ADDR.id

    def add_handler(
        self,
        msg_handler: MsgHandlerT,
        /,
        *,
        msg_filter: MsgFilterT | None = None,
    ) -> Callable[[], None]:
        """Add a Message handler to the list of such callbacks.

        Returns a callback that can be used to subsequently remove the Message handler.
        """

        def del_handler() -> None:
            if msg_handler in self._msg_handlers:
                self._msg_handlers.remove(msg_handler)

        if msg_handler not in self._msg_handlers:
            self._msg_handlers.append(msg_handler)

        return del_handler

    def connection_made(self, transport: RamsesTransportT) -> None:  # type: ignore[override]
        """Called when the connection to the Transport is established.

        The argument is the transport representing the pipe connection. To receive data,
        wait for pkt_received() calls. When the connection is closed, connection_lost()
        is called.
        """

        self._transport = transport

    def connection_lost(self, err: ExceptionT | None) -> None:  # type: ignore[override]
        """Called when the connection to the Transport is lost or closed.

        The argument is an exception object or None (the latter meaning a regular EOF is
        received or the connection was aborted or closed).
        """

        if self._wait_connection_lost.done():  # BUG: why is callback invoked twice?
            return

        if err:
            self._wait_connection_lost.set_exception(err)
        else:
            self._wait_connection_lost.set_result(None)

    @property
    def wait_connection_lost(self) -> asyncio.Future:
        """Return a future that will block until connection_lost() has been invoked.

        Can call fut.result() to check for result/any exception.
        """
        return self._wait_connection_lost

    def pause_writing(self) -> None:
        """Called when the transport's buffer goes over the high-water mark.

        Pause and resume calls are paired -- pause_writing() is called once when the
        buffer goes strictly over the high-water mark (even if subsequent writes
        increases the buffer size even more), and eventually resume_writing() is called
        once when the buffer size reaches the low-water mark.

        Note that if the buffer size equals the high-water mark, pause_writing() is not
        called -- it must go strictly over. Conversely, resume_writing() is called when
        the buffer size is equal or lower than the low-water mark.  These end conditions
        are important to ensure that things go as expected when either mark is zero.

        NOTE: This is the only Protocol callback that is not called through
        EventLoop.call_soon() -- if it were, it would have no effect when it's most
        needed (when the app keeps writing without yielding until pause_writing() is
        called).
        """

        self._pause_writing = True

    def resume_writing(self) -> None:
        """Called when the transport's buffer drains below the low-water mark.

        See pause_writing() for details.
        """

        self._pause_writing = False

    async def send_cmd(  # send_cmd() -> _send_cmd()
        self,
        cmd: Command,
        /,
        *,
        gap_duration: float = DEFAULT_GAP_DURATION,
        num_repeats: int = DEFAULT_NUM_REPEATS,
        priority: Priority = Priority.DEFAULT,
        qos: QosParams | None = None,
    ) -> Packet | None:
        """This is the wrapper for self._send_cmd(cmd)."""

        if _DBG_FORCE_LOG_PACKETS:
            _LOGGER.warning(f"QUEUED:     {cmd}")
        else:
            _LOGGER.debug(f"QUEUED:     {cmd}")

        # if not self._transport:
        #     raise exc.ProtocolSendFailed("There is no connected Transport")
        if self._pause_writing:
            raise exc.ProtocolSendFailed("The Protocol is currently read-only")

        return await self._send_cmd(
            cmd,
            gap_duration=gap_duration,
            num_repeats=num_repeats,
            priority=priority,
            qos=qos,
        )

    async def _send_cmd(  # _send_cmd() *-> _send_frame()
        self,
        cmd: Command,
        /,
        *,
        gap_duration: float = DEFAULT_GAP_DURATION,
        num_repeats: int = DEFAULT_NUM_REPEATS,
        priority: Priority = Priority.DEFAULT,
        qos: QosParams | None = None,
    ) -> Packet | None:  # only cmd, no args, kwargs
        """This is the wrapper for self._send_frame(cmd), with repeats.

        Repeats are distinct from retries (a QoS feature): you wouldn't have both.
        """

        await self._send_frame(str(cmd))
        for _ in range(num_repeats - 1):
            await asyncio.sleep(gap_duration)
            await self._send_frame(str(cmd))

        return None

    async def _send_frame(self, frame: str) -> None:  # _send_frame() -> transport
        """Write some bytes to the transport."""
        await self._transport.write_frame(frame)

    def pkt_received(self, pkt: Packet) -> None:
        """A wrapper for self._pkt_received(pkt)."""
        if _DBG_FORCE_LOG_PACKETS:
            _LOGGER.warning(f"Recv'd: {pkt._rssi} {pkt}")
        elif _LOGGER.getEffectiveLevel() > logging.DEBUG:
            _LOGGER.info(f"Recv'd: {pkt._rssi} {pkt}")
        else:
            _LOGGER.debug(f"Recv'd: {pkt._rssi} {pkt}")

        self._pkt_received(pkt)

    def _pkt_received(self, pkt: Packet) -> None:
        """Called by the Transport when a Packet is received."""
        try:
            msg = Message(pkt)  # should log all invalid msgs appropriately
        except exc.PacketInvalid:  # TODO: InvalidMessageError (packet is valid)
            return

        self._this_msg, self._prev_msg = msg, self._this_msg
        self._msg_received(msg)

    def _msg_received(self, msg: Message) -> None:
        """Pass any valid/wanted Messages to the client's callback.

        Also maintain _prev_msg, _this_msg attrs.
        """

        if self._msg_handler:  # type: ignore[truthy-function]
            self._loop.call_soon_threadsafe(self._msg_handler, msg)
        for callback in self._msg_handlers:
            # TODO: if handler's filter returns True:
            self._loop.call_soon_threadsafe(callback, msg)


class _DeviceIdFilterMixin(_BaseProtocol):
    """Filter out any unwanted (but otherwise valid) packets via device ids."""

    def __init__(
        self,
        msg_handler: MsgHandlerT,
        enforce_include_list: bool = False,
        exclude_list: dict[DeviceIdT, dict] | None = None,
        include_list: dict[DeviceIdT, dict] | None = None,
    ) -> None:
        super().__init__(msg_handler)

        exclude_list = exclude_list or {}
        include_list = include_list or {}

        self.enforce_include = enforce_include_list
        self._exclude = list(exclude_list.keys())
        self._include = list(include_list.keys())
        self._include += [ALL_DEV_ADDR.id, NON_DEV_ADDR.id]

        self._active_hgi: DeviceIdT | None = None
        self._known_hgi = self._extract_known_hgi(include_list)

        self._foreign_gwys_lst: list[DeviceIdT] = []
        self._foreign_last_run = dt.now().date()

    @property
    def hgi_id(self) -> DeviceIdT:
        if not self._transport:
            return self._known_hgi or HGI_DEV_ADDR.id
        return self._transport.get_extra_info(  # type: ignore[no-any-return]
            SZ_ACTIVE_HGI, self._known_hgi or HGI_DEV_ADDR.id
        )

    @staticmethod
    def _extract_known_hgi(include_list: dict[DeviceIdT, dict]) -> DeviceIdT | None:
        """Return the device_id of the gateway specified in the include_list, if any.

        The 'Known' gateway is the predicted Active gateway, given the known_list.
        The 'Active' gateway is the USB device that is Tx/Rx frames.

        The Known gateway ID should be the Active gateway ID, but does not have to
        match.

        Send a warning if the include_list is configured incorrectly.
        """

        known_hgis = [
            k for k, v in include_list.items() if v.get(SZ_CLASS) == DevType.HGI
        ]
        known_hgis = known_hgis or [
            k for k, v in include_list.items() if k[:2] == "18" and not v.get(SZ_CLASS)
        ]

        if not known_hgis:
            _LOGGER.info(
                f"The {SZ_KNOWN_LIST} should include exactly one gateway (HGI), "
                f"but does not (make sure you specify class: HGI)"
            )
            return None

        known_hgi = known_hgis[0]

        if include_list[known_hgi].get(SZ_CLASS) != DevType.HGI:
            _LOGGER.info(
                f"The {SZ_KNOWN_LIST} should include a well-configured gateway (HGI), "
                f"{known_hgi} should specify class: HGI (18: is also used for HVAC)"
            )

        elif len(known_hgis) > 1:
            _LOGGER.info(
                f"The {SZ_KNOWN_LIST} should include exactly one gateway (HGI), "
                f"{known_hgi} is the assumed device id (is it/are the others HVAC?)"
            )

        else:
            _LOGGER.debug(
                f"The {SZ_KNOWN_LIST} specifies {known_hgi} as the gateway (HGI)"
            )

        return known_hgis[0]

    def _set_active_hgi(self, dev_id: DeviceIdT, by_signature: bool = False) -> None:
        """Set the Active Gateway (HGI) device_id.

        Send a warning if the include list is configured incorrectly.
        """

        assert self._active_hgi is None  # should only be called once

        msg = f"The active gateway {dev_id}: {{ class: HGI }} "
        msg += "(by signature)" if by_signature else "(by filter)"

        if dev_id not in self._exclude:
            self._active_hgi = dev_id
            # else: setting self._active_hgi will not help

        if dev_id in self._exclude:
            _LOGGER.error(f"{msg} MUST NOT be in the {SZ_BLOCK_LIST}{TIP}")
        elif dev_id in self._include:
            pass
        elif self.enforce_include:
            _LOGGER.warning(f"{msg} SHOULD be in the (enforced) {SZ_KNOWN_LIST}")
            # self._include.append(dev_id)  # a good idea?
        else:
            _LOGGER.warning(f"{msg} SHOULD be in the {SZ_KNOWN_LIST}")

    def _is_wanted_addrs(
        self, src_id: DeviceIdT, dst_id: DeviceIdT, sending: bool = False
    ) -> bool:
        """Return True if the packet is not to be filtered out.

        In any one packet, an excluded device_id 'trumps' an included device_id.

        There are two ways to set the Active Gateway (HGI80/evofw3):
        - by signature (evofw3 only), when frame -> packet
        - by known_list (HGI80/evofw3), when filtering packets
        """

        def warn_foreign_hgi(dev_id: DeviceIdT) -> None:
            current_date = dt.now().date()

            if self._foreign_last_run != current_date:
                self._foreign_last_run = current_date
                self._foreign_gwys_lst = []  # reset the list every 24h

            if dev_id in self._foreign_gwys_lst:
                return

            _LOGGER.warning(
                f"Device {dev_id} is potentially a Foreign gateway, "
                f"the Active gateway is {self._active_hgi}, "
                f"alternatively, is it a HVAC device?{TIP}"
            )
            self._foreign_gwys_lst.append(dev_id)

        for dev_id in dict.fromkeys((src_id, dst_id)):  # removes duplicates
            if dev_id in self._exclude:  # problems if incl. active gateway
                return False

            if dev_id == self._active_hgi:  # is active gwy
                continue  # consider: return True

            if dev_id in self._include:  # incl. 63:262142 & --:------
                continue

            if sending and dev_id == HGI_DEV_ADDR.id:
                continue

            if self.enforce_include:
                return False

            if dev_id[:2] != DEV_TYPE_MAP.HGI:
                continue

            if self._active_hgi:  # this 18: is not in known_list
                warn_foreign_hgi(dev_id)

        return True

    def pkt_received(self, pkt: Packet) -> None:
        if not self._is_wanted_addrs(pkt.src.id, pkt.dst.id):
            raise exc.ProtocolError(f"Packet excluded by device_id filter: {pkt}")
        super().pkt_received(pkt)

    async def send_cmd(self, cmd: Command, *args, **kwargs) -> Packet | None:
        if not self._is_wanted_addrs(cmd.src.id, cmd.dst.id, sending=True):
            raise exc.ProtocolError(f"Command excluded by device_id filter: {cmd}")
        return await super().send_cmd(cmd, *args, **kwargs)


# NOTE: MRO: Impersonate -> Gapped/DutyCycle -> SyncCycle -> Qos/Context -> Base
# Impersonate first, as the Puzzle Packet needs to be sent before the Command
# Order of DutyCycle/Gapped doesn't matter, but both before SyncCycle
# QosTimers last, to start any timers immediately after Tx of Command


# ### Read-Only Protocol for FileTransport, PortTransport #############################
class ReadProtocol(_DeviceIdFilterMixin, _BaseProtocol):
    """A protocol that can only receive Packets."""

    def __init__(self, msg_handler: MsgHandlerT, **kwargs) -> None:
        super().__init__(msg_handler, **kwargs)

        self._pause_writing = True

    def connection_made(  # type: ignore[override]
        self, transport: RamsesTransportT, /, *, ramses: bool = False
    ) -> None:
        """Consume the callback if invoked by SerialTransport rather than PortTransport.

        Our PortTransport wraps SerialTransport and will wait for the signature echo
        to be received (c.f. FileTransport) before calling connection_made(ramses=True).
        """
        super().connection_made(transport)

    def resume_writing(self) -> None:
        raise NotImplementedError(f"{self}: The chosen Protocol is Read-Only")

    async def send_cmd(
        self,
        cmd: Command,
        /,
        *,
        gap_duration: float = DEFAULT_GAP_DURATION,
        num_repeats: int = DEFAULT_NUM_REPEATS,
        priority: Priority = Priority.DEFAULT,
        qos: QosParams | None = None,
    ) -> Packet | None:
        """Raise an exception as the Protocol cannot send Commands."""
        raise NotImplementedError(f"{self}: The chosen Protocol is Read-Only")


# ### Read-Write (sans QoS) Protocol for PortTransport ################################
class PortProtocol(_DeviceIdFilterMixin, _BaseProtocol):
    """A protocol that can receive Packets and send Commands."""

    _is_evofw3: bool | None = None

    def connection_made(  # type: ignore[override]
        self, transport: RamsesTransportT, /, *, ramses: bool = False
    ) -> None:
        """Consume the callback if invoked by SerialTransport rather than PortTransport.

        Our PortTransport wraps SerialTransport and will wait for the signature echo
        to be received (c.f. FileTransport) before calling connection_made(ramses=True).
        """

        if not ramses:
            return None

        super().connection_made(transport)
        # TODO: needed? self.resume_writing()

        self._set_active_hgi(self._transport.get_extra_info(SZ_ACTIVE_HGI))
        self._is_evofw3 = self._transport.get_extra_info(SZ_IS_EVOFW3)

    def connection_lost(self, err: ExceptionT | None) -> None:  # type: ignore[override]
        """Called when the connection is lost or closed."""

        super().connection_lost(err)

    def pkt_received(self, pkt: Packet) -> None:
        """Pass any valid/wanted packets to the callback."""
        super().pkt_received(pkt)

    async def _send_frame(self, frame: str) -> None:
        """Write some data bytes to the transport."""

        await super()._send_frame(frame)

    async def _send_impersonation_alert(self, cmd: Command) -> None:
        """Send an puzzle packet warning that impersonation is occurring."""

        if _DBG_DISABLE_IMPERSONATION_ALERTS:
            return

        msg = f"{self}: Impersonating device: {cmd.src}, for pkt: {cmd.tx_header}"
        if self._is_evofw3 is False:
            _LOGGER.error(f"{msg}, NB: non-evofw3 gateways can't impersonate!")
        else:
            _LOGGER.info(msg)

        await self._send_cmd(Command._puzzle(msg_type="11", message=cmd.tx_header))

    async def send_cmd(
        self,
        cmd: Command,
        /,
        *,
        gap_duration: float = DEFAULT_GAP_DURATION,
        num_repeats: int = DEFAULT_NUM_REPEATS,
        priority: Priority = Priority.DEFAULT,
        qos: QosParams | None = None,
    ) -> Packet | None:
        """Send a Command without QoS (send an impersonation alert if required)."""

        assert gap_duration == DEFAULT_GAP_DURATION
        assert DEFAULT_NUM_REPEATS <= num_repeats <= 3

        if qos and not isinstance(self, QosProtocol):
            raise exc.ProtocolError(f"{cmd} < QoS is not supported by this Protocol")

        if cmd.src.id != HGI_DEV_ADDR.id:  # or actual HGI addr
            await self._send_impersonation_alert(cmd)

        return await super().send_cmd(
            cmd,
            gap_duration=gap_duration,
            num_repeats=num_repeats,
            priority=priority,
            qos=qos,
        )


# ### Read-Write Protocol for QosTransport ############################################
class QosProtocol(PortProtocol):
    """A protocol that can receive Packets and send Commands with QoS (using a FSM)."""

    def __init__(
        self, msg_handler: MsgHandlerT, selective_qos: bool = False, **kwargs
    ) -> None:
        """Add a FSM to the Protocol, to provide QoS."""
        super().__init__(msg_handler, **kwargs)

        self._context = ProtocolContext(self)
        self._selective_qos = selective_qos  # QoS for some commands

    def __repr__(self) -> str:
        cls = self._context.state.__class__.__name__
        return f"QosProtocol({cls}, len(queue)={self._context._que.unfinished_tasks})"

    def connection_made(  # type: ignore[override]
        self, transport: RamsesTransportT, /, *, ramses: bool = False
    ) -> None:
        """Consume the callback if invoked by SerialTransport rather than PortTransport.

        Our PortTransport wraps SerialTransport and will wait for the signature echo
        to be received (c.f. FileTransport) before calling connection_made(ramses=True).
        """

        if not ramses:
            return

        super().connection_made(transport, ramses=ramses)
        self._context.connection_made(transport)

        if self._pause_writing:
            self._context.pause_writing()
        else:
            self._context.resume_writing()

    def connection_lost(self, err: ExceptionT | None) -> None:  # type: ignore[override]
        """Inform the FSM that the connection with the Transport has been lost."""

        super().connection_lost(err)
        self._context.connection_lost(err)  # is this safe, when KeyboardInterrupt?

    def pkt_received(self, pkt: Packet) -> None:
        """Inform the FSM that a Packet has been received."""

        super().pkt_received(pkt)
        self._context.pkt_received(pkt)

    def pause_writing(self) -> None:
        """Inform the FSM that the Protocol has been paused."""

        super().pause_writing()
        self._context.pause_writing()

    def resume_writing(self) -> None:
        """Inform the FSM that the Protocol has been paused."""

        super().resume_writing()
        self._context.resume_writing()

    async def _send_cmd(
        self,
        cmd: Command,
        /,
        *,
        gap_duration: float = DEFAULT_GAP_DURATION,
        num_repeats: int = DEFAULT_NUM_REPEATS,
        priority: Priority = Priority.DEFAULT,
        qos: QosParams | None = None,
    ) -> Packet | None:
        """Wrapper to send a Command with QoS (retries, until success or exception)."""

        # Should do the same as super()._send_cmd()
        async def send_cmd(kmd: Command) -> None:
            """Wrapper to for self._send_frame(cmd) with x re-transmits.

            Repeats are distinct from retries (a QoS feature): you wouldn't have both.
            """

            assert kmd is cmd  # maybe the FSM is confused

            await self._send_frame(str(kmd))
            for _ in range(num_repeats - 1):
                await asyncio.sleep(gap_duration)
                await self._send_frame(str(kmd))

        # if cmd.code == Code._PUZZ:  # NOTE: not as simple as this
        #     priority = Priority.HIGHEST  # FIXME: hack for _7FFF

        _CODES = (Code._0006, Code._0404, Code._1FC9)  # must have QoS

        # selective QoS (HACK) or the cmd does not want QoS
        if (self._selective_qos and cmd.code not in _CODES) or qos is None:
            return await send_cmd(cmd)  # type: ignore[func-returns-value]

        # if qos is None and cmd.code in _CODES:
        #     qos = QosParams(wait_for_reply=True)
        # if self._selective_qos and qos is None:
        #     return await send_cmd(cmd)  # type: ignore[func-returns-value]
        # if qos is None:
        #     qos = QosParams()

        # Should do this check before, or after previous block (of non-QoS sends)?
        # if not self._transport._is_wanted_addrs(cmd.src.id, cmd.dst.id, sending=True):
        #     raise exc.ProtocolError(
        #         f"{self}: Failed to send {cmd._hdr}: excluded by list"
        #     )

        try:
            return await self._context.send_cmd(send_cmd, cmd, priority, qos)
        # except InvalidStateError as err:  # TODO: handle InvalidStateError separately
        #     # reset protocol stack
        except exc.ProtocolError as err:
            # raise exc.ProtocolError(
            #     f"{self}: Failed to send {cmd._hdr}: {err}"
            # ) from err
            _LOGGER.info(f"{self}: Failed to send {cmd._hdr}: {err}")
            raise

    async def send_cmd(
        self,
        cmd: Command,
        /,
        *,
        gap_duration: float = DEFAULT_GAP_DURATION,
        num_repeats: int = DEFAULT_NUM_REPEATS,
        priority: Priority = Priority.DEFAULT,
        qos: QosParams | None = None,  # max_retries, timeout, wait_for_reply
    ) -> Packet | None:
        """Send a Command with Qos (with retries, until success or ProtocolError).

        Returns the Command's response Packet or the Command echo if a response is not
        expected (e.g. sending an RP).

        If wait_for_reply is True, return the RQ's RP (or W's I), or raise an exception
        if one doesn't arrive. If it is False, return the echo of the Command only. If
        it is None (the default), act as True for RQs, and False for all other Commands.

        Commands are queued and sent FIFO, except higher-priority Commands are always
        sent first.
        """

        assert gap_duration == DEFAULT_GAP_DURATION
        assert num_repeats == DEFAULT_NUM_REPEATS

        return await super().send_cmd(
            cmd,
            gap_duration=gap_duration,
            num_repeats=num_repeats,
            priority=priority,
            qos=qos,
        )


RamsesProtocolT = QosProtocol | PortProtocol | ReadProtocol


def protocol_factory(
    msg_handler: MsgHandlerT,
    /,
    *,
    disable_qos: bool | None = False,
    disable_sending: bool | None = False,
    enforce_include_list: bool = False,
    exclude_list: dict[DeviceIdT, dict] | None = None,
    include_list: dict[DeviceIdT, dict] | None = None,
) -> RamsesProtocolT:
    """Create and return a Ramses-specific async packet Protocol."""

    # The intention is, that once we are read-only, we're always read-only, but
    # until the QoS state machine is stable:
    #   disable_qos is True,  means QoS is always disabled
    #               is False, means QoS is never disabled
    #               is None,  means QoS is disabled, but enabled by the command

    if disable_sending:
        _LOGGER.debug("ReadProtocol: Sending has been disabled")
        return ReadProtocol(
            msg_handler,
            enforce_include_list=enforce_include_list,
            exclude_list=exclude_list,
            include_list=include_list,
        )

    if disable_qos or _DBG_DISABLE_QOS:
        _LOGGER.debug("PortProtocol: QoS has been disabled")
        return PortProtocol(
            msg_handler,
            enforce_include_list=enforce_include_list,
            exclude_list=exclude_list,
            include_list=include_list,
        )

    _LOGGER.debug("QosProtocol: QoS has been enabled")
    return QosProtocol(
        msg_handler,
        selective_qos=disable_qos is None,
        enforce_include_list=enforce_include_list,
        exclude_list=exclude_list,
        include_list=include_list,
    )


async def create_stack(
    msg_handler: MsgHandlerT,
    /,
    *,
    protocol_factory_: Callable | None = None,
    transport_factory_: Callable | None = None,
    disable_qos: bool | None = False,
    disable_sending: bool | None = False,
    enforce_include_list: bool = False,
    exclude_list: dict[DeviceIdT, dict] | None = None,
    include_list: dict[DeviceIdT, dict] | None = None,
    **kwargs,  # TODO: these are for the transport_factory
) -> tuple[RamsesProtocolT, RamsesTransportT]:
    """Utility function to provide a Protocol / Transport pair.

    Architecture: gwy (client) -> msg (Protocol) -> pkt (Transport) -> HGI/log (or dict)
    - send Commands via awaitable Protocol.send_cmd(cmd)
    - receive Messages via Gateway._handle_msg(msg) callback
    """

    read_only = kwargs.get("packet_dict") or kwargs.get("packet_log")
    disable_sending = disable_sending or read_only

    protocol = (protocol_factory_ or protocol_factory)(
        msg_handler,
        disable_qos=disable_qos,
        disable_sending=disable_sending,
        enforce_include_list=enforce_include_list,
        exclude_list=exclude_list,
        include_list=include_list,
    )

    transport = await (transport_factory_ or transport_factory)(
        protocol, disable_qos=disable_qos, disable_sending=disable_sending, **kwargs
    )

    if not kwargs.get(SZ_PORT_NAME):
        set_logger_timesource(transport._dt_now)
        _LOGGER.warning("Logger datetimes maintained as most recent packet timestamp")

    return protocol, transport

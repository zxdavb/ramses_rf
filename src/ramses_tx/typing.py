#!/usr/bin/env python3
"""RAMSES RF - Typing for RamsesProtocol & RamsesTransport."""

import asyncio
from collections.abc import Callable
from datetime import datetime as dt
from io import TextIOWrapper
from typing import Any, Protocol, TypeVar

from serial import Serial  # type: ignore[import-untyped]

from .command import Command
from .const import (
    DEFAULT_GAP_DURATION,
    DEFAULT_MAX_RETRIES,
    DEFAULT_NUM_REPEATS,
    DEFAULT_SEND_TIMEOUT,
    DEFAULT_WAIT_FOR_REPLY,
    Priority,
)
from .message import Message
from .packet import Packet

ExceptionT = TypeVar("ExceptionT", bound=type[Exception])
MsgFilterT = Callable[[Message], bool]
MsgHandlerT = Callable[[Message], None]
SerPortNameT = str


class QosParams:
    """A container for QoS attributes and state."""

    def __init__(
        self,
        *,
        max_retries: int | None = DEFAULT_MAX_RETRIES,
        timeout: float | None = DEFAULT_SEND_TIMEOUT,
        wait_for_reply: bool | None = DEFAULT_WAIT_FOR_REPLY,
    ) -> None:
        """Create a QosParams instance."""

        self._max_retries = DEFAULT_MAX_RETRIES if max_retries is None else max_retries
        self._timeout = timeout or DEFAULT_SEND_TIMEOUT
        self._wait_for_reply = wait_for_reply

        self._echo_pkt: Packet | None = None
        self._rply_pkt: Packet | None = None

        self._dt_cmd_sent: dt | None = None
        self._dt_echo_rcvd: dt | None = None
        self._dt_rply_rcvd: dt | None = None

    @property
    def max_retries(self) -> int:
        return self._max_retries

    @property
    def timeout(self) -> float:
        return self._timeout

    @property
    def wait_for_reply(self) -> bool | None:
        return self._wait_for_reply


class SendParams:
    """A container for Send attributes and state."""

    def __init__(
        self,
        *,
        gap_duration: float | None = DEFAULT_GAP_DURATION,
        num_repeats: int | None = DEFAULT_NUM_REPEATS,
        priority: Priority | None = Priority.DEFAULT,
    ) -> None:
        """Create a SendParams instance."""

        self._gap_duration = gap_duration or DEFAULT_GAP_DURATION
        self._num_repeats = num_repeats or DEFAULT_NUM_REPEATS
        self._priority = priority or Priority.DEFAULT

        self._dt_cmd_arrived: dt | None = None
        self._dt_cmd_queued: dt | None = None
        self._dt_cmd_sent: dt | None = None

    @property
    def gap_duration(self) -> float:
        return self._gap_duration

    @property
    def num_repeats(self) -> int:
        return self._num_repeats

    @property
    def priority(self) -> Priority:
        return self._priority


class xRamsesTransportT(Protocol):
    """A typing.Protocol (i.e. a structural type) of asyncio.Transport."""

    _is_closing: bool
    # _is_reading: bool

    def __init__(  # type: ignore[no-any-unimported]
        self,
        protocol: asyncio.Protocol,
        pkt_source: Serial | dict[str, str] | TextIOWrapper,
        loop: asyncio.AbstractEventLoop | None = None,
        extra: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None: ...

    def _dt_now(self) -> dt: ...

    def _abort(self, exc: ExceptionT) -> None:  # only in serial transport
        ...

    def _close(self, exc: ExceptionT | None = None) -> None: ...

    def close(self) -> None:
        """Close the transport gracefully.

        Schedules a call to `transport._protocol.connection_lost(None)`."""
        ...

    def get_extra_info(self, name: str, default: Any | None = None) -> Any: ...

    def is_closing(self) -> bool: ...

    # NOTE this should not be included - maybe is a subclasses
    # @staticmethod
    # def is_hgi80(serial_port: SerPortName) -> None | bool: ...

    def is_reading(self) -> bool: ...

    def pause_reading(self) -> None: ...

    def resume_reading(self) -> None: ...

    def send_frame(self, frame: str) -> None: ...

    # NOTE RamsesProtocol will not invoke write() directly
    def write(self, data: bytes) -> None: ...


class xRamsesProtocolT(Protocol):
    """A typing.Protocol (i.e. a structural type) of asyncio.Protocol."""

    _msg_handler: MsgHandlerT
    _pause_writing: bool
    _transport: xRamsesTransportT

    def __init__(self, msg_handler: MsgHandlerT) -> None: ...

    def add_handler(
        self, msg_handler: MsgHandlerT, /, *, msg_filter: MsgFilterT | None = None
    ) -> Callable[[], None]: ...

    def connection_lost(self, err: ExceptionT | None) -> None: ...

    @property
    def wait_connection_lost(self) -> asyncio.Future[ExceptionT | None]: ...

    def connection_made(self, transport: xRamsesTransportT) -> None: ...

    def pause_writing(self) -> None: ...

    def pkt_received(self, pkt: Packet) -> None: ...

    def resume_writing(self) -> None: ...

    async def send_cmd(
        self,
        cmd: Command,
        /,
        *,
        gap_duration: float = DEFAULT_GAP_DURATION,
        num_repeats: int = DEFAULT_NUM_REPEATS,
        priority: Priority = Priority.DEFAULT,
        qos: QosParams | None = None,
    ) -> Packet | None: ...

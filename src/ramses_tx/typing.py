#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - Typing for RamsesProtocol & RamsesTransport."""

from collections.abc import Callable
from enum import IntEnum
from typing import Any, Protocol, TypeVar

from .command import Command
from .message import Message
from .packet import Packet

ExceptionT = TypeVar("ExceptionT", bound=type[Exception])
MsgFilterT = Callable[[Message], bool]
MsgHandlerT = Callable[[Message], None]
SerPortName = str


_DEFAULT_TX_COUNT = 1  # number of times to Tx each Command
_DEFAULT_TX_DELAY = 0.02  # gap between re-Tx of same Command

DEFAULT_MAX_RETRIES = 3
DEFAULT_TIMEOUT = 30.0  # total waiting for successful send: FIXME


class SendPriority(IntEnum):
    _MAX = -9
    HIGH = -2
    DEFAULT = 0
    LOW = 2
    _MIN = 9


class QosParams:
    """A container for QoS parameters."""

    def __init__(
        self,
        *,
        max_retries: int = DEFAULT_MAX_RETRIES,
        timeout: float = DEFAULT_TIMEOUT,
        wait_for_reply: bool = None,  # None has a special meaning, distinct from False
    ) -> None:
        self._max_retries = max_retries
        self._timeout = timeout
        self._wait_for_reply = wait_for_reply

    @property
    def max_retries(self) -> int:
        return self._max_retries

    @property
    def timeout(self) -> float:
        return self._timeout

    @property
    def wait_for_reply(self) -> bool:
        return self._wait_for_reply


class RamsesTransportT(Protocol):
    """Is not a asyncio.Protocol, but is a typing.Protocol (i.e. a structural type)."""

    def close(self, exc: ExceptionT | None = None) -> None:
        ...

    def get_extra_info(self, name, default: Any | None = None) -> Any:
        ...

    def is_closing(self) -> bool:
        ...

    # NOTE this should not be included - maybe is a subclasses
    # @staticmethod
    # def is_hgi80(serial_port: SerPortName) -> None | bool: ...

    def is_reading(self) -> bool:
        ...

    def pause_reading(self) -> None:
        ...

    def resume_reading(self) -> None:
        ...

    def send_frame(self, frame: str) -> None:
        ...

    # NOTE this should not be included - a RamsesProtocol will not invoke it
    # def write(self, data: bytes) -> None: ...


class RamsesProtocolT(Protocol):
    """Is not a asyncio.Protocol, but is a typing.Protocol (i.e. a structural type)."""

    def add_handler(
        self, /, *, msg_handler: MsgHandlerT, msg_filter: MsgFilterT | None = None
    ) -> Callable[[], None]:
        ...

    def connection_lost(self, exc: ExceptionT | None) -> None:
        ...

    def connection_made(self, transport: RamsesTransportT) -> None:
        ...

    def pause_writing(self) -> None:
        ...

    def pkt_received(self, pkt: Packet) -> None:
        ...

    def resume_writing(self) -> None:
        ...

    async def send_cmd(
        self,
        cmd: Command,
        /,
        *,
        gap_duration: float = _DEFAULT_TX_DELAY,
        priority: SendPriority = SendPriority.DEFAULT,
        send_count: int = _DEFAULT_TX_COUNT,
        qos: QosParams | None = None,
    ) -> Packet | None:
        ...

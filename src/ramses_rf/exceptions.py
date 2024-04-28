#!/usr/bin/env python3
"""RAMSES RF - exceptions above the packet/protocol/transport layer."""

from __future__ import annotations

from ramses_tx.exceptions import (  # noqa: F401
    PacketAddrSetInvalid,
    PacketInvalid,
    PacketPayloadInvalid,
    ProtocolError,
    RamsesException,
)


class _RamsesUpperError(RamsesException):
    """A failure in the upper layer (state/schema, gateway, bindings, schedule)."""


########################################################################################
# Errors above the protocol/transport layer, incl. message processing, state & schema


class BindingError(_RamsesUpperError):
    """An error occured when binding."""


class BindingFsmError(BindingError):
    """The binding FSM was/became inconsistent (this shouldn't happen)."""


class BindingFlowFailed(BindingError):
    """The binding failed due to a timeout or retry limit being exceeded."""


########################################################################################
# Errors above the protocol/transport layer, incl. message processing, state & schema


class ScheduleError(_RamsesUpperError):
    """An error occured when getting/setting a schedule."""


class ScheduleFsmError(BindingError):
    """The schedule FSM was/became inconsistent (this shouldn't happen)."""


class ScheduleFlowError(BindingError):
    """The get/set schedule failed due to a timeout or retry limit being exceeded."""


########################################################################################
# Errors above the protocol/transport layer, incl. message processing, state & schema


class ExpiredCallbackError(_RamsesUpperError):
    """Raised when the callback has expired."""


class SystemInconsistent(_RamsesUpperError):
    """Base class for exceptions in this module."""


class SystemSchemaInconsistent(SystemInconsistent):
    """Raised when the system state (usu. schema) is inconsistent."""

    HINT = "try restarting the client library"


class DeviceNotFaked(SystemInconsistent):
    """Raised when the device does not have faking enabled."""

    HINT = "faking is configured in the known_list"


class ForeignGatewayError(_RamsesUpperError):
    """Raised when a foreign gateway is detected.

    These devices may not be gateways (set a class), or belong to a neighbour (exclude
    via block_list/known_list), or should be allowed (known_list).
    """

    HINT = "consider enforcing a known_list"

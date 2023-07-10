#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - exceptions."""
from __future__ import annotations


class RamsesError(Exception):
    """Base class for exceptions in this module."""

    ERR_MSG = "exception has occurred"
    ERR_TIP = ""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.message = args[0] if args else None

    def __str__(self) -> str:
        if self.message:
            return f"{self.ERR_MSG}: {self.message}{self.ERR_TIP}"
        return f"{self.ERR_MSG} {self.ERR_TIP}"


# Errors at/below the protocol/transport layer


class ProtocolBaseError(RamsesError):
    """Base class for exceptions in this module."""

    pass


class ProtocolError(ProtocolBaseError):
    """When attempting to transition to the next state, an error has occurred."""


class InvalidStateError(ProtocolError):
    """The context was found to be in an invalid state."""

    pass


class RetryLimitExceeded(ProtocolError):
    """When attempting to transition to the next state, the retry limit was exceeded."""

    pass


class SendTimeoutError(ProtocolError):
    """When attempting to transition to the next state, a timer has expired."""

    pass


# Errors above the protocol/transport layer


class ExpiredCallbackError(RamsesError):
    """Raised when the callback has expired."""

    ERR_MSG = "callback has expired"


class CorruptRamsesError(RamsesError):
    """Base class for exceptions in this module."""

    pass


class InvalidPacketError(CorruptRamsesError):
    """Raised when the packet is inconsistent."""

    ERR_MSG = "packet is invalid"


class InvalidAddrSetError(InvalidPacketError):
    """Raised when the packet's address set is inconsistent."""

    ERR_MSG = "addresses are invalid"


class InvalidPayloadError(InvalidPacketError):
    """Raised when the packet's payload is inconsistent."""

    ERR_MSG = "payload is invalid"


class CorruptStateError(CorruptRamsesError):
    """Raised when the system state (usu. schema) is inconsistent."""

    ERR_MSG = "schema is inconsistent"
    ERR_TIP = "(try restarting the client library)"


class ForeignGatewayError(RamsesError):
    """Raised when a foreign gateway is detected.

    These devices may not be gateways (set a class), or belong to a neighbout (exclude
    via block_list/known_list), or should be allowed (known_list).
    """

    ERR_MSG = "multiple HGI80-compatible gateways"
    ERR_TIP = " (consider enforcing a known_list)"

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - exceptions."""
from __future__ import annotations


class EvohomeError(Exception):
    """Base class for exceptions in this module."""

    pass


class ExpiredCallbackError(EvohomeError):
    """Raised when the callback has expired."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.message = args[0] if args else None

    def __str__(self) -> str:
        err_msg = "The callback has expired"
        err_tip = "(no hint)"
        if self.message:
            return f"{err_msg}: {self.message} {err_tip}"
        return f"{err_msg} {err_tip}"


class CorruptEvohomeError(EvohomeError):
    """Base class for exceptions in this module."""

    pass


class InvalidPacketError(CorruptEvohomeError):
    """Raised when the packet is inconsistent."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.message = args[0] if args else None

    def __str__(self) -> str:
        err_msg = "Corrupt packet"
        err_tip = ""
        if self.message:
            return f"{err_msg}: {self.message}{err_tip}"
        return f"{err_msg} {err_tip}"


class InvalidAddrSetError(InvalidPacketError):
    """Raised when the packet's address set is inconsistent."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.message = args[0] if args else None

    def __str__(self) -> str:
        err_msg = "Corrupt addresses"
        err_tip = ""
        if self.message:
            return f"{err_msg}: {self.message}{err_tip}"
        return f"{err_msg} {err_tip}"


class InvalidPayloadError(InvalidPacketError):
    """Raised when the packet's payload is inconsistent."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.message = args[0] if args else None

    def __str__(self) -> str:
        err_msg = "Corrupt payload"
        err_tip = ""
        if self.message:
            return f"{err_msg}: {self.message}{err_tip}"
        return f"{err_msg} {err_tip}"


class CorruptStateError(CorruptEvohomeError):
    """Raised when the system state (usu. schema) is inconsistent."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.message = args[0] if args else None

    def __str__(self) -> str:
        err_msg = "Inconsistent schema"
        err_tip = "(try restarting the client library)"
        if self.message:
            return f"{err_msg}: {self.message}{err_tip}"
        return f"{err_msg} {err_tip}"


class ForeignGatewayError(EvohomeError):
    """Raised when a foreign gateway is detected.

    These devices may not be gateways (set a class), or belong to a neighbout (exclude
    via block_list/known_list), or should be allowed (known_list).
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.message = args[0] if args else None

    def __str__(self) -> str:
        err_msg = "There is more than one HGI80-compatible gateway"
        err_tip = " (consider enforcing a known_list)"
        if self.message:
            return f"{err_msg}: {self.message}{err_tip}"
        return f"{err_msg} {err_tip}"

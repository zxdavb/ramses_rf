#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome RF - """


class EvohomeError(Exception):
    """Base class for exceptions in this module."""

    pass


class ExpiredCallbackError(EvohomeError):
    """Raised when the callback has expired."""

    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)
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


class CorruptPacketError(CorruptEvohomeError):
    """Raised when the payload is inconsistent."""

    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)
        self.message = args[0] if args else None

    def __str__(self) -> str:
        err_msg = "Corrupt packet"
        err_tip = " (will be ignored)"
        if self.message:
            return f"{err_msg}: {self.message}{err_tip}"
        return f"{err_msg} {err_tip}"


class CorruptAddrSetError(CorruptPacketError):
    """Raised when the payload is inconsistent."""

    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)
        self.message = args[0] if args else None

    def __str__(self) -> str:
        err_msg = "Corrupt addresses"
        err_tip = " (will be ignored)"
        if self.message:
            return f"{err_msg}: {self.message}{err_tip}"
        return f"{err_msg} {err_tip}"


class CorruptPayloadError(CorruptPacketError):
    """Raised when the payload is inconsistent."""

    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)
        self.message = args[0] if args else None

    def __str__(self) -> str:
        err_msg = "Corrupt payload"
        err_tip = " (will be ignored)"
        if self.message:
            return f"{err_msg}: {self.message}{err_tip}"
        return f"{err_msg} {err_tip}"


class CorruptStateError(CorruptEvohomeError):
    """Raised when the system state is inconsistent."""

    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)
        self.message = args[0] if args else None

    def __str__(self) -> str:
        err_msg = "Inconsistent state"
        err_tip = " (try restarting the client library)"
        if self.message:
            return f"{err_msg}: {self.message}{err_tip}"
        return f"{err_msg} {err_tip}"


class MultipleControllerError(CorruptEvohomeError):
    """Raised when there is more than one controller."""

    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)
        self.message = args[0] if args else None

    def __str__(self) -> str:
        err_msg = "There is more than one Evohome controller"
        err_tip = " (consider using an allow_list)"
        if self.message:
            return f"{err_msg}: {self.message}{err_tip}"
        return f"{err_msg} {err_tip}"

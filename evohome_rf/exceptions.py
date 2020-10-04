#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome serial."""


class Error(Exception):
    """Base class for exceptions in this module."""

    pass


class CorruptPayloadError(Error):
    """Raised when the payload is inconsistent."""

    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)
        self.message = args[0] if args else None

    def __str__(self) -> str:
        err_msg = "The payload is inconsistent"
        err_tip = "(check any RQ)"
        if self.message:
            return f"{err_msg}: {self.message} {err_tip}"
        return f"{err_msg} {err_tip}"


class CorruptStateError(Error):
    """Raised when the system state is inconsistent."""

    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)
        self.message = args[0] if args else None

    def __str__(self) -> str:
        err_msg = "The system state is inconsistent"
        err_tip = "(try restarting the client library)"
        if self.message:
            return f"{err_msg}: {self.message} {err_tip}"
        return f"{err_msg} {err_tip}"


class MultipleControllerError(Error):
    """Raised when there is more than one controller."""

    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)
        self.message = args[0] if args else None

    def __str__(self) -> str:
        err_msg = "There is more than one Evohome controller"
        err_tip = "(use an exclude/include list to prevent this error)"
        if self.message:
            return f"{err_msg}: {self.message} {err_tip}"
        return f"{err_msg} {err_tip}"

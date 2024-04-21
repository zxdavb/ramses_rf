#!/usr/bin/env python3
"""RAMSES RF - exceptions within the packet/protocol/transport layer."""

from __future__ import annotations


class _RamsesBaseException(Exception):
    """Base class for all ramses_tx exceptions."""

    pass


class RamsesException(_RamsesBaseException):
    """Base class for all ramses_tx exceptions."""

    HINT: None | str = None

    def __init__(self, *args: object):
        super().__init__(*args)
        self.message: str | None = args[0] if args else None  # type: ignore[assignment]

    def __str__(self) -> str:
        if self.message and self.HINT:
            return f"{self.message} (hint: {self.HINT})"
        if self.message:
            return self.message
        if self.HINT:
            return f"Hint: {self.HINT}"
        return ""


class _RamsesLowerError(RamsesException):
    """A failure in the lower layer (parser, protocol, transport, serial)."""


########################################################################################
# Errors at/below the protocol/transport layer, incl. packet processing


class ProtocolError(_RamsesLowerError):
    """An error occurred when sending, receiving or exchanging packets."""


class ProtocolFsmError(ProtocolError):
    """The protocol FSM was/became inconsistent (this shouldn't happen)."""


class ProtocolSendFailed(ProtocolFsmError):
    """The Command failed to elicit an echo or (if any) the expected response."""


class TransportError(ProtocolError):  # derived from ProtocolBaseError
    """An error when sending or receiving frames (bytes)."""


class TransportSerialError(TransportError):
    """The transport's serial port has thrown an error."""


class TransportSourceInvalid(TransportError):
    """The source of packets (frames) is not valid type/configuration."""


########################################################################################
# Errors at/below the protocol/transport layer, incl. packet processing


class ParserBaseError(_RamsesLowerError):
    """The packet is corrupt/not internally consistent, or cannot be parsed."""


class PacketInvalid(ParserBaseError):
    """The packet is corrupt/not internally consistent."""


class PacketAddrSetInvalid(PacketInvalid):
    """The packet's address set is inconsistent."""


class PacketPayloadInvalid(PacketInvalid):
    """The packet's payload is inconsistent."""


# Errors at/below the protocol/transport layer, incl. packet processing


class ParserError(ParserBaseError):
    """The packet cannot be parsed without error."""


class CommandInvalid(ParserError):
    """The command is corrupt/not internally consistent."""

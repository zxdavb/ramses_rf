#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - The evohome-compatible system."""
from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, TypeVar

from ramses_tx import Address, Message

from ..const import __dev_mode__
from ..entity_base import class_by_attr

# skipcq: PY-W2000
from ..const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    F9,
    FA,
    FC,
    FF,
)

# skipcq: PY-W2000
from ..const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    Code,
)

if TYPE_CHECKING:  # mypy TypeVars and similar (e.g. Index, Verb)
    # skipcq: PY-W2000
    from ..const import Index, Verb  # noqa: F401, pylint: disable=unused-import


DEV_MODE = __dev_mode__

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


_HvacSystemT = TypeVar("_HvacSystemT", bound="HvacSystem")


FAN_KLASS = SimpleNamespace(
    HVC="HVAC",  # Generic
)


class HvacSystem:
    """The Controller class."""

    _SLUG: str = FAN_KLASS.HVC

    def __init__(self, ctl, **kwargs) -> None:
        super().__init__(ctl, **kwargs)

        self._heat_demands: dict[str, Any] = {}
        self._relay_demands: dict[str, Any] = {}
        self._relay_failsafes: dict[str, Any] = {}


SYS_CLASS_BY_SLUG = class_by_attr(__name__, "_SLUG")


def TODO_system_factory(fan, *, msg: Message = None, **schema) -> _HvacSystemT:
    """Return the system class for a given controller/schema (defaults to evohome)."""

    def best_tcs_class(
        fan_addr: Address,
        *,
        msg: Message = None,
        eavesdrop: bool = False,
        **schema,
    ) -> type[_HvacSystemT]:
        """Return the system class for a given CTL/schema (defaults to evohome)."""

        _LOGGER.debug(
            f"Using a generic HVAC class for: {fan_addr} ({HvacSystem._SLUG})"
        )
        return HvacSystem

    return best_tcs_class(
        fan.addr,
        msg=msg,
        eavesdrop=fan._gwy.config.enable_eavesdrop,
        **schema,
    ).create_from_schema(fan, **schema)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the Command.put_*, Command.set_* APIs.
"""

from ramses_rf import RQ
from ramses_rf.protocol.const import _0418
from ramses_rf.protocol.ramses import (
    CODE_IDX_COMPLEX,
    CODE_IDX_NONE,
    CODE_IDX_SIMPLE,
    CODES_SCHEMA,
    RQ_NO_PAYLOAD,
)


def _test_codes_idx_mutex(mutex_list, other_list):
    codes = sorted(c for c in mutex_list if c in other_list)
    assert codes == []


def test_codes_idx_mutex():
    """Every code should be in one of the three CODE_IDX_* constants."""

    codes_idx_all = CODE_IDX_COMPLEX + CODE_IDX_NONE + CODE_IDX_SIMPLE
    _test_codes_idx_mutex(
        [c for c in CODES_SCHEMA if c not in codes_idx_all], CODES_SCHEMA
    )


def test_codes_idx_complex_mutex():
    """The three CODE_IDX_* constants should be mutally exclusive."""

    _test_codes_idx_mutex(CODE_IDX_COMPLEX, CODE_IDX_NONE + CODE_IDX_SIMPLE)


def test_codes_idx_none_mutex():
    """The three CODE_IDX_* constants should be mutally exclusive."""

    _test_codes_idx_mutex(CODE_IDX_NONE, CODE_IDX_SIMPLE + CODE_IDX_COMPLEX)


def test_codes_idx_simple_mutex():
    """The three CODE_IDX_* constants should be mutally exclusive."""

    _test_codes_idx_mutex(CODE_IDX_SIMPLE, CODE_IDX_NONE + CODE_IDX_COMPLEX)


def _test_codes_mutex():
    _test_codes_idx_mutex(RQ_IDX_ONLY, CODE_IDX_NONE)


RQ_IDX_NONE = [k for k, v in CODES_SCHEMA.items() if v.get(RQ, "")[:3] == "^00"]
RQ_IDX_ONLY = [
    k
    for k, v in CODES_SCHEMA.items()
    if k not in RQ_NO_PAYLOAD
    and RQ in v
    and (v[RQ] in (r"^0[0-9A-F]00$", r"^0[0-9A-F](00)?$"))
]
RQ_IDX_ONLY.extend((_0418,))
RQ_IDX_UNKNOWN = [
    k
    for k, v in CODES_SCHEMA.items()
    if k not in RQ_NO_PAYLOAD + RQ_IDX_ONLY and RQ in v
]
# RQ_UNKNOWN.extend()

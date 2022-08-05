#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the RAMSES II schema.
"""

from ramses_rf import RQ
from ramses_rf.device.heat import HEAT_CLASS_BY_SLUG
from ramses_rf.device.hvac import HVAC_CLASS_BY_SLUG
from ramses_rf.protocol.const import DEV_TYPE, Code
from ramses_rf.protocol.ramses import (
    _DEV_KLASSES_HEAT,
    _DEV_KLASSES_HVAC,
    _HVAC_VC_PAIR_BY_CLASS,
    CODE_IDX_COMPLEX,
    CODE_IDX_NONE,
    CODE_IDX_SIMPLE,
    CODES_SCHEMA,
    HVAC_KLASS_BY_VC_PAIR,
    RQ_NO_PAYLOAD,
)


def test_code_count():  # TODO make ==, not >=
    assert len(Code) >= len(CODES_SCHEMA)
    assert not [c for c in CODES_SCHEMA if c not in Code]


def test_verb_code_pairs():
    """Verb/code pairs are used to detect HVAC device classes: they should be unique."""

    assert len(HVAC_KLASS_BY_VC_PAIR) == (
        sum(len(v) for v in _HVAC_VC_PAIR_BY_CLASS.values())
    ), "Coding error: There is a duplicate verb/code pair"


def test_device_heat_slugs():
    """Every device slug should have an entry in it domain's _DEV_KLASSES_*."""

    assert not [s for s in _DEV_KLASSES_HEAT if s not in HEAT_CLASS_BY_SLUG]
    assert not [
        s
        for s in HEAT_CLASS_BY_SLUG
        if s not in _DEV_KLASSES_HEAT and s != DEV_TYPE.HEA
    ]


def test_device_hvac_slugs():
    """Every device slug should have an entry in it domain's _DEV_KLASSES_*."""

    assert not [s for s in _DEV_KLASSES_HVAC if s not in HVAC_CLASS_BY_SLUG]
    assert not [
        s
        for s in HVAC_CLASS_BY_SLUG
        if s not in _DEV_KLASSES_HVAC and s != DEV_TYPE.HVC
    ]


def assert_codes_idx_mutex(mutex_list, other_list):
    codes = sorted(c for c in mutex_list if c in other_list)
    assert codes == []


def test_codes_idx_mutex():
    """Every code should be in one of the three CODE_IDX_* constants."""

    codes_idx_all = CODE_IDX_COMPLEX + CODE_IDX_NONE + CODE_IDX_SIMPLE
    assert_codes_idx_mutex(
        [c for c in CODES_SCHEMA if c not in codes_idx_all], CODES_SCHEMA
    )


def test_codes_idx_complex_mutex():
    """The three CODE_IDX_* constants should be mutally exclusive."""

    assert_codes_idx_mutex(CODE_IDX_COMPLEX, CODE_IDX_NONE + CODE_IDX_SIMPLE)


def test_codes_idx_none_mutex():
    """The three CODE_IDX_* constants should be mutally exclusive."""

    assert_codes_idx_mutex(CODE_IDX_NONE, CODE_IDX_SIMPLE + CODE_IDX_COMPLEX)


def test_codes_idx_simple_mutex():
    """The three CODE_IDX_* constants should be mutally exclusive."""

    assert_codes_idx_mutex(CODE_IDX_SIMPLE, CODE_IDX_NONE + CODE_IDX_COMPLEX)


def _test_codes_mutex():
    assert_codes_idx_mutex(RQ_IDX_ONLY, CODE_IDX_NONE)


RQ_IDX_NONE = [k for k, v in CODES_SCHEMA.items() if v.get(RQ, "")[:3] == "^00"]
RQ_IDX_ONLY = [
    k
    for k, v in CODES_SCHEMA.items()
    if k not in RQ_NO_PAYLOAD
    and RQ in v
    and (v[RQ] in (r"^0[0-9A-F]00$", r"^0[0-9A-F](00)?$"))
]
RQ_IDX_ONLY.extend((Code._0418,))
RQ_IDX_UNKNOWN = [
    k
    for k, v in CODES_SCHEMA.items()
    if k not in RQ_NO_PAYLOAD + RQ_IDX_ONLY and RQ in v
]
# RQ_UNKNOWN.extend()

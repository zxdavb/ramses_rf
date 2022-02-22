#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the Command.put_*, Command.set_* APIs.
"""

import unittest

from ramses_rf import RQ
from ramses_rf.protocol.const import _0418
from ramses_rf.protocol.ramses import (
    CODE_IDX_COMPLEX,
    CODE_IDX_NONE,
    CODE_IDX_SIMPLE,
    CODES_SCHEMA,
    RQ_NO_PAYLOAD,
)


class TestIdxMutexBase(unittest.IsolatedAsyncioTestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.maxDiff = None

    def _test_codes_idx_mutex(self, mutex_list, other_list):
        codes = sorted(c for c in mutex_list if c in other_list)
        self.assertEqual(codes, [])


class TestCodeIdxMutex(TestIdxMutexBase):
    def test_codes_idx_mutex(self):
        """Every code should be in one of the three CODE_IDX_* constants."""

        codes_idx_all = CODE_IDX_COMPLEX + CODE_IDX_NONE + CODE_IDX_SIMPLE
        self._test_codes_idx_mutex(
            [c for c in CODES_SCHEMA if c not in codes_idx_all], CODES_SCHEMA
        )

    def test_codes_idx_complex_mutex(self):
        """The three CODE_IDX_* constants should be mutally exclusive."""

        self._test_codes_idx_mutex(CODE_IDX_COMPLEX, CODE_IDX_NONE + CODE_IDX_SIMPLE)

    def test_codes_idx_none_mutex(self):
        """The three CODE_IDX_* constants should be mutally exclusive."""

        self._test_codes_idx_mutex(CODE_IDX_NONE, CODE_IDX_SIMPLE + CODE_IDX_COMPLEX)

    def test_codes_idx_simple_mutex(self):
        """The three CODE_IDX_* constants should be mutally exclusive."""

        self._test_codes_idx_mutex(CODE_IDX_SIMPLE, CODE_IDX_NONE + CODE_IDX_COMPLEX)


class TestRqIdxMutex(TestIdxMutexBase):
    def _test_codes_mutex(self):
        self._test_codes_idx_mutex(RQ_IDX_ONLY, CODE_IDX_NONE)


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

if __name__ == "__main__":
    unittest.main()

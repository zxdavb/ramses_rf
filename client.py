#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""A CLI for the ramses_rf library.

ramses_rf is used to parse/process Honeywell's RAMSES-II packets.
"""
from __future__ import annotations

try:
    from ramses_cli.client import main

except ModuleNotFoundError:
    import os
    import sys

    sys.path.append(f"{os.path.dirname(__file__)}/src")

    from ramses_cli.client import main

if __name__ == "__main__":
    main()

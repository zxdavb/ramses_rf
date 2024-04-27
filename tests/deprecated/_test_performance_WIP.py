#!/usr/bin/env python3
"""RAMSES RF - PHelper functions."""

import sys
import time
from datetime import datetime as dt

from ramses_tx.helpers import dt_now, timestamp


def _precision_v_cost():
    import math

    #
    LOOPS = 10**6
    #
    print("time.time_ns(): %s" % time.time_ns())
    print("time.time():    %s\r\n" % time.time())
    #
    starts = time.time_ns()
    min_dt = [abs(time.time_ns() - time.time_ns()) for _ in range(LOOPS)]
    min_dt = min(filter(bool, min_dt))
    print("min delta   time_ns(): %s ns" % min_dt)
    print("duration    time_ns(): %s ns\r\n" % (time.time_ns() - starts))
    #
    starts = time.time_ns()
    min_dt = [abs(time.time() - time.time()) for _ in range(LOOPS)]
    min_dt = min(filter(bool, min_dt))
    print("min delta      time(): %s ns" % math.ceil(min_dt * 1e9))
    print("duration       time(): %s ns\r\n" % (time.time_ns() - starts))
    #
    starts = time.time_ns()
    min_dt = [abs(timestamp() - timestamp()) for _ in range(LOOPS)]
    min_dt = min(filter(bool, min_dt))
    print("min delta timestamp(): %s ns" % math.ceil(min_dt * 1e9))
    print("duration  timestamp(): %s ns\r\n" % (time.time_ns() - starts))
    #
    LOOPS = 10**4
    #
    starts = time.time_ns()
    min_td = [abs(dt.now() - dt.now()) for _ in range(LOOPS)]
    min_td = min(filter(bool, min_td))
    print("min delta dt.now(): %s ns" % math.ceil(min_dt * 1e9))
    print("duration  dt.now(): %s ns\r\n" % (time.time_ns() - starts))
    #
    starts = time.time_ns()
    min_td = [abs(dt_now() - dt_now()) for _ in range(LOOPS)]
    min_td = min(filter(bool, min_td))
    print("min delta dt_now(): %s ns" % math.ceil(min_dt * 1e9))
    print("duration  dt_now(): %s ns\r\n" % (time.time_ns() - starts))
    #
    starts = time.time_ns()
    min_td = [
        abs(
            (dt_now if sys.platform == "win32" else dt.now)()
            - (dt_now if sys.platform == "win32" else dt.now)()
        )
        for _ in range(LOOPS)
    ]
    min_td = min(filter(bool, min_td))
    print("min delta dt_now(): %s ns" % math.ceil(min_dt * 1e9))
    print("duration  dt_now(): %s ns\r\n" % (time.time_ns() - starts))
    #
    dt_nov = dt_now if sys.platform == "win32" else dt.now
    starts = time.time_ns()
    min_td = [abs(dt_nov() - dt_nov()) for _ in range(LOOPS)]
    min_td = min(filter(bool, min_td))
    print("min delta dt_now(): %s ns" % math.ceil(min_dt * 1e9))
    print("duration  dt_now(): %s ns\r\n" % (time.time_ns() - starts))

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
import argparse
from time import sleep

parser = argparse.ArgumentParser(description="Echo a file slowly")
parser.add_argument("-i", "--input-file", type=argparse.FileType("r"), default="-")
parser.add_argument("-d", "--delay-in-ms", type=int, default="100")
args = parser.parse_args()

for line in args.input_file:
    if "RQ" in line:
        continue
    print(line.rstrip()[27:])
    sleep(args.delay_in_ms / 1000.0)

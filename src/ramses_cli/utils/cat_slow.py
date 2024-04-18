#!/usr/bin/env python3
import argparse
from time import sleep

# python utils/cat_slow.py -i packet.log | tee /dev/pts/0
# cat packet.log | cut -d ' ' -f 2- | unix2dos | pv --quiet --line-mode --rate-limit 1 | tee /dev/pts/3

parser = argparse.ArgumentParser(description="Echo a file slowly")
parser.add_argument("-i", "--input-file", type=argparse.FileType("r"), default="-")
parser.add_argument("-d", "--delay-in-ms", type=int, default="100")
args = parser.parse_args()

for line in args.input_file:
    if "RQ" in line:
        continue
    print(line.rstrip()[27:])
    sleep(args.delay_in_ms / 1000.0)

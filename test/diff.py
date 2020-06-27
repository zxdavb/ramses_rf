"""Evohome RF log diff utility."""
import argparse
from collections import deque, namedtuple
from datetime import datetime as dt, timedelta
import os
import re

DEBUG_ADDR = "0.0.0.0"
DEBUG_PORT = 5678

RSSI_REGEXP = re.compile(r"(-{3}|\d{3})")
PKT_LINE = namedtuple("Packet", ["dtm", "rssi", "packet", "line"])

DATETIME_FORMAT = "YYYY-MM-DD HH:MM:SS.ssssss"
DATETIME_LENGTH = len(DATETIME_FORMAT)

# how far to look ahead for a matching packet - higher values will slow down
DEFAULT_LOOKAHEAD_SECS = 1  # may need to increase this if logs from diff systems
DEFAULT_LOOKAHEAD_PKTS = 5  # <3 has increased potential for false positives

# packets to print before/after a stall
DEFAULT_PKTS_BEFORE = 2
DEFAULT_PKTS_AFTER = 2

# exclude a stall unless they exceed the following
STALL_LIMIT_SECS = 30  # 30 is a useful minimum, max should be sync_cycle time, ~180
STALL_LIMIT_PKTS = 10  # <7 has increased potential for false positives

if False:
    BOTH, LEFT, RITE = "===", "<<<", ">>>"
else:
    BOTH, LEFT, RITE = " = ", "<  ", "  >"


def _parse_args():
    def extant_file(value):
        """Confirm value is the name of a existant file."""
        if not os.path.exists(value):
            raise argparse.ArgumentTypeError(f"{value} does not exist")
        return value

    def natural_int(value):
        """Confirm value is a positive integer."""
        i_value = int(value)
        if i_value < 1:  # or value != i_value:
            raise argparse.ArgumentTypeError(f"{value} is not a positive integer")
        return i_value

    def pos_int(value):
        """Confirm value is a non-negative integer."""
        i_value = int(value)
        if i_value < 0:  # or value is not i_value:
            raise argparse.ArgumentTypeError(f"{value} is not a non-negative integer")
        return i_value

    def dt_timedelta(value):
        """Confirm value is a positive timedelta (in seconds)."""
        f_value = float(value)
        if f_value < 0:  # or value is not f_value:
            raise argparse.ArgumentTypeError(f"{value} is not a non-negative float")
        return timedelta(seconds=f_value)

    parser = argparse.ArgumentParser()

    group = parser.add_argument_group(title="File names")
    group.add_argument(
        "hgi80_log", type=extant_file, help=f"({LEFT}) reference packet log"
    )
    group.add_argument(
        "evofw_log", type=extant_file, help=f"({RITE}) packet log to test"
    )

    group = parser.add_argument_group(title="Context control")
    group.add_argument(
        "-B",
        "--before",
        default=DEFAULT_PKTS_BEFORE,
        type=pos_int,
        help="matching lines to print before each block",
    )
    group.add_argument(
        "-A",
        "--after",
        default=DEFAULT_PKTS_AFTER,
        type=pos_int,
        help="matching lines to print after each block",
    )
    group.add_argument(
        "-s",
        "--seconds",
        default=timedelta(seconds=DEFAULT_LOOKAHEAD_SECS),
        type=dt_timedelta,
        help="minimum lookahead in seconds (float)",
    )
    group.add_argument(
        "-p",
        "--packets",
        default=DEFAULT_LOOKAHEAD_PKTS,
        type=natural_int,
        help="minimum lookahead in packets (int), recommended >=3",
    )

    group = parser.add_argument_group(title="Stall detection")
    group.add_argument(
        "-D",
        "--pause-duration",
        default=timedelta(seconds=STALL_LIMIT_SECS),
        type=dt_timedelta,
        help="minimum duration of pauses in seconds (float)",
    )
    group.add_argument(
        "-L",
        "--pause-length",
        default=STALL_LIMIT_PKTS,
        type=natural_int,
        help="minimum length of pauses in packets (int), recommended >=7",
    )

    group = parser.add_argument_group(title="Debug options")
    group.add_argument(
        "-z", "--debug_mode", action="count", default=0, help="1=N/A, 2=enable, 3=wait"
    )

    return parser.parse_args()


def main():
    """Main loop."""
    args = _parse_args()

    if args.debug_mode == 1:
        # print(f"Debugging not enabled, additional logging enabled.")
        pass

    elif args.debug_mode > 1:
        import ptvsd

        print(f"Debugging is enabled, listening on: {DEBUG_ADDR}:{DEBUG_PORT}.")
        ptvsd.enable_attach(address=(DEBUG_ADDR, DEBUG_PORT))

        if args.debug_mode > 2:
            print("Execution paused, waiting for debugger to attach...")
            ptvsd.wait_for_attach()
            print("Debugger is attached, continuing execution.")

    compare(args)


def compare(config) -> dict:

    MICROSECONDS = timedelta(microseconds=1)
    buffer = {
        "packets": deque(),
        "run_length": 0,
        "making_block": False,
        "pause_len": 0,
        "making_pause": False,
    }

    def time_diff(pkt_1, pkt_2) -> float:
        td = (pkt_2.dtm - pkt_1.dtm) / MICROSECONDS
        return 999999 if td > 999999 else max(td, -999999)

    def pkts_match(pkt, window, idx) -> bool:
        matched = pkt.packet == window[idx].packet
        return matched if not matched else time_diff(pkt, window[idx]) < 999999

    def buffer_print(buffer, num_lines):
        for _ in range(num_lines):
            print(buffer["packets"][0])
            buffer["packets"].popleft()

    def parse_line(raw_line: str) -> namedtuple:
        """Parse a line from a packet log into a dtm (detetime), payload (str) tuple.

        Assumes lines have a datetime stamp, e.g.: 'YYYY-MM-DD HH:MM:SS.ssssss'
        """
        line = raw_line.strip()  # if line != raw_line ("" != "/r/n"): # then, at EOF?
        if not line:
            return PKT_LINE(None, None, None, line)

        dtm = dt.fromisoformat(line[:DATETIME_LENGTH])
        pkt = line[DATETIME_LENGTH + 1 :]

        if pkt[:1] in ["#", "*"]:  # or not RSSI_REGEXP.match(pkt[:3]):
            return PKT_LINE(dtm, None, pkt, line)  # a pure diagnostic line
        return PKT_LINE(dtm, pkt[:3], pkt[4:], line)

    def slide_pkt_window(fh, pkt_window, until=None, min_length=config.packets):
        """Populate the window with packet log lines until at EOF.

        Assumes no blank lines in the middle of the file (thus no empty elements).
        """
        assert until is not None or min_length is not None

        if len(pkt_window) == 0:
            pkt_window.append(parse_line(fh.readline()))
        while pkt_window[-1].dtm is not None and len(pkt_window) < min_length:
            pkt_window.append(parse_line(fh.readline()))
        if until is not None:
            while pkt_window[-1].dtm is not None and pkt_window[-1].dtm < until:
                pkt_window.append(parse_line(fh.readline()))
        if pkt_window[-1].dtm is None:
            pkt_window.pop()

    def buffer_append(buffer, summary, diff, pkt, pkt2=None):
        """Populate the buffer, maintain counters and print any lines as able.

        Also includes code to track pauses.
        """

        def pause_began(buffer, summary, pkt):
            # idx = min(config.before, len(buffer["packets"]) - 1)
            # print("*** BEGAN:", buffer["packets"][idx])
            summary["pause_began"] = pkt

        def pause_ended(buffer, summary, pkt=None):
            # print("*** ENDED:", buffer["packets"][0])
            # duration = (
            #     dt.fromisoformat(buffer["packets"][0][4 : 4 + DATETIME_LENGTH])
            #     - summary["pause_began"].dtm
            # )
            duration = (
                summary["last_pkt_1"].dtm - summary["pause_began"].dtm
            )
            if (
                duration > config.pause_duration
                or buffer["pause_len"] > config.pause_length
            ):
                summary["pauses"].append({summary["pause_began"]: duration})

        td = time_diff(pkt, pkt2) if diff == BOTH else 0
        summary["dt_pos" if td > 0 else "dt_neg"] += td

        buffer["packets"].append(f"{diff} {pkt.dtm} ({td:+7.0f}) {pkt.packet}")
        buffer["run_length"] += 1

        if diff == LEFT:
            if not buffer["making_pause"]:
                buffer.update({"pause_len": 0, "making_pause": True})
                pause_began(buffer, summary, pkt)
            buffer["pause_len"] += 1

        elif buffer["making_pause"]:
            buffer["making_pause"] = False
            if buffer["pause_len"] > 3:
                pause_ended(buffer, summary)

        if diff in (LEFT, RITE):  # can print/clear the entire buffer
            # if not buffer["making_block"]:  # beginning of a block
            buffer_print(buffer, len(buffer["packets"]))
            buffer.update({"run_length": 0, "making_block": True})
            return

        if buffer["making_block"]:
            if buffer["run_length"] > config.before + config.after:  # end of a block
                buffer_print(buffer, config.after)
                buffer.update({"run_length": config.before, "making_block": False})
                buffer["packets"].popleft()  # the first BOTH pkt between AFTER & BEFORE
                print()

        elif buffer["run_length"] > config.before:
            buffer.update({"run_length": config.before, "making_block": False})
            buffer["packets"].popleft()  # an unwanted BOTH pkt before BEFORE

    def buffer_flush(buffer):
        if buffer["making_block"]:
            # block_ended(buffer, summary)

            buffer_print(buffer, min(config.after, buffer["run_length"]))
            print()

    def print_summary(dt_pos, dt_neg, num_pkts, num_1, num_2, warning, pauses, *args):
        num_total = sum([num_pkts, num_1, num_2])
        print(f"Of the {num_total} valid packets:")
        print(
            " - average time delta of matched packets:",
            f"{(dt_pos - dt_neg) / num_pkts:0.0f} "
            f"(+{dt_pos / num_pkts:0.0f}, {dt_neg / num_pkts:0.0f}) nanosecs",
        )
        print(
            " - there were:",
            f"{num_1} ({LEFT.strip()}, {num_1 / num_total * 100:0.2f}%), "
            f"{num_2} ({RITE.strip()}, {num_2 / num_total * 100:0.2f}%) "
            "unmatched packets",
        )

        lst = [v.total_seconds() for d in pauses for k, v in d.items()]
        print(
            f"\r\nOf the {len(lst)} pauses >{config.pause_length} packets "
            f"or >{config.pause_duration.total_seconds():0.2f} secs duration:"
        )
        if len(lst):
            print(
                f" - average duration: {sum(lst) / len(lst):.0f} secs; "
                f"maximum: {max(lst):.0f} secs"
            )
        else:
            print(" - average duration: 0 secs; maximum: 0 secs")

        # print()
        # [print(k.line) for d in pauses for k, v in d.items()]

        if warning is True:
            print("\r\nWARNING: The reference packet log is not from a HGI80.")

    SUMMARY_KEYS = ["dt_pos", "dt_neg", "num_pkts", "num_1", "num_2", "warning"]
    summary = {k: 0 for k in SUMMARY_KEYS}
    summary.update({"pauses": [], "last_pkt_1": None})

    pkt_2_window = deque()

    with open(config.hgi80_log) as fh_1, open(config.evofw_log) as fh_2:
        for raw_line in fh_1:
            pkt_1 = parse_line(raw_line)
            if "*" in pkt_1.packet or "#" in pkt_1.packet:
                summary["warning"] = True  # file_1 is evofw3, and not hgi80!

            slide_pkt_window(fh_2, pkt_2_window, until=pkt_1.dtm + config.seconds)

            for idx, pkt_2 in enumerate(list(pkt_2_window)):
                matched = pkts_match(pkt_1, pkt_2_window, idx)
                if matched:
                    for _ in range(idx):  # all pkts before the match
                        buffer_append(buffer, summary, RITE, pkt_2_window[0])
                        if not pkt_2_window[0].packet[:1] == "#":
                            summary["num_2"] += 1
                        pkt_2_window.popleft()

                    buffer_append(buffer, summary, BOTH, pkt_1, pkt_2)
                    summary["num_pkts"] += 1
                    pkt_2_window.popleft()
                    break

            else:
                buffer_append(buffer, summary, LEFT, pkt_1)
                summary["num_1"] += 1
                summary["last_pkt_1"] = pkt_1

        buffer_flush(buffer)

    print_summary(*list(summary.values()))


if __name__ == "__main__":
    main()

"""Evohome RF log diff utility."""
import argparse
from collections import deque, namedtuple
from datetime import datetime as dt, timedelta
import os
import re

DEBUG_ADDR = "0.0.0.0"
DEBUG_PORT = 5679

RSSI_REGEXP = re.compile(r"(-{3}|\d{3})")

PKT_LINE1 = namedtuple("Packet", ["dt", "rssi", "packet", "line"])
PKT_LINE = namedtuple("Packet", ["dtm", "rssi", "packet", "line"])


def _parse_args():
    def extant_file(file_name):
        """Check that value is the name of a existant file."""
        if not os.path.exists(file_name):
            raise argparse.ArgumentTypeError(f"{file_name} does not exist")
        return file_name

    def pos_int(value):
        """Check that value is a positive integer."""
        i_value = int(value)
        if not i_value > 0:
            raise argparse.ArgumentTypeError(f"{value} is not a positive integer")
        return i_value

    def pos_float(value):
        """Check that value is a positive float."""
        f_value = float(value)
        if f_value < 0:
            raise argparse.ArgumentTypeError(f"{value} is not a non-negative float")
        return f_value

    parser = argparse.ArgumentParser()

    group = parser.add_argument_group(title="File names")
    group.add_argument("hgi80_log", type=extant_file, help="(<<<) reference packet log")
    group.add_argument("evofw_log", type=extant_file, help="(>>>) packet log to test")

    group = parser.add_argument_group(title="Context control")
    group.add_argument(
        "-B", "--before", default=2, type=pos_int, help="print lines before the block"
    )
    group.add_argument(
        "-A", "--after", default=2, type=pos_int, help="print lines after the block"
    )
    group.add_argument(
        "-w", "--window", default=0.5, type=pos_float, help="look ahead in secs (float)"
    )
    group.add_argument(
        "-f", "--filter", default="", type=str, help="drop blocks without (e.g.) a '*'"
    )

    group = parser.add_argument_group(title="Debug options")
    group.add_argument(
        "-z", "--debug_mode", action="count", default=0, help="1=log, 2=enable, 3=wait"
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

    print_summary(*list(compare2(args).values()))


def print_summary(dt_diff_pos, dt_diff_neg, count_match, count_1, count_2, warning):
    num_outliers = 0

    print("Of the valid packets:")
    print(
        " - average time delta of matched packets:",
        f"{(dt_diff_pos - dt_diff_neg) / count_match:0.0f} "
        f"(+{dt_diff_pos / count_match:0.0f}, {dt_diff_neg / count_match:0.0f})"
        f" ns, with {num_outliers} outliers",
    )
    num_total = sum([count_match, count_1, count_2])
    print(
        " - there were:",
        f"{num_total + num_outliers:0d} true packets, with "
        f"{count_1} (<<<, {count_1 / num_total * 100:0.2f}%), "
        f"{count_2} (>>>, {count_2 / num_total * 100:0.2f}%) unmatched",
    )
    if warning:
        print("\r\n*** WARNING: The reference packet log is not from a HGI80.")


def compare2(config) -> dict:

    MICROSECONDS = timedelta(microseconds=1)
    buffer = {"packets": deque(), "run_length": 0, "making_block": False}

    def buffer_print(buffer, num_lines):
        for _ in range(num_lines):
            print(buffer["packets"][0])
            buffer["packets"].popleft()

    def parse_line(raw_line: str) -> namedtuple:
        """Parse a line from a packet log into a dtm (dt), payload (str) tuple.

        Assumes lines have a datetime stamp: 'YYYY-MM-DD HH:MM:SS.ssssss'
        """
        line = raw_line.strip()
        # if line != raw_line:  # "" != "/r/n": # then, at EOF?
        dtm = dt.fromisoformat(line[:26]) if line != "" else None
        if line[27:30][:1] in ["#", "*"] or not RSSI_REGEXP.match(line[27:30]):
            pkt = PKT_LINE(dtm, None, line[27:], line)  # a pure diagnostic line
        else:
            pkt = PKT_LINE(dtm, line[27:30], line[31:], line)
        return pkt

    def slide_pkt_window(fh, pkt_window, until=None, min_length=0) -> None:
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
        """Populate the buffer."""
        if diff == "===":
            td = (pkt2.dtm - pkt.dtm) / MICROSECONDS
            td = 999999 if td > 999999 else max(td, -999999)

            if td > 0:
                summary["dt_diff_pos"] += td
            else:
                summary["dt_diff_neg"] += td

        else:
            td = 0.0

        buffer["packets"].append(f"{diff} {pkt.dtm} ({td:+7.0f}) {pkt.packet}")
        buffer["run_length"] += 1

        if diff in ["<<<", ">>>"]:
            buffer.update({"run_length": 0, "making_block": True})
            buffer_print(buffer, len(buffer["packets"]))
            return

        if buffer["making_block"]:
            if buffer["run_length"] > config.before + config.after:
                buffer.update({"run_length": config.before, "making_block": False})
                buffer_print(buffer, config.after)
                buffer["packets"].popleft()
                print()

        elif buffer["run_length"] > config.before:
            buffer.update({"run_length": config.before, "making_block": False})
            buffer["packets"].popleft()

    def buffer_flush(buffer):
        if buffer["making_block"]:
            buffer_print(buffer, min(config.after, buffer["run_length"]))

    TIME_WINDOW = timedelta(seconds=config.window)

    pkt_2_window = deque()
    summary = {
        "dt_diff_pos": 0,
        "dt_diff_neg": 0,
        "count_match": 0,
        "count_1": 0,
        "count_2": 0,
        "warning": False
    }

    with open(config.hgi80_log) as fh_1, open(config.evofw_log) as fh_2:
        # slide_pkt_window(fh_2, pkt2_window, num_seconds=TIME_WINDOW)

        for raw_line in fh_1:
            pkt_1 = parse_line(raw_line)
            if "*" in pkt_1.packet or "#" in pkt_1.packet:
                summary["warning"] = True

            slide_pkt_window(fh_2, pkt_2_window, until=pkt_1.dtm + TIME_WINDOW)

            for idx, pkt_2 in enumerate(list(pkt_2_window)):
                matched = pkt_1.packet == pkt_2.packet
                if matched:  # is this the end of a block?
                    # should check the next packet is not a better match

                    for _ in range(idx):  # all pkts before the match
                        buffer_append(buffer, summary, ">>>", pkt_2_window[0])
                        if not pkt_2_window[0].packet[:1] == "#":
                            summary["count_2"] += 1
                        pkt_2_window.popleft()

                    buffer_append(buffer, summary, "===", pkt_1, pkt_2)
                    summary["count_match"] += 1
                    pkt_2_window.popleft()
                    break

            else:  # there was no break
                buffer_append(buffer, summary, "<<<", pkt_1)
                summary["count_1"] += 1

        buffer_flush(buffer)

    return summary


def compare(config) -> None:
    """Main loop."""

    def parse(line: str) -> namedtuple:
        if line[27:30][:1] in ["#", "*"] or not RSSI_REGEXP.match(line[27:30]):
            # a diagnostic line
            pkt = PKT_LINE1(line[:26], None, line[27:], line)
        else:
            pkt = PKT_LINE1(line[:26], line[27:30], line[31:], line)
        return pkt

    def populate_pkt_1_window(until):
        """Extend the window out to the lookahead time."""
        if pkt_1_window == []:
            pkt_1_window.append(parse(fh_1.readline().strip()))
        while pkt_1_window[-1].dt and dt.fromisoformat(pkt_1_window[-1].dt) < until:
            pkt_1_window.append(parse(fh_1.readline().strip()))

    def fifo_pkt_list(pkt_list: list, pkt: dict):
        pkt_list.append(pkt)
        if len(pkt_list) > config.before:
            del pkt_list[0]

    def print_block(pkt_before, block_list):
        if len(pkt_before) == config.before:
            new_block(block_list)
            block_list = [""]
        for pkt in pkt_before:
            block_list.append(f"=== {pkt.line}")
        return [], block_list

    def new_block(_block_list):
        if any(config.filter in x for x in _block_list):
            for log_line in block_list:
                print(log_line)

    TIME_WINDOW = timedelta(seconds=config.window)
    pkt_1_before = []
    pkt_1_window = []
    counter = 0

    block_list = []
    dt_diff_sum = dt_diff_pos = dt_diff_neg = 0
    num_outliers = count_match = count_2 = count_1 = 0
    warning = False

    # this algorithm wont work properly if the files are in the wrong order
    with open(config.hgi80_log) as fh_1, open(config.evofw_log) as fh_2:

        for line in fh_2.readlines():
            pkt_2 = parse(line.strip())
            populate_pkt_1_window(until=dt.fromisoformat(pkt_2.dt) + TIME_WINDOW)

            for idx, pkt_1 in enumerate(pkt_1_window):
                matched = pkt_2.packet == pkt_1.packet

                if pkt_1.packet[:1] == "#" or "*" in pkt_1.packet:
                    warning = True

                if matched:
                    if idx > 0:  # some unmatched pkt_1s
                        counter = config.after
                        pkt_1_before, block_list = print_block(pkt_1_before, block_list)

                        for i in range(idx):  # only in 1st file
                            block_list.append(f"<<< {pkt_1_window[0].line}")
                            del pkt_1_window[0]  # remove unmatched pkt_1s
                            count_1 += 1

                    # what is the average timedelta between matched packets?
                    td = (
                        dt.fromisoformat(pkt_2.dt)
                        - dt.fromisoformat(pkt_1_window[0].dt)
                    ) / timedelta(microseconds=1)

                    # the * 50 to exclude outliers, usu. 2-3 identical pkts, ~1s apart
                    if abs(td) > (dt_diff_sum + abs(td)) / (count_match + 1) * 50:
                        if pkt_1_window[1].packet == pkt_2.packet:
                            t2 = (
                                dt.fromisoformat(pkt_2.dt)
                                - dt.fromisoformat(pkt_1_window[1].dt)
                            ) / timedelta(microseconds=1)

                        if abs(t2) > (dt_diff_sum + abs(t2)) / (count_match + 1) * 50:
                            num_outliers += 1
                            print(f"zzz {pkt_1_window[0].line}")
                            print(f"zzz {pkt_2.line}")

                        else:
                            td = t2

                            block_list.append(f"<<< {pkt_1_window[0].line}")
                            del pkt_1_window[0]  # remove unmatched (outlier) pkt_1s
                            count_1 += 1

                    dt_diff_sum += abs(td)
                    if td > 0:
                        dt_diff_pos += td
                    else:
                        dt_diff_neg += td
                    count_match += 1

                    # del pkt_1_window[0]  # this packet matched!
                    break

            if matched:
                if counter > 0:
                    counter -= 1
                    block_list.append(f"=== {pkt_1_window[0].line}")  # TODO: pkt_1.line
                else:
                    # keep most recent matched two packets for next -B
                    fifo_pkt_list(pkt_1_before, pkt_1_window[0])  # TODO: pkt_1

                del pkt_1_window[0]  # this packet matched!
                # break

            else:  # only in 2nd file
                counter = config.after

                block_list.append(f">>> {pkt_2.line}")
                pkt_1_before, block_list = print_block(pkt_1_before, block_list)
                if not pkt_2.packet.startswith("#") and "*" not in pkt_2.packet:
                    count_2 += 1

    new_block(block_list)

    return dt_diff_pos, dt_diff_neg, count_match, count_1, count_2, warning


if __name__ == "__main__":
    main()

"""Evohome RF log diff utility."""
import argparse
from collections import namedtuple
from datetime import datetime as dt, timedelta
import os
import re

DEBUG_ADDR = "0.0.0.0"
DEBUG_PORT = 5679

RSSI_REGEXP = re.compile(r"(-{3}|\d{3})")

PKT_LINE = namedtuple("Packet", ["dt", "rssi", "packet", "line"])


def _parse_args():
    def extant_file(file_name):
        """Check that value is the name of a existant file."""
        if not os.path.exists(file_name):
            raise argparse.ArgumentTypeError(f"{file_name} does not exist")
        return file_name

    def pos_int(value):
        """Check that value is a not a negative integer."""
        i_value = int(value)
        if i_value < 0:
            raise argparse.ArgumentTypeError(f"{value} is not a non-negative integer")
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
        "-w", "--window", default=0.1, type=pos_float, help="look ahead in secs (float)"
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

    compare(args)


def compare(config) -> None:
    """Main loop."""

    def parse(line: str) -> namedtuple:
        if line[27:30][:1] in ["#", "*"] or not RSSI_REGEXP.match(line[27:30]):
            # a diagnostic line
            pkt = PKT_LINE(line[:26], None, line[27:], line)
        else:
            pkt = PKT_LINE(line[:26], line[27:30], line[31:], line)
        return pkt

    def populate_pkt_1_window(until):
        """Extend the window out to the lookahead time."""
        if pkt_1_window == []:
            pkt_1_window.append(parse(fh_1.readline().strip()))
        while pkt_1_window[-1].dt and dt.fromisoformat(pkt_1_window[-1].dt) < until:
            pkt_1_window.append(parse(fh_1.readline().strip()))

    def fifo_pkt(pkt_before: list, pkt: dict):
        pkt_before.append(pkt)
        if len(pkt_before) > config.before:
            del pkt_before[0]

    def print_block(pkt_before, block_list):
        if len(pkt_before) == config.before:
            end_block(block_list)
            block_list = [""]
        for pkt in pkt_before:
            block_list.append(f"=== {pkt.line}")
        return [], block_list

    def end_block(_block_list):
        if any(config.filter in x for x in _block_list):
            for log_line in block_list:
                print(log_line)

    TIME_WINDOW = timedelta(seconds=config.window)
    pkt_2_before = []
    pkt_1_window = []
    counter = 0

    block_list = []
    dt_diff = dt_diff_p = dt_diff_m = 0
    count_match = num_ignored = count_2 = count_1 = 0

    with open(config.hgi80_log) as fh_1, open(config.evofw_log) as fh_2:

        for line in fh_2.readlines():
            pkt_2 = parse(line.strip())
            populate_pkt_1_window(until=dt.fromisoformat(pkt_2.dt) + TIME_WINDOW)

            for idx, pkt_1 in enumerate(pkt_1_window):
                matched = pkt_2.packet == pkt_1.packet

                if matched:
                    if idx > 0:  # some unmatched pkt_1s
                        counter = config.after
                        pkt_2_before, block_list = print_block(pkt_2_before, block_list)

                        for i in range(idx):  # only in 1st file
                            block_list.append(f">>> {pkt_1_window[0].line}")
                            # this if qualifier shouldn't be required for hgi80_log
                            # if pkt_2.packet[:1] != "#" and "*" not in pkt_2.packet:
                            count_1 += 1
                            del pkt_1_window[0]

                    # what is the average timedelta between matched packets?
                    td = (
                        dt.fromisoformat(pkt_2.dt)
                        - dt.fromisoformat(pkt_1_window[0].dt)
                    ) / timedelta(microseconds=1)

                    # the * 50 is to exclude outliers
                    if abs(td) < (dt_diff + abs(td)) / (count_match + 1) * 50:
                        dt_diff += abs(td)
                        if td > 0:
                            dt_diff_p += td
                        else:
                            dt_diff_m += td
                        count_match += 1
                    else:
                        num_ignored += 1

                    del pkt_1_window[0]  # this packet matched, so no longer needed
                    break

            if matched:
                if counter > 0:
                    counter -= 1
                    block_list.append(f"=== {pkt_2.line}")
                else:
                    fifo_pkt(pkt_2_before, pkt_2)  # keep the prior two packets for -B
            else:  # only in 2nd file
                counter = config.after
                pkt_2_before, block_list = print_block(pkt_2_before, block_list)
                block_list.append(f"<<< {pkt_2.line}")
                if not pkt_2.packet.startswith("#") and "*" not in pkt_2.packet:
                    count_2 += 1

    end_block(block_list)

    print("\r\nOf the valid packets:")
    print(
        " - average time delta of matched packets:",
        f"{dt_diff / count_match:0.0f} "
        f"(+{dt_diff_p / count_match:0.0f}, {dt_diff_m / count_match:0.0f})"
        f" ns, with {num_ignored} outliers",
    )
    num_total = sum([count_match, count_2, count_1])
    print(
        " - there were:",
        f"{num_total + num_ignored:0d} total packets, with "
        f"{count_1} ({count_1 / num_total * 100:0.2f}%), "
        f"{count_2} ({count_2 / num_total * 100:0.2f}%) unmatched",
    )


if __name__ == "__main__":
    main()

"""Evohome RF log diff utility."""
import argparse
import os
import re
from datetime import datetime as dt, timedelta

RSSI_REGEXP = re.compile(r"(-{3}|\d{3})")

DEBUG_ADDR = "172.27.0.138"
DEBUG_PORT = 5679


def _parse_args():
    def extant_file(file_name):
        """Check that value is the name of a existant file."""
        if not os.path.exists(file_name):
            raise argparse.ArgumentTypeError(f"{file_name} does not exist")
        return file_name

    def positive_int(value):
        """Check that value is a positive int."""
        i_value = int(value)
        if i_value <= 0:
            raise argparse.ArgumentTypeError(f"{value} is not a positive int")
        return i_value

    def positive_float(value):
        """Check that value is a positive float."""
        f_value = float(value)
        if f_value <= 0:
            raise argparse.ArgumentTypeError(f"{value} is not a positive float")
        return f_value

    parser = argparse.ArgumentParser()

    group = parser.add_argument_group(title="File names")
    group.add_argument("file_one", type=extant_file, help="left file (<<<), say nanofw")
    group.add_argument("file_two", type=extant_file, help="right file (>>>), say hgi80")

    # Context control:
    #   -B, --before-context=NUM  print NUM lines of leading context
    #   -A, --after-context=NUM   print NUM lines of trailing context
    #   -C, --context=NUM         print NUM lines of output context

    group = parser.add_argument_group(title="Context control")
    group.add_argument(
        "-B", "--before", default=2, type=positive_int, help="lines before the block"
    )
    group.add_argument(
        "-A", "--after", default=2, type=positive_int, help="lines after the block"
    )
    group.add_argument(
        "-w", "--window", default=1, type=positive_float, help="look ahead in seconds"
    )
    group.add_argument(
        "-f",
        "--filter",
        default="*",
        type=str,
        help="drop blocks without this character",
    )

    group = parser.add_argument_group(title="Debug options")
    group.add_argument(
        "-z",
        "--debug_mode",
        action="count",
        default=0,
        help="1=debug logging, 2=enabled, 3=wait for attach",
    )

    return parser.parse_args()


def main():
    """Main loop."""
    args = _parse_args()

    if args.debug_mode == 1:
        # print(f"Debugging is enabled, additional logging enabled.")
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

    def parse(line: str) -> dict:
        line = line.strip()
        if RSSI_REGEXP.match(line[27:30]):  # is not a diagnostic line
            return {"dt": line[:26], "rssi": line[27:30], "pkt": line[31:]}
        return {"dt": line[:26], "rssi": None, "pkt": line[27:]}

    def un_parse(pkt: dict) -> str:
        if pkt["rssi"]:
            return f"{pkt['dt']} {pkt['rssi']} {pkt['pkt']}"
        return f"{pkt['dt']} {pkt['pkt']}"

    def update_list(until):
        if pkt2_list == []:
            pkt2_list.append(parse(fh2.readline()))
        while pkt2_list[-1]["dt"] and dt.fromisoformat(pkt2_list[-1]["dt"]) < until:
            pkt2_list.append(parse(fh2.readline()))

    def fifo_pkt(pkt_before: list, pkt: dict):
        pkt_before.append(pkt)
        if len(pkt_before) > config.before:
            del pkt_before[0]

    def print_before(pkt_before) -> list:
        if len(pkt_before) == config.before:
            print()
        for pkt in pkt_before:
            print(f"=== {un_parse(pkt)}")
        return []

    def print_block(pkt_before, block_list) -> list:
        if len(pkt_before) == config.before:
            end_block(block_list)
            block_list = [""]
        for pkt in pkt_before:
            # print(f"=== {un_parse(pkt)}")
            block_list.append(f"=== {un_parse(pkt)}")
        return [], block_list

    def end_block(_block_list):
        if any(config.filter in x for x in _block_list):
            for log_line in block_list:
                print(log_line)
            pass

    TIME_WINDOW = timedelta(seconds=config.window)
    pkt1_before = []
    pkt2_list = []
    counter = 0

    block_list = []

    with open(config.file_one) as fh1, open(config.file_two) as fh2:

        for line in fh1.readlines():
            pkt1 = parse(line)
            update_list(dt.fromisoformat(pkt1["dt"]) + TIME_WINDOW)

            for idx, pkt2 in enumerate(pkt2_list):
                matched = pkt1["pkt"] == pkt2["pkt"]

                if matched:
                    if idx > 0:  # some unmatched pkt2s
                        counter = config.after
                        # t1_before = print_before(pkt1_before)
                        pkt1_before, block_list = print_block(pkt1_before, block_list)

                        for i in range(idx):
                            # print(f">>> {un_parse(pkt2_list[0])}")  # only in 2nd file
                            block_list.append(
                                f">>> {un_parse(pkt2_list[0])}"
                            )  # only in 2nd file
                            del pkt2_list[0]

                    del pkt2_list[0]  # the matching packet
                    break

            if matched:
                if counter > 0:
                    counter -= 1
                    # print(f"=== {un_parse(pkt1)}")
                    block_list.append(f"=== {un_parse(pkt1)}")
                else:
                    fifo_pkt(pkt1_before, pkt1)
            else:
                counter = config.after
                # t1_before = print_before(pkt1_before)
                pkt1_before, block_list = print_block(pkt1_before, block_list)
                # int(f"<<< {un_parse(pkt1)}")  # only in 1st file
                block_list.append(f"<<< {un_parse(pkt1)}")  # only in 1st file
                pass

    end_block(block_list)


if __name__ == "__main__":  # called from CLI?
    main()

#!/usr/bin/env python3
#
"""RAMSES RF - Test the Faultlog functions."""

from ramses_rf import Message, Packet
from ramses_rf.system.faultlog_new import FaultLog, FaultLogEntry
from ramses_tx.address import HGI_DEVICE_ID
from ramses_tx.const import SZ_LOG_ENTRY, Code
from ramses_tx.schemas import DeviceIdT
from tests.helpers import TEST_DIR

WORK_DIR = f"{TEST_DIR}/parsers"


# ### TEST DATA #######################################################################

CTL_ID = "01:145038"
HGI_ID = HGI_DEVICE_ID

TESTS = {}

TESTS["00"] = (
    f" I --- {CTL_ID} {HGI_ID} --:------ 0418 022 000000B0000000000000000000007FFFFF7000000000",  # {'log_idx': '00', 'log_entry': None}
)

TESTS["01"] = (
    f"RP --- {CTL_ID} {HGI_ID} --:------ 0418 022 004000B0040004000000CB955F71FFFFFF70001283B3",  # {'log_idx': '00', 'log_entry': ('21-12-23T11:59:35', 'restore',    'battery_low', 'actuator',     '00', '04:164787', 'B0', '0000', 'FFFF7000')}
    f" I --- {CTL_ID} {HGI_ID} --:------ 0418 022 000000B0000000000000000000007FFFFF7000000000",  # {'log_idx': '00', 'log_entry': None}
)

# ### TESTS ###########################################################################


def _proc_log_line(pkt_line):
    try:
        pkt = Packet.from_file(pkt_line[:26], pkt_line[27:])
    except ValueError:
        return

    msg = Message(pkt)
    if msg.code != Code._0418 or not msg.payload.get(SZ_LOG_ENTRY):
        return

    entry = FaultLogEntry.from_msg(msg)
    assert entry


#######################################################################################


class Controller:
    def __init__(self, ctl_id: DeviceIdT) -> None:
        self.id = ctl_id
        self._gwy = None


def test_faultlog_entries():
    """Test instantiation of faultlog entries."""

    with open(f"{WORK_DIR}/code_0418.log") as f:
        while line := (f.readline()):
            _proc_log_line(line)


def test_faultlog_instantiation():
    """Test instantiation of a faultlog."""

    fault_log = FaultLog(Controller("01:026398"))

    pkt = Packet.from_file(
        "2021-12-23T00:00:00.000000",
        "...  I --- 01:026398 18:000730 --:------ 0418 022 000000B0000000000000000000007FFFFF7000000000",
    )
    msg = Message(pkt)

    fault_log._handle_msg(msg)

    pkt = Packet.from_file(
        "2021-12-23T11:59:35.999999",
        "... RP --- 01:026398 18:000730 --:------ 0418 022 004000B0040004000000CB955F71FFFFFF70001283B3",
    )
    msg = Message(pkt)

    fault_log._handle_msg(msg)
    pass

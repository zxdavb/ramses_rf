#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Mocked devices used for testing.Will provide an appropriate Tx for a given Rx.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime as dt
from datetime import timedelta as td
from queue import Full

from ramses_rf.const import I_, RP, RQ, SZ_ACTUATORS, SZ_ZONES, W_, ZON_ROLE_MAP, Code
from ramses_rf.protocol import InvalidPacketError
from ramses_rf.protocol.command import Command, validate_api_params
from ramses_rf.schemas import SZ_CLASS

from .const import GWY_ID, __dev_mode__

DEV_MODE = __dev_mode__

CTL_ID = "01:000730"
THM_ID = "03:123456"

RUNNING = True


_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class MockCommand(Command):
    @classmethod  # constructor for RP/0005
    @validate_api_params()
    def put_zone_types(
        cls,
        src_id: str,
        dst_id: str,
        zone_type: str,
        zone_mask: tuple,
        *,
        sub_idx: str = "00",
    ):
        """Constructor for RP/0005."""

        zones = f"{sum(b<<i for i, b in enumerate(zone_mask)):04X}"
        payload = f"{sub_idx}{zone_type}{zones[2:]}{zones[:2]}"  # swap order

        return cls._from_attrs(RP, Code._0005, payload, addr0=src_id, addr1=dst_id)

    @classmethod  # constructor for RP/000C
    @validate_api_params(has_zone=True)
    def put_zone_devices(
        cls,
        src_id: str,
        dst_id: str,
        zone_idx: int | str,
        zone_type: str,
        devices: tuple[str],
    ):
        """Constructor for RP/000C."""

        payload = f"{zone_idx}{zone_type}..."

        return cls._from_attrs(RP, Code._000C, payload, addr0=src_id, addr1=dst_id)


class MockDeviceBase:
    """A pseudo-mocked device used for testing."""

    def __init__(self, gwy, device_id) -> None:

        self._gwy = gwy
        self._loop = gwy._loop
        self._ether = gwy.pkt_transport.serial._que

        self.id = device_id
        self._tasks = []

    def rx_frame_as_cmd(self, cmd: Command) -> None:
        """Find/Create an encoded frame (via its hdr), and place in on the ether.

        The rp_header is the sent cmd's rx_header (the header of the packet the gwy is
        waiting for).
        """

        pkt_header = cmd.tx_header

        if response := RESPONSES.get(pkt_header):
            self.tx_frames_as_cmds((self.make_response_pkt(response),))

    def tx_frames_as_cmds(self, cmds: Command | tuple[Command]) -> None:
        """Queue pkts on the ether for the gwy to Rx."""

        cmds = tuple() if cmds is None else cmds  # safety net

        for cmd in cmds if isinstance(cmds, tuple) else (cmds,):
            try:
                self._ether.put_nowait((0, dt.now(), cmd))
            except Full:
                pass

    def make_response_pkt(self, frame: str) -> Command:
        """Convert the response into a command."""

        try:
            return Command(frame)
        except InvalidPacketError as exc:
            raise InvalidPacketError(f"Invalid entry the response table: {exc}")


class MockDeviceCtl(MockDeviceBase):
    """A pseudo-mocked controller used for testing.

    Will periodically Rx a sync_cycle set that will be available via `read()`.
    Will use a reponse table to provide a known Rx for a given Tx sent via `write()`.
    """

    SYNC_CYCLE_INTERVAL = 60  # sync_cycle interval, in seconds
    SYNC_CYCLE_REMANING = 5
    # SYNC_CYCLE_PACKETS = sync_cycle_pkts(DEV_ID, SYNC_CYCLE_INTERVAL)

    def __init__(self, gwy, device_id, *, schema=None) -> None:
        super().__init__(gwy, device_id)

        self._tcs = None  # load_system(gwy, self.id, schema or {})

        self._change_counter = 8
        self.next_cycle = dt.now() + td(seconds=self.SYNC_CYCLE_REMANING)

        self._tasks = [self._loop.create_task(self.tx_frames_of_sync_cycle())]

    def rx_frame_as_cmd(self, cmd: Command) -> None:
        """Find/Create an encoded frame, and place in on the ether."""

        pkt_header = cmd.tx_header

        cmds: Command | tuple[Command] = None  # type: ignore[assignment]

        if pkt_header == f"{Code._1F09}|{RQ}|{CTL_ID}":
            cmds = self.make_response_1f09()

        elif pkt_header[:17] == f"{Code._0005}|{RQ}|{CTL_ID}":
            cmds = self.make_response_0005(pkt_header[18:])

        elif pkt_header[:17] == f"{Code._0006}|{RQ}|{CTL_ID}":
            cmds = self.make_response_0006(pkt_header)

        elif pkt_header[:17] == f"{Code._000C}|{RQ}|{CTL_ID}":
            cmds = self.make_response_000c(pkt_header[18:])

        elif response := RESPONSES.get(pkt_header):
            if pkt_header[:17] == f"{Code._0404}|{W_}|{CTL_ID}":
                self._change_counter += 2
            cmds = self.make_response_pkt(response)

        if cmds:
            self.tx_frames_as_cmds(cmds)

    async def tx_frames_of_sync_cycle(self) -> None:
        """Periodically queue sync_cycle pkts on the ether for the gwy to Rx."""

        while RUNNING:
            await asyncio.sleep((self.next_cycle - dt.now()).total_seconds())

            for cmd in sync_cycle_pkts(CTL_ID, self.SYNC_CYCLE_INTERVAL):
                try:
                    self._ether.put_nowait((1, dt.now(), cmd))
                except Full:
                    pass
                await asyncio.sleep(0.02)

            self.next_cycle = dt.now() + td(seconds=self.SYNC_CYCLE_INTERVAL - 0.06)

    def make_response_1f09(self) -> Command:
        interval = int((self.next_cycle - dt.now()).total_seconds() * 10)
        return Command._from_attrs(
            RP, Code._1F09, f"00{interval:04X}", addr0=self.id, addr1=GWY_ID
        )

    def make_response_0005(self, context: str) -> None | Command:
        def is_type(idx, zone_type):
            return zones.get(f"{idx:02X}", {}).get(SZ_CLASS) == (
                ZON_ROLE_MAP[zone_type]
            )

        zone_type = context[2:]
        if not self._tcs or zone_type not in ZON_ROLE_MAP.HEAT_ZONES:
            return

        zones = self._tcs.schema[SZ_ZONES]
        zone_mask = (is_type(idx, zone_type) for idx in range(0x10))

        return MockCommand._put_zone_types(
            self.id, GWY_ID, zone_type, zone_mask, sub_idx=context[:2]
        )

    def make_response_0006(self, rp_header) -> Command:
        payload = f"0005{self._change_counter:04X}"
        return Command._from_attrs(RP, Code._0006, payload, addr0=self.id, addr1=GWY_ID)

    def make_response_000c(self, context: str) -> None | Command:
        zone_idx, zone_type = context[:2], context[2:]

        if context == "000D":  # 01|DEV_ROLE_MAP.HTG
            pass
        elif context == "010D":  # 00|DEV_ROLE_MAP.HTG
            pass
        elif context == "000E":  # 00|DEV_ROLE_MAP.DHW
            pass
        elif context[2:] not in ZON_ROLE_MAP.HEAT_ZONES:
            return

        zone = self._tcs.zone_by_idx.get(zone_idx) if self._tcs else None
        if not zone:
            return

        if zone_type == (SZ_ACTUATORS, zone.schema[SZ_CLASS]):
            pass
        if zone_type == (SZ_ACTUATORS, zone.schema[SZ_CLASS]):
            pass

        return


class MockDeviceThm(MockDeviceBase):
    """A pseudo-mocked thermostat used for testing."""

    def __init__(self, gwy, device_id, *, schema=None) -> None:
        super().__init__(gwy, device_id)

        self.temperature = None  # TODO: maintain internal state (is needed?)


def sync_cycle_pkts(ctl_id, seconds) -> tuple[Command, Command, Command]:
    """Return a sync_cycle set of packets as from a controller."""
    # .I --- 01:087939 --:------ 01:087939 1F09 003 FF0532
    # .I --- 01:087939 --:------ 01:087939 2309 009 0007D0-010640-0201F4
    # .I --- 01:087939 --:------ 01:087939 30C9 009 0007A0-010634-020656

    cmd_1f09 = Command._from_attrs(
        I_, Code._1F09, f"FF{seconds * 10:04X}", addr0=ctl_id, addr2=ctl_id
    )
    cmd_2309 = Command._from_attrs(
        I_, Code._2309, "0007D00106400201F4", addr0=ctl_id, addr2=ctl_id
    )
    cmd_30c9 = Command._from_attrs(
        I_, Code._30C9, "0007A0010634020656", addr0=ctl_id, addr2=ctl_id
    )

    return cmd_1f09, cmd_2309, cmd_30c9


RESPONSES = {
    f"0006|RQ|{CTL_ID}": f"RP --- {CTL_ID} {GWY_ID} --:------ 0006 004 00050008",
    # RQ schedule for zone 01
    f"0404|RQ|{CTL_ID}|0101": f"RP --- {CTL_ID} {GWY_ID} --:------ 0404 048 0120000829010368816DCCC91183301005D1D93428200E1C7D720C04402C0442640E82000C851701ADD3AFAED1131151",
    f"0404|RQ|{CTL_ID}|0102": f"RP --- {CTL_ID} {GWY_ID} --:------ 0404 048 0120000829020339DEBC8DBE1EFBDB5EDBA8DDB92DBEDFADDAB6671179E4FF4EC153F0143C05CFC033F00C3C03CFC173",
    f"0404|RQ|{CTL_ID}|0103": f"RP --- {CTL_ID} {GWY_ID} --:------ 0404 046 01200008270303F01C3C072FC00BF002BC00AF7CFEB6DEDE46BBB721EE6DBA78095E8297E0E5CF5BF50DA0291B9C",
    # RQ schedule for DHW
    f"0404|RQ|{CTL_ID}|FA01": f"RP --- {CTL_ID} {GWY_ID} --:------ 0404 048 0023000829010468816DCDD10980300C45D1BE24CD9713398093388BF33981A3882842B5BDE9571F178E4ABB4DA5E879",
    f"0404|RQ|{CTL_ID}|FA02": f"RP --- {CTL_ID} {GWY_ID} --:------ 0404 048 00230008290204EDCEF7F3DD761BBBC9C7EEF0B15BEABF13B80257E00A5C812B700D5C03D7C035700D5C03D7C175701D",
    f"0404|RQ|{CTL_ID}|FA03": f"RP --- {CTL_ID} {GWY_ID} --:------ 0404 048 002300082903045C07D7C1757003DC0037C00D7003DC00B7827B6FB38D5DEF56702BB8F7B6766E829BE026B8096E829B",
    f"0404|RQ|{CTL_ID}|FA04": f"RP --- {CTL_ID} {GWY_ID} --:------ 0404 014 002300080704041FF702BAC2188E",
    # W schedule for zone 01
    f"0404| W|{CTL_ID}|0101": f" I --- {CTL_ID} {GWY_ID} --:------ 0404 007 01200008290103",
    f"0404| W|{CTL_ID}|0102": f" I --- {CTL_ID} {GWY_ID} --:------ 0404 007 01200008290203",
    f"0404| W|{CTL_ID}|0103": f" I --- {CTL_ID} {GWY_ID} --:------ 0404 007 01200008280300",
    # W schedule for DHW
    f"0404| W|{CTL_ID}|FA01": f" I --- {CTL_ID} {GWY_ID} --:------ 0404 007 01200008290104",
    f"0404| W|{CTL_ID}|FA02": f" I --- {CTL_ID} {GWY_ID} --:------ 0404 007 01200008290204",
    f"0404| W|{CTL_ID}|FA03": f" I --- {CTL_ID} {GWY_ID} --:------ 0404 007 01200008280304",
    f"0404| W|{CTL_ID}|FA04": f" I --- {CTL_ID} {GWY_ID} --:------ 0404 007 01200008280400",
    #
    f"2309|RQ|{CTL_ID}|00": f"RP --- {CTL_ID} --:------ {GWY_ID} 2309 003 0007D0",
    f"2309|RQ|{CTL_ID}|01": f"RP --- {CTL_ID} --:------ {GWY_ID} 2309 003 010640",
    f"2309|RQ|{CTL_ID}|02": f"RP --- {CTL_ID} --:------ {GWY_ID} 2309 003 0201F4",
    #
    f"30C9|RQ|{CTL_ID}|00": f"RP --- {CTL_ID} --:------ {GWY_ID} 30C9 003 0007A0",
    f"30C9|RQ|{CTL_ID}|01": f"RP --- {CTL_ID} --:------ {GWY_ID} 30C9 003 010634",
    f"30C9|RQ|{CTL_ID}|02": f"RP --- {CTL_ID} --:------ {GWY_ID} 30C9 003 020656",
}  # "pkt_header": "response_pkt"

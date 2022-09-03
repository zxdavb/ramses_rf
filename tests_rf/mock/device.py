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
from typing import Callable

from ramses_rf.const import I_, RP, RQ, SZ_ACTUATORS, SZ_ZONES, W_, ZON_ROLE_MAP, Code
from ramses_rf.protocol import InvalidPacketError
from ramses_rf.protocol.command import Command as CommandBase
from ramses_rf.protocol.command import validate_api_params
from ramses_rf.schemas import SZ_CLASS

from .const import GWY_ID, __dev_mode__

DEV_MODE = __dev_mode__

CTL_ID = "01:888888"
THM_ID = "03:123456"


_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


_DeviceIdT = str
_PktIdxT = str


class Command(CommandBase):
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

        self.id: _DeviceIdT = device_id

        self._is_running: bool = None  # type: ignore[assignment]
        self._tasks: list[asyncio.Task] = []

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


_1F09_CYCLE_DURATION = td(seconds=3 * 60)  # varies between controllers, usu. 3-5 mins
_1F09_CYCLE_PERIOD = 20  # ~number of cycles until 000A is sent instead of 2309/30C9
_1F09_CYCLE_REMAINING = td(seconds=5)

_3150_CYCLE_DURATION = td(seconds=20 * 60)  # fixed at 20 mins
_3150_CYCLE_REMAINING = td(seconds=19 * 60)

DEFAULT_3B00_CYCLE_RATE = 3  # default 3/hr?
DEFAULT_3B00_CYCLE_DURATION = td(seconds=60 * 60 / DEFAULT_3B00_CYCLE_RATE)
_3B00_CYCLE_REMAINING = td(seconds=9 * 60)


class MockDeviceCtl(MockDeviceBase):
    """A pseudo-mocked controller used for testing.

    Will periodically Rx a sync_cycle set that will be available via `read()`.
    Will use a reponse table to provide a known Rx for a given Tx sent via `write()`.
    """

    _1F09_DURATION = _1F09_CYCLE_DURATION  # varies between controllers

    def __init__(
        self, gwy, device_id, *, cycle_rate: int = DEFAULT_3B00_CYCLE_RATE
    ) -> None:
        super().__init__(gwy, device_id)

        self._ref = gwy.get_device(device_id)  # device_factory(gwy, self._addr)
        self._tcs = self._ref.tcs

        self._change_counter: int = 8

        # initial values for the cycles, defer to reduce intial pkts Txs
        dt_now = dt.now()
        self._next_1f09_cycle: dt = dt_now + self._1F09_DURATION * 0.5
        self._next_3150_cycle: dt = dt_now + _3150_CYCLE_DURATION * 0.9
        self._next_3b00_cycle: dt = dt_now  # will defer below

        self._3b00_duration: td = td(seconds=0)  # not normally a valid duration
        self._cycle_rate: int = None  # type: ignore[assignment]
        self.cycle_rate = cycle_rate

        # Finally, 'start' the controller
        self._is_running = True
        self._tasks = [
            self._loop.create_task(self.tx_1f09_cycle()),
            self._loop.create_task(self.tx_3150_cycle()),
            self._loop.create_task(self.tx_3b00_cycle()),
        ]

    @property
    def cycle_rate(self) -> int:
        """Return the number of cycles per hour."""
        return self._cycle_rate

    @cycle_rate.setter
    def cycle_rate(self, value: int) -> None:
        """Set the number of cycles per hour.

        Calculates when the next cycle is due (it may become immediately due).
        """
        if value == self._cycle_rate:
            return
        assert value in (1, 2, 3, 6, 9, 12)
        self._cycle_rate = value
        self._3b00_duration, old_duration = (
            td(seconds=60 * 60 / value),
            self._3b00_duration,
        )
        self._next_3b00_cycle += self._3b00_duration - old_duration

    # @property
    # def heat_demand(self) -> int:
    #     """Return the number of cycles per hour."""
    #     return self._heat_demand

    @property
    def _sync_1f09_remaining(self) -> float:
        """Return the number of seconds until the next 1F09 cycle."""
        return (self._next_1f09_cycle - dt.now()).total_seconds()

    @property
    def _sync_3150_remaining(self) -> float:
        """Return the number of seconds until the next 3150 cycle."""
        return (self._next_3150_cycle - dt.now()).total_seconds()

    @property
    def _sync_3b00_remaining(self) -> float:
        """Return the number of seconds until the next 3B00 cycle."""
        return (self._next_3b00_cycle - dt.now()).total_seconds()

    def rx_frame_as_cmd(self, cmd: Command) -> None:
        """Find/Create an encoded frame, and place in on the ether."""

        LOOKUP_RQ: dict[str, Callable] = {
            Code._0005: self._make_0005,
            Code._0006: self._make_0006,
            Code._000C: self._make_000c,
            Code._1F09: self._make_1f09,
        }

        LOOKUP_OTH = {
            Code._0404: self._proc_0404,
            Code._3150: self._proc_3150,
        }

        assert cmd.dst.id == self.id

        if cmd.code == Code._1FC9:  # TODO
            return

        if cmd.verb == RQ and (fnc := LOOKUP_RQ.get(cmd.code)):
            self.tx_frames_as_cmds(fnc(dest_id=cmd.src.id))

        elif cmd.verb != RQ and (fnc := LOOKUP_OTH.get(cmd.code)):
            self.tx_frames_as_cmds(fnc(cmd))

        elif response := RESPONSES.get(cmd.tx_header):
            self.tx_frames_as_cmds(self.make_response_pkt(response))

    async def tx_1f09_cycle(self) -> None:  # 1F09, 2309/30C9 or 000A
        """Periodically queue sync_cycle pkts on the ether for the gwy to Rx."""
        # I|1F09|FFxxxx and 2309/30C9 every 3-5m
        # I|1F09|FFxxxx and 000A every 60-90m, instead (say every 20 cycles?)

        # .I --- 01:087939 --:------ 01:087939 1F09 003 FF0532
        # .I --- 01:087939 --:------ 01:087939 2309 009 0007D0-010640-0201F4
        # .I --- 01:087939 --:------ 01:087939 30C9 009 0007A0-010634-020656

        counter = 0
        while self._is_running:
            await asyncio.sleep(self._sync_1f09_remaining)

            self._next_1f09_cycle = dt.now() + self._1F09_DURATION

            self.tx_frames_as_cmds(self._make_1f09())
            await asyncio.sleep(0.02)

            counter = (counter + 1) % _1F09_CYCLE_PERIOD
            if counter == 0:
                self.tx_frames_as_cmds(self._make_000a())
                return

            self.tx_frames_as_cmds(self._make_2309())
            await asyncio.sleep(0.02)
            self.tx_frames_as_cmds(self._make_30c9())

    async def tx_3150_cycle(self) -> None:  # 3150
        """Periodically queue heat_cycle pkts on the ether for the gwy to Rx."""
        # I|3150|FCxx minimum every cycle, and on state change & again 1m later

        while self._is_running:
            await asyncio.sleep(self._sync_3150_remaining)

            # if was an even-driven 3150 sent elsewhere, have to restart the timer
            if self._next_3150_cycle > (dt_now := dt.now()):
                continue
            else:
                self._next_3150_cycle = dt_now + _3150_CYCLE_DURATION

            self.tx_frames_as_cmds(self._make_3150())

    async def tx_3b00_cycle(self) -> None:  # 3B00
        """Periodically queue heat_cycle pkts on the ether for the gwy to Rx."""
        # I|3B00|FCC8 every 10m (usu. 3-4s drift)

        while self._is_running:
            await asyncio.sleep(self._sync_3b00_remaining)

            if self._sync_3b00_remaining > 0:  # may have been updated elsewhere
                continue

            self._next_3b00_cycle = dt.now() + self._3b00_duration

    def _make_0005(self, context: str) -> None | Command:
        def is_type(idx, zone_type):
            return zones.get(f"{idx:02X}", {}).get(SZ_CLASS) == (
                ZON_ROLE_MAP[zone_type]
            )

        zone_type = context[2:]
        if not self._tcs or zone_type not in ZON_ROLE_MAP.HEAT_ZONES:
            return None

        zones = self._tcs.schema[SZ_ZONES]
        zone_mask = (is_type(idx, zone_type) for idx in range(0x10))

        return Command.put_zone_types(
            self.id, GWY_ID, zone_type, zone_mask, sub_idx=context[:2]
        )

    def _make_0006(self, dest_id: str) -> Command:
        payload = f"0005{self._change_counter:04X}"  # 0005 is not a typo
        return Command._from_attrs(
            RP, Code._0006, payload, addr0=self.id, addr1=dest_id
        )

    def _make_000a(self, dest_id: None | _DeviceIdT = None) -> Command:  # TODO:
        return None  # type: ignore[return-value]

    def _make_000c(self, context: str) -> Command:  # TODO: no return None
        zone_idx, zone_type = context[:2], context[2:]

        if context == "000D":  # 01|DEV_ROLE_MAP.HTG
            pass
        elif context == "010D":  # 00|DEV_ROLE_MAP.HTG
            pass
        elif context == "000E":  # 00|DEV_ROLE_MAP.DHW
            pass
        elif context[2:] not in ZON_ROLE_MAP.HEAT_ZONES:
            raise NotImplementedError

        zone = self._tcs.zone_by_idx.get(zone_idx) if self._tcs else None
        if not zone:
            return None  # type: ignore[return-value]

        if zone_type == (SZ_ACTUATORS, zone.schema[SZ_CLASS]):
            pass
        if zone_type == (SZ_ACTUATORS, zone.schema[SZ_CLASS]):
            pass

        return None  # type: ignore[return-value]

    def _proc_0404(self, pkt: Command) -> Command:
        """Process an inbound 0404 packet."""
        if pkt.verb not in (W_, RQ):
            return None

        if response := RESPONSES.get(pkt.tx_header):
            if pkt.verb == W_:
                self._change_counter += 2
            return self.make_response_pkt(response)

    def _make_1100(self, dest_id: None | _DeviceIdT = None) -> Command:  # TODO
        """Craft a stateful 1100 array pkt (is WIP)."""

        payload = "0007D00106400201F4"  # HACK
        return Command._from_attrs(
            I_, Code._1100, payload, addr0=self.id, addr2=self.id
        )

    def _make_1f09(self, dest_id: None | _DeviceIdT = None) -> Command:
        """Craft a stateful 1F09 pkt."""

        if dest_id:
            verb = RP
            payload = f"00{self._sync_1f09_remaining * 10:04X}"
            addrs = {"addr0": self.id, "addr1": dest_id}
        else:
            # assert 0 < self._sync_cycle_remaining < 5  # required?
            verb = I_
            payload = f"FF{_1F09_CYCLE_DURATION * 10:04X}"  # TypeError: unsupported format string passed to datetime.timedelta.__format__
            addrs = {"addr0": self.id, "addr2": self.id}

        return Command._from_attrs(verb, Code._1F09, payload, **addrs)

    def _make_2309(
        self, dest_id: None | _DeviceIdT = None, idx: None | _PktIdxT = None
    ) -> Command:  # WIP
        """Craft a stateful 2309 array pkt (is WIP)."""

        assert dest_id is None or idx is not None

        payload = "0007D00106400201F4"  # HACK
        return Command._from_attrs(
            I_, Code._2309, payload, addr0=self.id, addr2=self.id
        )

    def _make_30c9(
        self, dest_id: None | _DeviceIdT = None, idx: None | _PktIdxT = None
    ) -> Command:  # WIP
        """Craft a stateful 3C09 array pkt (is WIP)."""

        assert dest_id is None or idx is not None

        payload = "0007A0010634020656"  # HACK
        return Command._from_attrs(
            I_, Code._30C9, payload, addr0=self.id, addr2=self.id
        )

    def _proc_3150(self, pkt: Command) -> None:
        """Process an inbound 3150 packet."""
        pass

    def _make_3150(  # WIP
        self, dest_id: None | _DeviceIdT = None, idx: None | _PktIdxT = None
    ) -> Command:
        """Craft a stateful 3150 cmd (is WIP)."""

        payload = "0007A0010634020656"  # HACK
        return Command._from_attrs(
            I_, Code._30C9, payload, addr0=self.id, addr2=self.id
        )

    def _make_3b00(self) -> Command:
        """Craft a 3B00 pkt."""
        # 'I --- 01:145038 --:------ 01:145038 3B00 002 FCC8  # only periodic I, never RP
        # .I --- --:------ --:------ 12:207082 3B00 002 00C8  # idx=00, never? FC
        # .I --- 13:209679 --:------ 13:209679 3B00 002 00C8  #

        # 2020-06-09T12:06:45.628934 054  I --- 13:209679 --:------ 13:209679 3B00 002 00C8
        # 2020-06-09T12:06:48.415689 045  I --- 01:158182 --:------ 01:158182 3B00 002 FCC8
        # 2020-06-09T12:16:44.544482 057  I --- 13:209679 --:------ 13:209679 3B00 002 00C8
        # 2020-06-09T12:16:47.107356 045  I --- 01:158182 --:------ 01:158182 3B00 002 FCC8
        # does 13: Tx at end of cycle?

        return Command._from_attrs(I_, Code._30C9, "FCC8", addr0=self.id, addr2=self.id)


class MockDeviceThm(MockDeviceBase):
    """A pseudo-mocked thermostat used for testing."""

    def __init__(self, gwy, device_id, *, schema=None) -> None:
        super().__init__(gwy, device_id)

        self.temperature = None  # TODO: maintain internal state (is needed?)


RESPONSES: dict[str, str] = {
    f"0006|RQ|{CTL_ID}": f"RP --- {CTL_ID} {GWY_ID} --:------ 0006 004 00050008",
    # RQ schedule for zone 01
    f"0404|RQ|{CTL_ID}|0101": f"RP --- {CTL_ID} {GWY_ID} --:------ 0404 048 0120000829010368816DCCC91183301005D1D93428200E1C7D720C04402C0442640E82000C851701ADD3AFAED1131151",
    f"0404|RQ|{CTL_ID}|0102": f"RP --- {CTL_ID} {GWY_ID} --:------ 0404 048 0120000829020339DEBC8DBE1EFBDB5EDBA8DDB92DBEDFADDAB6671179E4FF4EC153F0143C05CFC033F00C3C03CFC173",
    f"0404|RQ|{CTL_ID}|0103": f"RP --- {CTL_ID} {GWY_ID} --:------ 0404 046 01200008270303F01C3C072FC00BF002BC00AF7CFEB6DEDE46BBB721EE6DBA78095E8297E0E5CF5BF50DA0291B9C",
    # RQ schedule for DHW
    f"0404|RQ|{CTL_ID}|HW01": f"RP --- {CTL_ID} {GWY_ID} --:------ 0404 048 0023000829010468816DCDD10980300C45D1BE24CD9713398093388BF33981A3882842B5BDE9571F178E4ABB4DA5E879",
    f"0404|RQ|{CTL_ID}|HW02": f"RP --- {CTL_ID} {GWY_ID} --:------ 0404 048 00230008290204EDCEF7F3DD761BBBC9C7EEF0B15BEABF13B80257E00A5C812B700D5C03D7C035700D5C03D7C175701D",
    f"0404|RQ|{CTL_ID}|HW03": f"RP --- {CTL_ID} {GWY_ID} --:------ 0404 048 002300082903045C07D7C1757003DC0037C00D7003DC00B7827B6FB38D5DEF56702BB8F7B6766E829BE026B8096E829B",
    f"0404|RQ|{CTL_ID}|HW04": f"RP --- {CTL_ID} {GWY_ID} --:------ 0404 014 002300080704041FF702BAC2188E",
    # W schedule for zone 01
    f"0404| W|{CTL_ID}|0101": f" I --- {CTL_ID} {GWY_ID} --:------ 0404 007 01200008290103",
    f"0404| W|{CTL_ID}|0102": f" I --- {CTL_ID} {GWY_ID} --:------ 0404 007 01200008290203",
    f"0404| W|{CTL_ID}|0103": f" I --- {CTL_ID} {GWY_ID} --:------ 0404 007 01200008280300",
    # W schedule for DHW
    f"0404| W|{CTL_ID}|HW01": f" I --- {CTL_ID} {GWY_ID} --:------ 0404 007 01200008290104",
    f"0404| W|{CTL_ID}|HW02": f" I --- {CTL_ID} {GWY_ID} --:------ 0404 007 01200008290204",
    f"0404| W|{CTL_ID}|HW03": f" I --- {CTL_ID} {GWY_ID} --:------ 0404 007 01200008280304",
    f"0404| W|{CTL_ID}|HW04": f" I --- {CTL_ID} {GWY_ID} --:------ 0404 007 01200008280400",
    #
    f"2309|RQ|{CTL_ID}|00": f"RP --- {CTL_ID} --:------ {GWY_ID} 2309 003 0007D0",
    f"2309|RQ|{CTL_ID}|01": f"RP --- {CTL_ID} --:------ {GWY_ID} 2309 003 010640",
    f"2309|RQ|{CTL_ID}|02": f"RP --- {CTL_ID} --:------ {GWY_ID} 2309 003 0201F4",
    #
    f"30C9|RQ|{CTL_ID}|00": f"RP --- {CTL_ID} --:------ {GWY_ID} 30C9 003 0007A0",
    f"30C9|RQ|{CTL_ID}|01": f"RP --- {CTL_ID} --:------ {GWY_ID} 30C9 003 010634",
    f"30C9|RQ|{CTL_ID}|02": f"RP --- {CTL_ID} --:------ {GWY_ID} 30C9 003 020656",
}  # "pkt_header": "response_pkt"

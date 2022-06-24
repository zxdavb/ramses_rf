#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

A pseudo-mocked serial port used for testing.

Will provide a fixed Tx for a given Rx.
"""

import asyncio
import logging
from datetime import datetime as dt
from datetime import timedelta as td
from queue import Empty, Full, PriorityQueue
from typing import Optional, Union

from ramses_rf import Gateway
from ramses_rf.const import SZ_ACTUATORS, SZ_CLASS, SZ_ZONES, ZON_ROLE_MAP
from ramses_rf.protocol import InvalidPacketError
from ramses_rf.protocol.command import Command as CommandBase
from ramses_rf.protocol.command import validate_api_params
from ramses_rf.protocol.const import (
    _000C,
    _1F09,
    _30C9,
    I_,
    RP,
    _0005,
    _0006,
    _0404,
    _2309,
    __dev_mode__,
)
from ramses_rf.protocol.transport import PacketProtocolPort, SerTransportPoll

RUNNING = True

DEV_MODE = __dev_mode__ and False

GWY_ID = "18:181818"
CTL_ID = "01:000730"

_LOGGER = logging.getLogger(__name__)
# _LOGGER.setLevel(logging.WARNING)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


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

        return cls._from_attrs(RP, _0005, payload, addr0=src_id, addr1=dst_id)

    @classmethod  # constructor for RP/000C
    @validate_api_params(has_zone=True)
    def put_zone_devices(
        cls,
        src_id: str,
        dst_id: str,
        zone_idx: Union[int, str],
        zone_type: str,
        devices: tuple[str],
    ):
        """Constructor for RP/000C."""

        payload = f"{zone_idx}{zone_type}..."

        return cls._from_attrs(RP, _000C, payload, addr0=src_id, addr1=dst_id)


class MockSerialBase:  # all the 'mocking' is done here

    """A pseudo-mocked serial port used for testing.

    Will periodically Rx a sync_cycle set that will be available via `read()`.
    Will use a reponse table to provide a known Rx for a given Tx sent via `write()`.
    """

    DEV_ID = GWY_ID

    def __init__(self, gwy, port=None, **kwargs) -> None:
        self._loop = gwy._loop

        self.port = port
        self._rx_buffer = bytes()
        self._out_waiting = 0
        self.is_open = None

        self._devices = []

        self._que = PriorityQueue(maxsize=24)
        self._next_bytes = self._loop.create_task(self._rx_buffer_bytes())

    def close(self, exc=None):
        """Close the por."""
        if not self.is_open:
            return
        self.is_open = False

        for device in self._devices:
            for task in device._tasks:
                task.cancel()
        if task := self._next_bytes:
            task.cancel()

    @property
    def in_waiting(self) -> int:
        """Return the number of bytes currently in the input buffer."""
        return len(self._rx_buffer)

    def read_all(self) -> bytes:
        """Read max size bytes from the serial port."""
        return self.read(size=self.in_waiting)

    def read(self, size: int = 1) -> bytes:
        """Read max size bytes from the serial port."""
        data, self._rx_buffer = self._rx_buffer[:size], self._rx_buffer[size:]
        return data

    async def _rx_buffer_bytes(self) -> None:
        """Poll the queue and add bytes to the Rx buffer."""

        self.is_open = True

        while RUNNING:
            await asyncio.sleep(0.001)

            try:
                klass, _, data, rp_header = self._que.get_nowait()
            except Empty:
                continue

            if klass == 3:
                self._out_waiting -= len(data)
            self._rx_buffer += b"000 " + data

            if rp_header:
                for device in self._devices:
                    device.rx_frame_by_header(rp_header)

            self._que.task_done()

    @property
    def out_waiting(self) -> int:
        """Return the number of bytes currently in the output buffer."""
        return self._out_waiting

    def write(self, data: bytes) -> int:
        """Output the given byte string over the serial port."""

        if data[:1] == b"!":  # an evofw3 flag
            return 0
        if data[7:16] == b"18:000730":
            data = data[:7] + bytes(self.DEV_ID, "ascii") + data[16:]
        try:
            self._tx_data(data, Command(data.decode("ascii")))
        except InvalidPacketError:
            pass
        return 0

    def _tx_data(self, data: str, cmd: Command) -> None:
        """Transmit a packet from the gateway, usually an RQ."""

        try:
            self._que.put_nowait((3, dt.now(), data, cmd.rx_header))
        except Full:
            return
        self._out_waiting += len(data)


class MockSerial(MockSerialBase):
    def __init__(self, gwy, *args, **kwargs) -> None:
        super().__init__(gwy, *args, **kwargs)

        self._devices = [MockDeviceCtl(self, gwy)]


class MockDeviceCtl:
    """A pseudo-mocked controller used for testing.

    Will periodically Rx a sync_cycle set that will be available via `read()`.
    Will use a reponse table to provide a known Rx for a given Tx sent via `write()`.
    """

    DEV_ID = CTL_ID

    SYNC_CYCLE_INTERVAL = 60  # sync_cycle interval, in seconds
    SYNC_CYCLE_REMANING = 5
    # SYNC_CYCLE_PACKETS = sync_cycle_pkts(DEV_ID, SYNC_CYCLE_INTERVAL)

    def __init__(self, ser, gwy, schema=None) -> None:

        self._ser = ser
        self._que = ser._que  # this entity will only put

        self._gwy = gwy
        self._loop = gwy._loop

        self._tcs = None  # load_system(gwy, self.DEV_ID, schema or {})

        self._change_counter = 8
        self.next_cycle = dt.now() + td(seconds=self.SYNC_CYCLE_REMANING)

        self._tasks = [self._loop.create_task(self.tx_sync_cycle())]

    def rx_frame_by_header(self, rp_header: str) -> None:
        """Find an encoded frame (via its header), and queue it for the gwy to Rx.

        The rp_header is the sent cmd's rx_header (the header of teh packet the gwy is
        waiting for).
        """

        if rp_header == f"{_1F09}|{RP}|{CTL_ID}":
            pkts = self.tx_response_1f09()

        elif rp_header[:17] == f"{_0005}|{RP}|{CTL_ID}":
            pkts = self.tx_response_0005(rp_header[18:])

        elif rp_header[:17] == f"{_0006}|{RP}|{CTL_ID}":
            pkts = self.tx_response_0006(rp_header)

        elif rp_header[:17] == f"{_000C}|{RP}|{CTL_ID}":
            pkts = self.tx_response_000c(rp_header[18:])

        elif response := RESPONSES.get(rp_header):
            if rp_header[:17] == f"{_0404}|{I_}|{CTL_ID}":
                self._change_counter += 2
            pkts = self.tx_response_pkt(response + "\r\n")
        else:
            pkts = None

        if not pkts:
            return
        if isinstance(pkts[0], int):
            pkts = ((pkts),)

        for (priority, cmd) in pkts:
            try:
                self._que.put_nowait(
                    (priority, dt.now(), bytes(f"{cmd}\r\n", "ascii"), None)
                )
            except Full:
                pass

    async def tx_sync_cycle(self) -> None:
        """Periodically transmit sync_cycle packets from the controller."""

        while RUNNING:
            await asyncio.sleep((self.next_cycle - dt.now()).total_seconds())

            for cmd in sync_cycle_pkts(CTL_ID, self.SYNC_CYCLE_INTERVAL):
                try:
                    self._que.put_nowait(
                        (0, dt.now(), bytes(f"{cmd}\r\n", "ascii"), None)
                    )
                except Full:
                    pass
                await asyncio.sleep(0.02)

            self.next_cycle = dt.now() + td(seconds=self.SYNC_CYCLE_INTERVAL - 0.06)

    def tx_response_pkt(self, frame: str) -> Optional[tuple]:
        try:
            return 2, Command(frame)
        except InvalidPacketError as exc:
            raise InvalidPacketError(f"Invalid entry the response table: {exc}")

    def tx_response_1f09(self) -> Optional[tuple]:
        interval = int((self.next_cycle - dt.now()).total_seconds() * 10)
        return 1, Command._from_attrs(
            RP, _1F09, f"00{interval:04X}", addr0=self.DEV_ID, addr1=GWY_ID
        )

    def tx_response_0005(self, context: str) -> Optional[tuple]:
        def is_type(idx, zone_type):
            return zones.get(f"{idx:02X}", {}).get(SZ_CLASS) == (
                ZON_ROLE_MAP[zone_type]
            )

        zone_type = context[2:]
        if not self._tcs or zone_type not in ZON_ROLE_MAP.HEAT_ZONES:
            return

        zones = self._tcs.schema[SZ_ZONES]
        zone_mask = (is_type(idx, zone_type) for idx in range(0x10))

        return 1, Command.put_zone_types(
            self.DEV_ID, GWY_ID, zone_type, zone_mask, sub_idx=context[:2]
        )

    def tx_response_0006(self, rp_header) -> Optional[tuple]:
        payload = f"0005{self._change_counter:04X}"
        return 1, Command._from_attrs(
            RP, _0006, payload, addr0=self.DEV_ID, addr1=GWY_ID
        )

    def tx_response_000c(self, context: str) -> Optional[tuple]:
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


class SerTransportMock(SerTransportPoll):  # only to gracefully close the mocked port
    def close(self) -> None:
        super().close()

        if self.serial:
            self.serial.close()


class MockGateway(Gateway):  # to use a bespoke create_pkt_stack()
    def _start(self) -> None:
        """Initiate ad-hoc sending, and (polled) receiving."""

        (_LOGGER.warning if DEV_MODE else _LOGGER.debug)("ENGINE: Starting poller...")

        # if self.ser_name:  # source of packets is a serial port
        pkt_receiver = (
            self.msg_transport.get_extra_info(self.msg_transport.READER)
            if self.msg_transport
            else None
        )
        self.pkt_protocol, self.pkt_transport = create_pkt_stack(
            self, pkt_receiver, ser_port=self.ser_name
        )  # TODO: can raise SerialException
        if self.msg_transport:
            self.msg_transport._set_dispatcher(self.pkt_protocol.send_data)


def create_pkt_stack(  # to use a mocked Serial port (and a sympathetic Transport)
    gwy, pkt_callback, *, ser_port=None
) -> tuple[asyncio.Protocol, asyncio.Transport]:
    """Return a mocked packet stack.

    Must use SerTransportPoll and not SerTransportAsync.
    """

    pkt_protocol = PacketProtocolPort(gwy, pkt_callback)

    ser_instance = MockSerial(gwy, port=ser_port)
    pkt_transport = SerTransportMock(gwy._loop, pkt_protocol, ser_instance)

    return (pkt_protocol, pkt_transport)


def sync_cycle_pkts(ctl_id, seconds) -> tuple[Command, Command, Command]:
    """Return a sync_cycle set of packets as from a controller."""
    #  I --- 01:087939 --:------ 01:087939 1F09 003 FF0532
    #  I --- 01:087939 --:------ 01:087939 2309 009 0007D0-010640-0201F4
    #  I --- 01:087939 --:------ 01:087939 30C9 009 0007A0-010634-020656

    cmd_1f09 = Command._from_attrs(
        I_, _1F09, f"FF{seconds * 10:04X}", addr0=ctl_id, addr2=ctl_id
    )
    cmd_2309 = Command._from_attrs(
        I_, _2309, "0007D00106400201F4", addr0=ctl_id, addr2=ctl_id
    )
    cmd_30c9 = Command._from_attrs(
        I_, _30C9, "0007A0010634020656", addr0=ctl_id, addr2=ctl_id
    )

    return cmd_1f09, cmd_2309, cmd_30c9


RESPONSES = {
    f"0006|RP|{CTL_ID}": f"RP --- {CTL_ID} {GWY_ID} --:------ 0006 004 00050008",
    # RQ schedule for zone 01
    f"0404|RP|{CTL_ID}|0101": f"RP --- {CTL_ID} {GWY_ID} --:------ 0404 048 0120000829010368816DCCC91183301005D1D93428200E1C7D720C04402C0442640E82000C851701ADD3AFAED1131151",
    f"0404|RP|{CTL_ID}|0102": f"RP --- {CTL_ID} {GWY_ID} --:------ 0404 048 0120000829020339DEBC8DBE1EFBDB5EDBA8DDB92DBEDFADDAB6671179E4FF4EC153F0143C05CFC033F00C3C03CFC173",
    f"0404|RP|{CTL_ID}|0103": f"RP --- {CTL_ID} {GWY_ID} --:------ 0404 046 01200008270303F01C3C072FC00BF002BC00AF7CFEB6DEDE46BBB721EE6DBA78095E8297E0E5CF5BF50DA0291B9C",
    # RQ schedule for DHW
    f"0404|RP|{CTL_ID}|FA01": f"RP --- {CTL_ID} {GWY_ID} --:------ 0404 048 0023000829010468816DCDD10980300C45D1BE24CD9713398093388BF33981A3882842B5BDE9571F178E4ABB4DA5E879",
    f"0404|RP|{CTL_ID}|FA02": f"RP --- {CTL_ID} {GWY_ID} --:------ 0404 048 00230008290204EDCEF7F3DD761BBBC9C7EEF0B15BEABF13B80257E00A5C812B700D5C03D7C035700D5C03D7C175701D",
    f"0404|RP|{CTL_ID}|FA03": f"RP --- {CTL_ID} {GWY_ID} --:------ 0404 048 002300082903045C07D7C1757003DC0037C00D7003DC00B7827B6FB38D5DEF56702BB8F7B6766E829BE026B8096E829B",
    f"0404|RP|{CTL_ID}|FA04": f"RP --- {CTL_ID} {GWY_ID} --:------ 0404 014 002300080704041FF702BAC2188E",
    # W schedule for zone 01
    f"0404| I|{CTL_ID}|0101": f" I --- {CTL_ID} {GWY_ID} --:------ 0404 007 01200008290103",
    f"0404| I|{CTL_ID}|0102": f" I --- {CTL_ID} {GWY_ID} --:------ 0404 007 01200008290203",
    f"0404| I|{CTL_ID}|0103": f" I --- {CTL_ID} {GWY_ID} --:------ 0404 007 01200008280300",
    # W schedule for DHW
    f"0404| I|{CTL_ID}|FA01": f" I --- {CTL_ID} {GWY_ID} --:------ 0404 007 01200008290104",
    f"0404| I|{CTL_ID}|FA02": f" I --- {CTL_ID} {GWY_ID} --:------ 0404 007 01200008290204",
    f"0404| I|{CTL_ID}|FA03": f" I --- {CTL_ID} {GWY_ID} --:------ 0404 007 01200008280304",
    f"0404| I|{CTL_ID}|FA04": f" I --- {CTL_ID} {GWY_ID} --:------ 0404 007 01200008280400",
    #
    f"2309|RP|{CTL_ID}|00": f"RP --- {CTL_ID} --:------ {GWY_ID} 2309 003 0007D0",
    f"2309|RP|{CTL_ID}|01": f"RP --- {CTL_ID} --:------ {GWY_ID} 2309 003 010640",
    f"2309|RP|{CTL_ID}|02": f"RP --- {CTL_ID} --:------ {GWY_ID} 2309 003 0201F4",
    #
    f"30C9|RP|{CTL_ID}|00": f"RP --- {CTL_ID} --:------ {GWY_ID} 30C9 003 0007A0",
    f"30C9|RP|{CTL_ID}|01": f"RP --- {CTL_ID} --:------ {GWY_ID} 30C9 003 010634",
    f"30C9|RP|{CTL_ID}|02": f"RP --- {CTL_ID} --:------ {GWY_ID} 30C9 003 020656",
}  # "pkt_header": "response_pkt"

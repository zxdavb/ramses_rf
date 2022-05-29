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
from queue import Empty, PriorityQueue

from ramses_rf import Gateway
from ramses_rf.protocol import InvalidPacketError
from ramses_rf.protocol.command import Command
from ramses_rf.protocol.const import _1F09, _30C9, I_, RP, _2309, __dev_mode__
from ramses_rf.protocol.transport import PacketProtocolPort, SerTransportPoll

RUNNING = True

DEV_MODE = __dev_mode__ and False

GWY_ID = "18:181818"
CTL_ID = "01:123456"

_LOGGER = logging.getLogger(__name__)
# _LOGGER.setLevel(logging.WARNING)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class MockSerialBase:  # all the 'mocking' is done here

    """A pseudo-mocked serial port used for testing.

    Will periodically Rx a sync_cycle set that will be available via `read()`.
    Will use a reponse table to provide a known Rx for a given Tx sent via `write()`.
    """

    def __init__(self, gwy, port=None, **kwargs) -> None:
        self._gwy = gwy
        self._loop = gwy._loop

        self.port = port

        self._que = PriorityQueue(maxsize=5)
        self._rx_buffer = bytes()

        self._out_waiting = 0

        self._next_bytes = self._loop.create_task(self._rx_next_bytes())

        self.is_open = True

    @property
    def in_waiting(self) -> int:
        """Return the number of bytes currently in the input buffer."""
        return len(self._rx_buffer)

    @property
    def out_waiting(self) -> int:
        """Return the number of bytes currently in the output buffer."""
        return self._out_waiting

    def read(self, size: int = 1) -> bytes:
        """Read max size bytes from the serial port."""
        data, self._rx_buffer = self._rx_buffer[:size], self._rx_buffer[size:]
        return data

    def read_all(self) -> bytes:
        """Read max size bytes from the serial port."""
        return self.read(size=self.in_waiting)

    def write(self, data: bytes) -> int:
        """Output the given byte string over the serial port."""

        if data[:1] == b"!":
            return 0
        if data[7:16] == b"18:000730":
            data = data[:7] + bytes(GWY_ID, "ascii") + data[16:]
        try:
            self._tx_request(data, Command.from_frame(data.decode("ascii")))
        except InvalidPacketError:
            pass
        return 0

    def _rx_frame_by_header(self, rp_header: str) -> None:
        """Find an encoded frame (via its header), and queue it for the gwy to Rx."""
        pass

    async def _rx_next_bytes(self) -> bytes:
        """Poll the queue and add bytes to the Rx buffer."""

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
                self._rx_frame_by_header(rp_header)

            self._que.task_done()

    def _tx_request(self, data: str, cmd: Command) -> None:
        """Transmit a packet from the gateway, usually an RQ."""

        self._que.put_nowait((3, dt.now(), data, cmd.rx_header))
        self._out_waiting += len(data)


class MockSerial(MockSerialBase):
    """A pseudo-mocked controller used for testing.

    Will periodically Rx a sync_cycle set that will be available via `read()`.
    Will use a reponse table to provide a known Rx for a given Tx sent via `write()`.
    """

    SYNC_INTERVAL = 60  # sync_cycle interval, in seconds
    # SYNC_PACKETS = sync_cycle_pkts(CTL_ID, SYNC_INTERVAL)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.next_cycle = dt.now() + td(seconds=10)
        self._sync_cycle = self._loop.create_task(self._tx_sync_cycle())

    def _rx_frame_by_header(self, rp_header: str) -> None:
        """Find an encoded frame (via its header), and queue it for the gwy to Rx."""

        def tx_response(frame: str):
            try:
                cmd = Command.from_frame(frame)
            except InvalidPacketError as exc:
                raise InvalidPacketError(f"Invalid entry the response table: {exc}")
            self._que.put_nowait((2, dt.now(), bytes(f"{cmd}\r\n", "ascii"), None))

        def tx_response_1f09():
            seconds = (self.next_cycle - dt.now()).total_seconds()
            cmd = Command.packet(
                RP, _1F09, f"00{seconds * 10:04X}", addr0=CTL_ID, addr2=CTL_ID
            )
            self._que.put_nowait((1, dt.now(), bytes(f"{cmd}\r\n", "ascii"), None))

        if rp_header == f"{_1F09}|{RP}|{CTL_ID}":
            tx_response_1f09()
        elif frame := RESPONSES.get(rp_header):
            tx_response(frame + "\r\n")

    async def _tx_sync_cycle(self) -> None:
        """Periodically transmit sync_cycle packets from the controller."""

        while RUNNING:
            dt_now = dt.now()
            await asyncio.sleep((self.next_cycle - dt_now).total_seconds())
            self.next_cycle = dt_now + td(seconds=self.SYNC_INTERVAL)

            for cmd in sync_cycle_pkts(CTL_ID, self.SYNC_INTERVAL):
                self._que.put_nowait((0, dt.now(), bytes(f"{cmd}\r\n", "ascii"), None))
                await asyncio.sleep(0.02)


class SerTransportMock(SerTransportPoll):  # only to gracefully close the mocked port
    def close(self) -> None:
        super().close()

        for task in (self.serial._sync_cycle, self.serial._next_bytes):
            if task:
                task.cancel()


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

    cmd_1f09 = Command.packet(
        I_, _1F09, f"FF{seconds * 10:04X}", addr0=ctl_id, addr2=ctl_id
    )
    cmd_2309 = Command.packet(
        I_, _2309, "0007D00106400201F4", addr0=ctl_id, addr2=ctl_id
    )
    cmd_30c9 = Command.packet(
        I_, _30C9, "0007A0010634020656", addr0=ctl_id, addr2=ctl_id
    )

    return cmd_1f09, cmd_2309, cmd_30c9


RESPONSES = {
    f"0006|RP|{CTL_ID}": f"RP --- {CTL_ID} --:------ {GWY_ID} 0006 004 00050008",
    #
    f"0404|RP|{CTL_ID}|0101": f"RP --- {CTL_ID} --:------ {GWY_ID} 0404 048 0120000829010368816DCCC91183301005D1D93428200E1C7D720C04402C0442640E82000C851701ADD3AFAED1131151",
    f"0404|RP|{CTL_ID}|0102": f"RP --- {CTL_ID} --:------ {GWY_ID} 0404 048 0120000829020339DEBC8DBE1EFBDB5EDBA8DDB92DBEDFADDAB6671179E4FF4EC153F0143C05CFC033F00C3C03CFC173",
    f"0404|RP|{CTL_ID}|0103": f"RP --- {CTL_ID} --:------ {GWY_ID} 0404 046 01200008270303F01C3C072FC00BF002BC00AF7CFEB6DEDE46BBB721EE6DBA78095E8297E0E5CF5BF50DA0291B9C",
    #
    f"2309|RP|{CTL_ID}|00": f"RP --- {CTL_ID} --:------ {GWY_ID} 2309 003 0007D0",
    f"2309|RP|{CTL_ID}|01": f"RP --- {CTL_ID} --:------ {GWY_ID} 2309 003 010640",
    f"2309|RP|{CTL_ID}|02": f"RP --- {CTL_ID} --:------ {GWY_ID} 2309 003 0201F4",
    #
    f"30C9|RP|{CTL_ID}|00": f"RP --- {CTL_ID} --:------ {GWY_ID} 30C9 003 0007A0",
    f"30C9|RP|{CTL_ID}|01": f"RP --- {CTL_ID} --:------ {GWY_ID} 30C9 003 010634",
    f"30C9|RP|{CTL_ID}|02": f"RP --- {CTL_ID} --:------ {GWY_ID} 30C9 003 020656",
}  # "pkt_header": "response_pkt"

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
from queue import Empty, PriorityQueue
from typing import Tuple

from ramses_rf import Gateway
from ramses_rf.protocol import InvalidPacketError
from ramses_rf.protocol.command import Command
from ramses_rf.protocol.const import _1F09, _30C9, I_, _2309, __dev_mode__
from ramses_rf.protocol.transport import PacketProtocolPort, SerTransportPoll

RUNNING = True

DEV_MODE = __dev_mode__ and False

GWY_ID = "18:123456"
CTL_ID = "01:145038"

_LOGGER = logging.getLogger(__name__)
# _LOGGER.setLevel(logging.WARNING)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class MockSerial:  # all the 'mocking' is done here

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

        self._sync_cycle = self._loop.create_task(self._tx_sync_cycle())
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

        data = data.decode("ascii")
        if data[:1] == "!":
            return 0

        try:
            _, hdr = self._validate_raw_pkt(data)
        except InvalidPacketError:
            return 0

        self._tx_request(data, hdr)
        return 0

    @staticmethod
    def _validate_raw_pkt(data) -> Tuple[str, str]:
        cmd = data.split()
        cmd = Command.packet(
            cmd[0], cmd[5], cmd[7], addr0=cmd[2], addr1=cmd[3], addr2=cmd[4]
        )  # may raise InvalidPacketError:
        return str(cmd), str(cmd.tx_header)

    async def _rx_next_bytes(self) -> bytes:
        """Poll the queue and add bytes to the Rx buffer."""

        while RUNNING:
            await asyncio.sleep(0.001)

            try:
                _, _, data, header = self._que.get_nowait()
            except Empty:
                continue

            self._rx_buffer += b"000 " + bytes(data, "ascii")  # + b"\r\n"

            if header:
                self._out_waiting -= len(data)
                self._tx_response(header)

            self._que.task_done()

    def _tx_request(self, data: str, header: str) -> None:
        """Transmit a packet from the gateway, usually an RQ."""

        assert data[-2:] == "\r\n", f"_tx_request({data})"

        if data[7:16] == "18:000730":
            data = data[:7] + GWY_ID + data[16:]

        self._que.put_nowait((3, dt.now(), data, header))
        self._out_waiting += len(data)

    def _tx_response(self, header: str) -> None:
        """Transmit a response packet, if any, from a device."""

        data = RESPONSES.get(header)
        if not data:
            return

        try:
            self._validate_raw_pkt(data)
        except InvalidPacketError as exc:
            raise InvalidPacketError(f"Invalid pkt in the response table: {exc}")

        assert data[-2:] != "\r\n", f"_tx_response({data})"
        self._que.put_nowait((2, dt.now(), f"{data}\r\n", None))

    async def _tx_sync_cycle(self) -> None:
        """Periodically transmit sync_cycle packets from the controller."""

        INTERVAL = 60  # sync_cycle interval, in seconds

        await asyncio.sleep(5)
        while RUNNING:
            for data, _ in sync_cycle_pkts(CTL_ID, INTERVAL):
                assert data[-2:] != "\r\n", f"_tx_sync_cycle({data})"
                self._que.put_nowait((0, dt.now(), f"{data}\r\n", None))
                await asyncio.sleep(0.02)

            await asyncio.sleep(INTERVAL - 0.06)


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


def sync_cycle_pkts(ctl_id, seconds) -> Tuple[Command, Command, Command]:
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

    return ((str(cmd), str(cmd.tx_header)) for cmd in (cmd_1f09, cmd_2309, cmd_30c9))


RESPONSES = {
    f"0006|RQ|{CTL_ID}": f"RP --- {CTL_ID} --:------ {GWY_ID} 0006 004 00050008",
    #
    f"0404|RQ|{CTL_ID}|0101": f"RP --- {CTL_ID} --:------ {GWY_ID} 0404 048 0120000829010368816DCCC91183301005D1D93428200E1C7D720C04402C0442640E82000C851701ADD3AFAED1131151",
    f"0404|RQ|{CTL_ID}|0102": f"RP --- {CTL_ID} --:------ {GWY_ID} 0404 048 0120000829020339DEBC8DBE1EFBDB5EDBA8DDB92DBEDFADDAB6671179E4FF4EC153F0143C05CFC033F00C3C03CFC173",
    f"0404|RQ|{CTL_ID}|0103": f"RP --- {CTL_ID} --:------ {GWY_ID} 0404 046 01200008270303F01C3C072FC00BF002BC00AF7CFEB6DEDE46BBB721EE6DBA78095E8297E0E5CF5BF50DA0291B9C",
    #
    f"2309|RQ|{CTL_ID}|00": f"RP --- {CTL_ID} --:------ {GWY_ID} 2309 003 0007D0",
    f"2309|RQ|{CTL_ID}|01": f"RP --- {CTL_ID} --:------ {GWY_ID} 2309 003 010640",
    f"2309|RQ|{CTL_ID}|02": f"RP --- {CTL_ID} --:------ {GWY_ID} 2309 003 0201F4",
    #
    f"30C9|RQ|{CTL_ID}|00": f"RP --- {CTL_ID} --:------ {GWY_ID} 30C9 003 0007A0",
    f"30C9|RQ|{CTL_ID}|01": f"RP --- {CTL_ID} --:------ {GWY_ID} 30C9 003 010634",
    f"30C9|RQ|{CTL_ID}|02": f"RP --- {CTL_ID} --:------ {GWY_ID} 30C9 003 020656",
}  # "pkt_header": "response_pkt"

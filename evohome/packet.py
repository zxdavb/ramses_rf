"""Packet processor."""
import asyncio
from datetime import datetime as dt, timedelta
import logging
from string import printable
from threading import Lock
from types import SimpleNamespace
from typing import Optional, Tuple

from serial import SerialException  # noqa
from serial_asyncio import open_serial_connection  # noqa

from .command import Command, _pkt_header
from .const import (
    DTM_LONG_REGEX,
    MESSAGE_REGEX,
    NON_DEVICE,
    NUL_DEVICE,
    __dev_mode__,
    id_to_address,
)
from .logger import dt_now, dt_str

BAUDRATE = 115200
READ_TIMEOUT = 0.5
XON_XOFF = True

Pause = SimpleNamespace(
    NONE=timedelta(seconds=0),
    MINIMUM=timedelta(seconds=0.01),
    SHORT=timedelta(seconds=0.05),
    DEFAULT=timedelta(seconds=0.15),
    LONG=timedelta(seconds=0.5),
)

# tx (from sent to gwy, to get back from gwy) seems to takes 0.025
DISABLE_QOS_CODE = False
MAX_BUFFER_LEN = 1
MAX_SEND_COUNT = 1
# RETRANS_TIMEOUT = timedelta(seconds=0.03)
# 0.060 gives false +ve for 10E0?
# 0.065 too low when stressed with (e.g.) schedules, log entries
EXPIRY_TIMEOUT = timedelta(seconds=2.0)  # say 0.5

_LOGGER = logging.getLogger(__name__)
if True or __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)
else:
    _LOGGER.setLevel(logging.WARNING)


def extra(dtm, pkt=None):
    _date, _time = dtm[:26].split("T")
    return {
        "date": _date,
        "time": _time,
        "_packet": str(pkt) + " " if pkt else "",
        "error_text": "",
        "comment": "",
    }


def _logger(log_msg, pkt, dtm_now):
    _LOGGER.warning("%s < %s", pkt, log_msg, extra=extra(dtm_now.isoformat(), pkt))


def split_pkt_line(packet_line: str) -> Tuple[str, str, str]:
    # line format: 'datetime packet < parser-message: * evofw3-errmsg # evofw3-comment'
    def _split(text: str, char: str) -> Tuple[str, str]:
        _list = text.split(char, maxsplit=1)
        return _list[0].strip(), _list[1].strip() if len(_list) == 2 else ""

    packet_tmp, comment = _split(packet_line, "#")
    packet_tmp, error = _split(packet_tmp, "*")
    packet, _ = _split(packet_tmp, "<")
    return packet, f"* {error} " if error else "", f"# {comment} " if comment else ""


class Packet:
    """The packet class."""

    def __init__(self, dtm, pkt, raw_pkt) -> None:
        """Create a packet."""
        self.dtm = dtm
        self.date, self.time = dtm.split("T")  # dtm assumed to be valid

        self._pkt_line = pkt
        self._raw_pkt_line = raw_pkt
        self.packet, self.error_text, self.comment = split_pkt_line(pkt)
        self._packet = self.packet + " " if self.packet else ""  # NOTE: hack 4 logging

        self.addrs = [None] * 3
        self.src_addr = self.dst_addr = None

        self._is_valid = None
        self._is_valid = self.is_valid

    def __str__(self) -> str:
        return self.packet if self.packet else ""

    def __repr__(self):
        return str(self._raw_pkt_line if self._raw_pkt_line else self._pkt_line)

    def __eq__(self, other) -> bool:
        if not hasattr(other, "packet"):
            return NotImplemented
        return self.packet == other.packet

    @property
    def is_valid(self) -> Optional[bool]:
        """Return True if a valid packets, otherwise return False/None & log it."""
        # 'good' packets are not logged here, as they may be for silent discarding

        def validate_addresses() -> Optional[bool]:
            """Return True if the address fields are valid (create any addresses)."""
            for idx, addr in enumerate(
                [self.packet[i : i + 9] for i in range(11, 32, 10)]
            ):
                self.addrs[idx] = id_to_address(addr)

            # This check will invalidate these rare pkts (which are never transmitted)
            # ---  I --- --:------ --:------ --:------ 0001 005 00FFFF02FF
            # ---  I --- --:------ --:------ --:------ 0001 005 00FFFF0200
            if not all(
                (
                    self.addrs[0].id not in (NON_DEVICE.id, NUL_DEVICE.id),
                    (self.addrs[1].id, self.addrs[2].id).count(NON_DEVICE.id) == 1,
                )
            ) and not all(
                (
                    self.addrs[2].id not in (NON_DEVICE.id, NUL_DEVICE.id),
                    self.addrs[0].id == self.addrs[1].id == NON_DEVICE.id,
                )
            ):
                return False

            device_addrs = list(filter(lambda x: x.type != "--", self.addrs))

            self.src_addr = device_addrs[0]
            self.dst_addr = device_addrs[1] if len(device_addrs) > 1 else NON_DEVICE

            if self.src_addr.id == self.dst_addr.id:
                self.src_addr = self.dst_addr
            elif self.src_addr.type == self.dst_addr.type:
                # 064  I --- 01:078710 --:------ 01:144246 1F09 003 FF04B5 (invalid)
                return False

            return len(device_addrs) < 3

        if self._is_valid is not None or not self._pkt_line:
            return self._is_valid

        if self.error_text:  # log all packets with an error
            if self.packet:
                _LOGGER.warning("%s < Bad packet: ", self, extra=self.__dict__)
            else:
                _LOGGER.warning("< Bad packet: ", extra=self.__dict__)
            return False

        if not self.packet and self.comment:  # log null packets only if has a comment
            _LOGGER.warning("", extra=self.__dict__)  # normally a warning
            return False

        # TODO: these packets shouldn't go to the packet log, only STDERR?
        if not MESSAGE_REGEX.match(self.packet):
            err_msg = "invalid packet structure"
        elif not validate_addresses():
            err_msg = "invalid packet addresses"
        elif int(self.packet[46:49]) > 48:  # TODO: is 02/I/22C9 > 24?
            err_msg = "excessive payload length"
        elif int(self.packet[46:49]) * 2 != len(self.packet[50:]):
            err_msg = "mismatched payload length"
        else:  # it is a valid packet
            # TODO: Check that an expected RP arrived for an RQ sent by this library
            return True

        _LOGGER.warning("%s < Bad packet: %s ", self, err_msg, extra=self.__dict__)
        return False

    def is_wanted(self, include: list = None, exclude: list = None) -> bool:
        """Silently drop packets with unwanted (e.g. neighbour's) devices.

        Packets to/from HGI80: are never ignored.
        """

        def is_wanted_pkt() -> bool:
            """Return True is a packet is not to be filtered out."""

            if " 18:" in self.packet:  # NOTE: " 18:", leading space is required
                return True
            if include:
                return any(device in self.packet for device in include)
            if exclude:
                return not any(device in self.packet for device in exclude)
            return True

        if is_wanted_pkt():
            _LOGGER.info("%s ", self.packet, extra=self.__dict__)
            return True
        return False

    @property
    def _header(self) -> Optional[str]:
        """Return the QoS header of this packet."""

        if self.is_valid:
            return _pkt_header(str(self))


class PortPktProvider:
    """Base class for packets from a serial port."""

    def __init__(self, serial_port, loop, timeout=READ_TIMEOUT) -> None:
        # self.serial_port = "rfc2217://localhost:5000"
        self.serial_port = serial_port
        self.baudrate = BAUDRATE
        self.timeout = timeout
        self.xonxoff = XON_XOFF
        self._loop = loop

        self._qos_lock = Lock()
        self._qos_buffer = {}

        self.reader = self.write = None
        self._pause = dt.min

    async def __aenter__(self):
        # TODO: Add ValueError, SerialException wrapper
        self.reader, self.writer = await open_serial_connection(
            loop=self._loop,
            url=self.serial_port,
            baudrate=self.baudrate,
            timeout=self.timeout,
            # write_timeout=None,
            xonxoff=self.xonxoff,
        )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        pass

    async def get_pkt(self) -> Tuple[str, str, Optional[bytearray]]:
        """Pull (get) the next packet tuple (dtm, pkt, pkt_raw) from a serial port."""

        async def read_pkt():
            try:  # HACK: because I can't get read timeout to work
                if True or self.reader._transport.serial.in_waiting:
                    pkt_raw = await self.reader.readline()
                else:
                    pkt_raw = b""
                    await asyncio.sleep(0)
            except SerialException:
                return Packet(dt_str(), "", None)

            dtm_str = dt_str()  # done here & now for most-accurate timestamp
            # _LOGGER.debug("%s < Raw pkt", pkt_raw, extra=extra(dtm_str, pkt_raw))

            try:
                pkt_str = "".join(
                    c
                    for c in pkt_raw.decode("ascii", errors="strict").strip()
                    if c in printable
                )
            except UnicodeDecodeError:
                _LOGGER.warning("%s < Bad pkt", pkt_raw, extra=extra(dtm_str, pkt_raw))
                return Packet(dtm_str, "", pkt_raw)

            # any firmware-level packet hacks, i.e. non-HGI80 devices, should be here

            return Packet(dtm_str, pkt_str, pkt_raw)

        # TODO: validate the packet before calculating the header
        pkt = await read_pkt()

        if DISABLE_QOS_CODE or pkt._pkt_line == "":
            await asyncio.sleep(0)
            return pkt  # TODO: or None

        # await asyncio.sleep(0)
        self._qos_lock.acquire()

        if pkt._header in self._qos_buffer:
            # # _LOGGER.warning(
            # #     "%s < %s, received from gateway (was in buffer) %s ",
            # #     pkt,
            # #     pkt._header,
            # #     f"GET {self._qos_buffer}",
            # #     extra=pkt.__dict__,
            # # )
            # self._pause = dt.min

            cmd = self._qos_buffer[pkt._header]  # AAA
            # print("PKT:", pkt._header, "_RQ:", cmd._rq_header, "_RP:", cmd._rp_header)

            if pkt._header == cmd._rq_header:
                self._qos_buffer[cmd._rp_header] = cmd

                dtm_now = dt_now()  # after submit
                if cmd.verb == " W" or cmd.code in ("0004", "0404", "0418"):
                    cmd.dtm_timeout = dtm_now + Pause.LONG
                elif cmd.verb == "RQ":
                    cmd.dtm_timeout = dtm_now + Pause.LONG
                else:
                    cmd.dtm_timeout = dtm_now + Pause.DEFAULT

                cmd.transmit_count = 1
                cmd.dtm_expires = dtm_now + EXPIRY_TIMEOUT

            del self._qos_buffer[pkt._header]

        # # elif str(pkt)[4:6] == "RP" and str(pkt)[21:23] == "18":
        # #     _LOGGER.warning(
        # #         "%s < %s, received from gateway (wasn't in buffer) %s",
        # #         pkt,
        # #         pkt._header,
        # #         f"GET {self._qos_buffer}",
        # #         extra=pkt.__dict__,
        # #     )

        self._qos_lock.release()
        await asyncio.sleep(0)

        return pkt

    async def put_pkt(self, put_cmd, logger):  # TODO: logger is a hack
        """Send (put) the next packet to a serial port."""

        def write_pkt(cmd) -> None:

            self.writer.write(bytearray(f"{cmd}\r\n".encode("ascii")))
            # _logger(f"just sent to gateway", f"... {cmd}", dtm_now)

            dtm_now = dt_now()  # after submit

            # the pause between submitting (command) packets
            if cmd is None or str(cmd).startswith("!"):  # evofw3 traceflag:
                self._pause = dtm_now + Pause.MINIMUM
                return
            elif cmd.verb == " W" or cmd.code in ("0004", "0404", "0418"):
                self._pause = dtm_now + Pause.SHORT
            else:  # BBB
                self._pause = dtm_now + Pause.SHORT

            if DISABLE_QOS_CODE:
                return

            # how long to wait to see the packet appear on the ether
            if cmd.verb == " W" or cmd.code in ("0004", "0404", "0418"):
                cmd.dtm_timeout = dtm_now + Pause.DEFAULT
            elif cmd.verb == "RQ":
                cmd.dtm_timeout = dtm_now + Pause.SHORT
            else:
                cmd.dtm_timeout = dtm_now + Pause.DEFAULT

            cmd.transmit_count += 1
            if cmd.transmit_count == 1:
                cmd.dtm_expires = dtm_now + EXPIRY_TIMEOUT
            else:
                _LOGGER.warning(
                    "... %s < was re-transmitted %s of %s",
                    cmd,
                    cmd.transmit_count,
                    MAX_SEND_COUNT,
                    extra=extra(dtm_now.isoformat(), cmd),
                )

        # print("PUT", self._qos_buffer)

        while True:
            dtm_now = dt_now()  # before submit
            await asyncio.sleep(min((self._pause - dtm_now).total_seconds(), 0.01))
            # if self._pause > dtm_now:  # sleep until mid-tx pause is over
            #    await asyncio.sleep(min((self._pause - dtm_now).total_seconds(), 0.01))
            #     # await asyncio.sleep((self._pause - dtm_now).total_seconds())
            #     # await asyncio.sleep(0.01)

            if DISABLE_QOS_CODE:
                write_pkt(put_cmd)
                break

            self._qos_lock.acquire()

            if put_cmd is not None and str(put_cmd).startswith("!"):
                _cmd = put_cmd
            else:
                _cmd = self._check_buffer(put_cmd)  # None, put_cmd, or cmd from buffer

            # dtm_untils = [
            #     v.dtm_timeout
            #     for v in self._qos_buffer.values()
            #     if v.dtm_timeout is not None
            # ]

            self._qos_lock.release()
            await asyncio.sleep(0)

            if _cmd is put_cmd:
                write_pkt(_cmd)
                break
            elif _cmd is not None:
                write_pkt(_cmd)
            # elif dtm_untils:
            #     await asyncio.sleep((min(dtm_untils) - dtm_now).total_seconds())
            # # # else:
            # # #     await asyncio.sleep(0)

        await asyncio.sleep(0)
        # print("PUT", self._qos_buffer)

    def _check_buffer(self, put_cmd) -> Optional[Command]:
        """Maintain the buffer & return the next packet to be retransmitted, if any."""
        # print("CHKa", self._qos_buffer)

        dtm_now = dt_now()
        expired_kmds = []
        cmd = None

        for header, kmd in self._qos_buffer.items():
            if kmd.dtm_expires < dtm_now:  # abandon
                _LOGGER.error(
                    "%s < %s, timed out: fully expired: removed",
                    f"... {kmd}",
                    header,
                    extra=extra(dtm_now.isoformat(), f"... {kmd}"),
                )
                expired_kmds.append(header)

            elif kmd.dtm_timeout < dtm_now:  # retransmit?
                if kmd.transmit_count >= MAX_SEND_COUNT:  # abandon
                    # _LOGGER.error(
                    #     "%s < %s, timed out: exceeded retries (%s of %s): removed",
                    #     f"... {kmd}",
                    #     header,
                    #     kmd.transmit_count,
                    #     MAX_SEND_COUNT,
                    #     extra=extra(dtm_now.isoformat(), f"... {kmd}"),
                    # )
                    expired_kmds.append(header)

                else:  # retransmit (choose the next cmd with the higher priority)
                    cmd = kmd if cmd is None or kmd < cmd else cmd
                    _LOGGER.error(
                        "%s < %s, timed out: re-transmissible (%s of %s): remains",
                        f"... {kmd}",
                        header,
                        kmd.transmit_count,
                        MAX_SEND_COUNT,
                        extra=extra(dtm_now.isoformat(), f"... {kmd}"),
                    )
        else:
            self._qos_buffer = {
                h: p for h, p in self._qos_buffer.items() if h not in expired_kmds
            }

        # print("CHKb", self._qos_buffer)

        if cmd is not None:  # re-transmit
            # log_msg = "next for re-transmission (remains in buffer) "
            # print("aaa")
            pass

        elif len(self._qos_buffer) < MAX_BUFFER_LEN:
            # print("bbb")  # no problem
            cmd = put_cmd
            self._qos_buffer[cmd._rq_header] = cmd
            # log_msg = "next for transmission (added to buffer) "

        else:  # buffer is full
            # print("ccc")  # problem
            return None

        # _LOGGER.warning(
        #     "%s < %s, %s",
        #     f"... {cmd}",
        #     cmd._rq_header,
        #     log_msg,
        #     extra=extra(dtm_now.isoformat(), f"... {cmd}"),
        # )

        # print("CHKc", self._qos_buffer)
        return cmd


class FilePktProvider:
    """WIP: Base class for packets from a source file."""

    def __init__(self, file_name) -> None:
        self.file_name = file_name

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        pass

    async def get_pkt(self) -> Optional[str]:
        """Get the next packet line from a source file."""
        return


async def port_pkts(manager, include=None, exclude=None, relay=None):

    while True:
        pkt = await manager.get_pkt()
        if pkt.is_valid and pkt.is_wanted(include=include, exclude=exclude):
            if relay is not None:  # TODO: handle socket close
                asyncio.create_task(relay.write(pkt.packet))
            yield pkt

        await asyncio.sleep(0)  # at least 0, to enable a Ctrl-C


async def file_pkts(fp, include=None, exclude=None):

    for ts_pkt in fp:
        ts_pkt = ts_pkt.strip()
        if ts_pkt == "":  # ignore blank lines
            continue

        try:
            dtm, pkt = ts_pkt[:26], ts_pkt[27:]
            # assuming a completely valid log file, asserts allows for -O for inc. speed
            assert DTM_LONG_REGEX.match(dtm)
            assert dt.fromisoformat(dtm)

        except (AssertionError, TypeError, ValueError):
            _LOGGER.warning(
                "%s < Packet line has an invalid timestamp (ignoring)",
                ts_pkt,
                extra=extra(dt_str(), ts_pkt),
            )
            continue

        pkt = Packet(dtm, pkt, None)
        if pkt.is_valid and pkt.is_wanted(include=include, exclude=exclude):
            yield pkt

        await asyncio.sleep(0)  # usu. 0, only to enable a Ctrl-C

"""Packet processor."""
import asyncio
from datetime import datetime as dt, timedelta
import logging
from string import printable
from threading import Lock
from typing import Optional, Tuple

from serial import SerialException  # noqa
from serial_asyncio import open_serial_connection  # noqa

from .command import Command, Pause, Qos
from .const import (
    DTM_LONG_REGEX,
    MESSAGE_REGEX,
    NON_DEVICE,
    NUL_DEVICE,
    Address,
    __dev_mode__,
)
from .logger import dt_now, dt_str

BAUDRATE = 115200
READ_TIMEOUT = 0.5
XON_XOFF = True

MAX_BUFFER_LEN = 3
MAX_RETRY_COUNT = 3
RETRANS_TIMEOUT = timedelta(seconds=0.5)
EXPIRY_TIMEOUT = timedelta(seconds=2.0)


_LOGGER = logging.getLogger(__name__)
if __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)


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
                self.addrs[idx] = Address(id=addr, type=addr[:2])

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
        """Return the QoS header of this packet, if it is valid."""

        if self.is_valid:
            return "|".join(self.packet[4:6], self.src_addr, self.packet[41:45])


class PortPktProvider:
    """Base class for packets from a serial port."""

    def __init__(self, serial_port, loop, timeout=READ_TIMEOUT) -> None:
        # self.serial_port = "rfc2217://localhost:5000"
        self.serial_port = serial_port
        self.baudrate = BAUDRATE
        self.timeout = timeout
        self.xonxoff = XON_XOFF
        self.loop = loop

        self._lock = Lock()
        self._qos_buffer = {}

        self.reader = self.write = None
        self._pause = dt.min

    async def __aenter__(self):
        # TODO: Add ValueError, SerialException wrapper
        self.reader, self.writer = await open_serial_connection(
            loop=self.loop,
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
        """Pull (get) the next packet tuple (dtm, pkt, pkt_bytes) from a serial port."""

        try:  # HACK: because I can't get read timeout to work
            if True or self.reader._transport.serial.in_waiting:
                pkt_bytes = await self.reader.readline()
            else:
                pkt_bytes = b""
                await asyncio.sleep(0.1)
        except SerialException:
            return dt_str(), "", None

        dtm_str = dt_str()  # done here & now for most-accurate timestamp
        _LOGGER.debug("%s < Raw packet", pkt_bytes, extra=extra(dtm_str, pkt_bytes))

        try:
            pkt_str = "".join(
                c
                for c in pkt_bytes.decode("ascii", errors="strict").strip()
                if c in printable
            )
        except UnicodeDecodeError:
            _LOGGER.warning(
                "%s < Bad (raw) packet", pkt_bytes, extra=extra(dtm_str, pkt_bytes)
            )
            return dtm_str, "", pkt_bytes

        # any firmware-level packet hacks, i.e. non-HGI80 devices, should be here

        # TODO: validate the packet before calculating the header
        if self._lock is not None:
            header = "|".join((pkt_str[4:6], pkt_str[11:20], pkt_str[41:45]))

            self._lock.acquire()

            if header in self._qos_buffer:
                _LOGGER.warning(
                    "%s < received, assumed valid (removed from buffer), header = %s",
                    pkt_str,
                    header,
                    extra=extra(dtm_str, pkt_bytes),
                )
                del self._qos_buffer[header]
            elif pkt_str != "":
                _LOGGER.warning(
                    "%s < received, assumed valid (wasn't in the buffer), header = %s",
                    pkt_str,
                    header,
                    extra=extra(dtm_str, pkt_bytes),
                )

            self._lock.release()

        return dtm_str, pkt_str, pkt_bytes

    async def put_pkt(self, put_pkt, logger):  # TODO: logger is a hack
        """Send (put) the next packet to a serial port."""
        qos_pkt = self.check_buffer()
        if put_pkt is not None and str(put_pkt).startswith("!"):
            pkt = put_pkt
        else:
            pkt = put_pkt if qos_pkt is None else qos_pkt

        while pkt is not None:

            dtm_now = dt_now()
            if pkt is qos_pkt:  # already in buffer
                _logger("for transmission (already in buffer)", f"... {pkt}", dtm_now)

            elif pkt.qos == Qos.AT_MOST_ONCE:  # don't add to buffer
                _logger("for transmission (wont add to buffer)", f"... {pkt}", dtm_now)

            else:  # add to buffer
                _logger("for transmission (will add to buffer)", f"... {pkt}", dtm_now)

            if self._pause > dtm_now:  # sleep until pause is over
                await asyncio.sleep((self._pause - dtm_now).total_seconds())

            self.writer.write(bytearray(f"{pkt}\r\n".encode("ascii")))
            # logger.debug("# Data was sent to %s: %s", self.serial_port, pkt)

            dtm_now = dt_now()  # TODO: needed?
            _logger("transmitted", f"... {pkt}", dtm_now)

            if pkt is None or str(pkt).startswith("!"):  # evofw3 traceflag:
                self._pause = dtm_now + timedelta(seconds=Pause.SHORT)
            else:
                self._pause = dtm_now + timedelta(seconds=max(pkt.pause, Pause.DEFAULT))

            if pkt.qos != Qos.AT_MOST_ONCE:
                pkt.dtm_timeout = dtm_now + RETRANS_TIMEOUT
                if pkt.transmit_count == 0:
                    pkt.dtm_expires = dtm_now + EXPIRY_TIMEOUT
                pkt.transmit_count += 1

            if pkt is put_pkt:
                break

            qos_pkt = self.check_buffer()
            pkt = put_pkt if qos_pkt is None else qos_pkt

        if put_pkt is not None and put_pkt.qos != Qos.AT_MOST_ONCE:
            while len(self._qos_buffer) == MAX_BUFFER_LEN:  # TODO: need a lock in here?
                await asyncio.sleep(Pause.SHORT)
            self._lock.acquire()
            self._qos_buffer[put_pkt._header] = put_pkt
            self._lock.release()

    def check_buffer(self) -> Optional[Command]:
        """Return the next packet to be retransmitted, and maintain the QoS buffer."""
        dtm_now = dt_now()
        expired_pkts = []
        cmd = None

        self._lock.acquire()

        for header, pkt in self._qos_buffer.items():
            if pkt.dtm_expires < dtm_now:  # abandon
                _logger(
                    "timed out & fully expired (removed from buffer)",
                    f"... {pkt}",
                    dtm_now,
                )
                expired_pkts.append(header)

            elif pkt.dtm_timeout < dtm_now:  # retransmit?
                if pkt.transmit_count == MAX_RETRY_COUNT:  # abandon
                    _logger(
                        "timed out & exceeded retry count (removed from buffer)",
                        f"... {pkt}",
                        dtm_now,
                    )
                    expired_pkts.append(header)

                else:  # retransmit
                    cmd = pkt if cmd is None or pkt.priority < cmd.priority else cmd
                    _logger(
                        "timed out & re-transmissible (remains in buffer)",
                        f"... {pkt}",
                        dtm_now,
                    )

        else:
            self._qos_buffer = {
                h: p for h, p in self._qos_buffer.items() if h not in expired_pkts
            }

        self._lock.release()

        if cmd is not None:  # re-transmit
            _logger(
                "timed out & next for re-transmission (remains in buffer)", cmd, dtm_now
            )
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
        pkt = Packet(*(await manager.get_pkt()))
        if pkt.is_valid and pkt.is_wanted(include=include, exclude=exclude):
            if relay is not None:  # TODO: handle socket close
                asyncio.create_task(relay.write(pkt.packet))
            yield pkt

        await asyncio.sleep(Pause.NONE)  # at least 0, to enable a Ctrl-C


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

        await asyncio.sleep(Pause.NONE)  # usu. 0, to enable a Ctrl-C

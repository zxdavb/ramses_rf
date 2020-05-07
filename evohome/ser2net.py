"""Simple proxy for connecting over TCP or telnet to serial port."""
import asyncio
import logging
from string import printable

# from .const import COMMAND_REGEX

_LOGGER = logging.getLogger(__name__)  # evohome.ser2net


class Ser2NetProtocol(asyncio.Protocol):
    def __init__(self, command_queue) -> None:
        _LOGGER.warning("Ser2NetProtocol.__init__(%s)", command_queue)

        self._command_queue = command_queue
        self.transport = None

    def connection_made(self, transport):
        _LOGGER.warning("Ser2NetProtocol.connection_made(%s)", transport)

        self.transport = transport
        _LOGGER.warning(" - connection from: %s", transport.get_extra_info("peername"))

    def data_received(self, data):
        _LOGGER.warning("Ser2NetProtocol.data_received(%s)", data)
        _LOGGER.warning(" - packet received from network: %s", data)

        packet = "".join(c for c in data.decode().strip() if c in printable)

        # if not COMMAND_REGEX.match(packet):
        #     _LOGGER.warning(" - command invalid: %s", packet)
        #     return

        self._command_queue.put_nowait(packet)
        _LOGGER.warning(" - command sent to dispatch queue: %s", packet)

    def eof_received(self):
        _LOGGER.warning("Ser2NetProtocol.eof_received()")

        # self.transport.close()
        _LOGGER.warning(" - socket closed.")

    def connection_lost(self, exc):
        _LOGGER.warning("Ser2NetProtocol.connection_lost(%s)", exc)


class Ser2NetServer:
    """Create a raw ser2net relay."""

    def __init__(self, addr_port, cmd_que, loop) -> None:
        _LOGGER.warning("Ser2NetServer.__init__(%s, %s)", addr_port, cmd_que)

        self._loop = loop if loop else asyncio.get_running_loop()
        self._addr, self._port = addr_port.split(":")
        self.protocol = Ser2NetProtocol(cmd_que)
        self.server = None

    async def start(self) -> None:
        _LOGGER.warning("Ser2NetServer.start()")

        self.server = await self._loop.create_server(
            lambda: self.protocol, self._addr, int(self._port)
        )
        await self.server.serve_forever(),
        _LOGGER.warning(" - listening on %s:%s", self._addr, int(self._port))

    async def write(self, data) -> None:
        _LOGGER.warning("Ser2NetServer.write(%s)", data)

        if self.protocol.transport:
            self.protocol.transport.write(data)
            _LOGGER.warning(" - data sent to socket: %s", data)
        else:
            _LOGGER.warning(" - no active session, unable to send")

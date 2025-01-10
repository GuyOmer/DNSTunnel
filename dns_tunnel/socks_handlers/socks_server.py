import enum
import logging
import select
import socket
from typing import Iterable, cast

import more_itertools

from dns_tunnel.consts import (
    PROXY_CLIENT_ADDRESS,
    PROXY_CLIENT_PORT,
    PROXY_SERVER_ADDRESS,
    PROXY_SERVER_PORT,
)
from dns_tunnel.protocol import DNSPacket, MessageType
from dns_tunnel.selectables.proxy_socket import ProxySocket
from dns_tunnel.selectables.tcp_client_socket import TCPClientSocket
from dns_tunnel.socks5_protocol import (
    SOCKS5AuthMethod,
    SOCKS5CommandCode,
    SOCKS5ConnectRequestStatus,
    SOCKS5DNSConnectRequest,
    SOCKS5DNSConnectResponse,
    SOCKS5Greeting,
    SOCKS5GreetingResponse,
)
from dns_tunnel.socks_handlers.base_handler import BaseHandler

# Initialize logger
logging.basicConfig(level=logging.DEBUG, format="Server %(module)s %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


@enum.unique
class SOCKS5HandshakeState(enum.Enum):
    WAITING_FOR_CONNECT_REQUEST = enum.auto()


class ProxyServerHandler(BaseHandler):
    def __init__(self, logger: logging.Logger):
        super().__init__(logger)
        self._session_id_to_destination: dict[int, TCPClientSocket | None] = {}
        self._session_id_to_socks5_handshake_state: dict[int, SOCKS5HandshakeState] = {}

    @property
    def address(self):
        return PROXY_SERVER_ADDRESS

    @property
    def port(self):
        return PROXY_SERVER_PORT

    @property
    def edges(self):
        return self._session_id_to_destination.values()

    def run(self):
        ingress_socket = self.init_ingress_socket(PROXY_CLIENT_ADDRESS, PROXY_CLIENT_PORT)
        self._logger.info("Proxy server started and listening for connections")

        while True:
            self._rlist = [ingress_socket] + [d for d in self._session_id_to_destination.values() if d]
            self.init_wlist(ingress_socket)

            r_ready, w_ready, _ = select.select(self._rlist, self._wlist, [])
            self.handle_ingress_socket_read(ingress_socket, r_ready, w_ready)

            for dest in cast(
                Iterable[TCPClientSocket],
                [r for r in r_ready if r in self._session_id_to_destination.values()],
            ):
                data = dest.read()

                if not data:
                    self._logger.info(f"Destination socket {dest.session_id} closed")
                    self._session_id_to_destination[dest.session_id] = None
                    ingress_socket.end_session(dest.session_id)
                    dest.close()
                    continue

                self._logger.debug(f"Read {len(data)} bytes from destination socket {dest.session_id}")
                for chunk in more_itertools.chunked(data, DNSPacket.MAX_PAYLOAD):
                    ingress_socket.add_to_write_queue(bytes(chunk), dest.session_id)

            self.write_wlist(w_ready)

    def get_edge_by_session_id(self, session_id: int) -> TCPClientSocket:
        return self._session_id_to_destination.get(session_id)

    def remove_edge_by_session_id(self, session_id: int) -> None:
        logger.info(f"Closing session {session_id}")
        self._session_id_to_destination[session_id] = None

    def _handle_incoming_ingress_message(self, ingress: ProxySocket, msg: DNSPacket):
        if (msg.header.message_type == MessageType.NORMAL_MESSAGE and
                msg.header.session_id not in self._session_id_to_destination):
            logger.debug(f"Handling incoming message for session {msg.header.session_id}")
            self._handle_socks5_handshake(ingress, msg)
            return

        super()._handle_incoming_ingress_message(ingress, msg)

    def _handle_socks5_handshake(self, ingress: ProxySocket, msg: DNSPacket):
        # Session is still in SOCKS5 handshake phase
        logger.debug(f"Session {msg.header.session_id} in SOCKS5 handshake phase")

        # Check if start of handshake
        if msg.header.session_id not in self._session_id_to_socks5_handshake_state:
            self._session_id_to_socks5_handshake_state[msg.header.session_id] = (
                SOCKS5HandshakeState.WAITING_FOR_CONNECT_REQUEST
            )
            greeting_msg = SOCKS5Greeting.from_bytes(msg.payload)
            if SOCKS5AuthMethod.NO_AUTH not in greeting_msg.auth_methods:
                logger.error("Only no-auth is supported")
                raise ValueError("Only no-auth is supported")

            ingress.add_to_write_queue(
                SOCKS5GreetingResponse(SOCKS5AuthMethod.NO_AUTH).to_bytes(),
                msg.header.session_id,
            )
            logger.debug(f"Sent SOCKS5 greeting response for session {msg.header.session_id}")
        # Handshake already in progress
        else:
            match self._session_id_to_socks5_handshake_state[msg.header.session_id]:
                case SOCKS5HandshakeState.WAITING_FOR_CONNECT_REQUEST:
                    command_msg = SOCKS5DNSConnectRequest.from_bytes(msg.payload)
                    if command_msg.command != SOCKS5CommandCode.ESTABLISH_A_TCP_IP_STREAM_CONNECTION:
                        logger.error(f"Only {SOCKS5CommandCode.ESTABLISH_A_TCP_IP_STREAM_CONNECTION} is supported")
                        raise ValueError(
                            f"Only {SOCKS5CommandCode.ESTABLISH_A_TCP_IP_STREAM_CONNECTION} is supported"
                        )

                    dest_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    dest_sock.setblocking(False)

                    try:
                        try:
                            dest_sock.connect((command_msg.address, command_msg.port))
                        except BlockingIOError as e:
                            _, connected, __ = select.select([], [dest_sock], [], 0.4)
                            if not connected:
                                raise ConnectionRefusedError("Connection refused") from e
                    except (socket.gaierror, ConnectionRefusedError, BlockingIOError) as e:
                        logger.error(f"Failed to connect to {command_msg.address}:{command_msg.port} with {e}")
                        ingress.add_to_write_queue(
                            SOCKS5DNSConnectResponse(
                                SOCKS5ConnectRequestStatus.HOST_UNREACHABLE,
                                command_msg.address,
                                command_msg.port,
                            ).to_bytes(),
                            msg.header.session_id,
                        )
                        logger.error(
                            f"Host {command_msg.address}:{command_msg.port} not found for session "
                            f"{msg.header.session_id}"
                        )
                        return

                    self._session_id_to_destination[msg.header.session_id] = TCPClientSocket(
                        dest_sock, msg.header.session_id
                    )
                    ingress.add_to_write_queue(
                        SOCKS5DNSConnectResponse(
                            SOCKS5ConnectRequestStatus.GRANTED, command_msg.address, command_msg.port
                        ).to_bytes(),
                        msg.header.session_id,
                    )
                    logger.info(
                        f"Established TCP connection to {command_msg.address}:{command_msg.port} for session "
                        f"{msg.header.session_id}"
                    )
                case _:
                    logger.error("Invalid state")
                    raise ValueError("Invalid state")


if __name__ == "__main__":
    ProxyServerHandler(logger).run()

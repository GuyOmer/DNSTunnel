import enum
import logging
import os
import select
import socket

import more_itertools

from dns_tunnel.protocol import DNSPacket, MessageType, create_ack_message
from dns_tunnel.selectables.proxy_socket import ProxySocket
from dns_tunnel.selectables.tcp_client_socket import TCPClientSocket
from dns_tunnel.socks5_protocol import (
    SOCKS5AuthMethod,
    SOCKS5CommandCode,
    SOCKS5ConnectRequestStatus,
    SOCKS5Greeting,
    SOCKS5GreetingResponse,
    SOCKS5IPv4ConnectRequest,
    SOCKS5IPv4ConnectResponse,
)

PROXY_SERVER_ADDRESS = os.getenv("PROXY_SERVER_ADDRESS", "dns-server")
PROXY_SERVER_PORT = int(os.getenv("PROXY_SERVER_PORT", "53"))
PROXY_CLIENT_ADDRESS = os.getenv("PROXY_CLIENT_ADDRESS", "dns-server")
PROXY_CLIENT_PORT = int(os.getenv("PROXY_CLIENT_PORT", "53"))


# Initialize logger
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


@enum.unique
class SOCKS5HandshakeState(enum.Enum):
    WAITING_FOR_CONNECT_REQUEST = enum.auto()


class ProxyServerHandler:
    def __init__(self):
        self._rlist = []
        self._wlist = []
        self._destinations: list[TCPClientSocket] = []

        self._session_id_to_destination: dict[int, TCPClientSocket] = {}
        self._session_id_to_socks5_handshake_state: dict[int, SOCKS5HandshakeState] = {}

    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # s.listen(5)
        s.bind(("0.0.0.0", PROXY_SERVER_PORT))
        ingress_socket = ProxySocket(
            s,
            (PROXY_CLIENT_ADDRESS, PROXY_CLIENT_PORT),
        )
        self._rlist.append(ingress_socket)
        logger.info("Proxy server started and listening for connections")

        while True:
            r_ready, w_ready, _ = select.select(self._rlist, self._wlist, [])

            if ingress_socket in r_ready:
                msgs = ingress_socket.read()
                logger.debug(f"Received {len(msgs)} messages from ingress socket")

                for msg in msgs:
                    self._handle_incoming_ingress_message(ingress_socket, msg)

            for dest in [r for r in r_ready if r in self._destinations]:
                data = dest.read()  # TODO: Need to be real TCP read
                logger.debug(f"Read {len(data)} bytes from destination socket {dest.session_id}")
                for chunk in more_itertools.chunked(data, DNSPacket.MAX_PAYLOAD):
                    ingress_socket.queue_to_session(chunk, dest.session_id)

            for w in w_ready:
                if isinstance(w, (ProxySocket, TCPClientSocket)):
                    w.write()
                    logger.debug(f"Written data to socket {w}")

    def _handle_incoming_ingress_message(self, ingress: ProxySocket, msg: DNSPacket):
        logger.debug(f"Handling incoming message for session {msg.header.session_id}")

        if msg.header.message_type == MessageType.ACK_MESSAGE:
            ingress.ack_message(msg.header.session_id, msg.header.sequence_number)
            logger.debug(f"ACK message for session {msg.header.session_id}, sequence {msg.header.sequence_number}")
            return

        # Add ack to send queue
        ingress.add_to_write_queue(
            create_ack_message(
                msg.header.session_id,
                msg.header.sequence_number,
            ).to_bytes()
        )

        # Handle the message
        if msg.header.session_id not in self._session_id_to_destination:
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

                ingress.add_to_write_queue(SOCKS5GreetingResponse(SOCKS5AuthMethod.NO_AUTH).to_bytes())
                logger.debug(f"Sent SOCKS5 greeting response for session {msg.header.session_id}")
            # Handshake already in progress
            else:
                match self._session_id_to_socks5_handshake_state[msg.header.session_id]:
                    case SOCKS5HandshakeState.WAITING_FOR_CONNECT_REQUEST:
                        command_msg = SOCKS5IPv4ConnectRequest.from_bytes(msg.payload)
                        if command_msg.command != SOCKS5CommandCode.ESTABLISH_A_TCP_IP_STREAM_CONNECTION:
                            logger.error(f"Only {SOCKS5CommandCode.ESTABLISH_A_TCP_IP_STREAM_CONNECTION} is supported")
                            raise ValueError(
                                f"Only {SOCKS5CommandCode.ESTABLISH_A_TCP_IP_STREAM_CONNECTION} is supported"
                            )

                        dest_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        dest_sock.connect((command_msg.host, command_msg.port))  # TODO: might this block?
                        self._session_id_to_destination[msg.header.session_id] = TCPClientSocket(
                            dest_sock, msg.header.session_id
                        )
                        ingress.add_to_write_queue(
                            SOCKS5IPv4ConnectResponse(
                                SOCKS5ConnectRequestStatus.GRANTED, command_msg.host, command_msg.port
                            ).to_bytes()
                        )
                        logger.info(
                            f"Established TCP connection to {command_msg.host}:{command_msg.port} for session {msg.header.session_id}"
                        )
                    case _:
                        logger.error("Invalid state")
                        raise ValueError("Invalid state")

        else:
            # proxy tunnel already setup, just forward messages
            destination = self._session_id_to_destination[msg.header.session_id]
            destination.add_to_write_queue(msg.payload)
            logger.debug(f"Forwarded message to destination for session {msg.header.session_id}")


if __name__ == "__main__":
    ProxyServerHandler().run()

import abc
import itertools
import socket
from logging import Logger
import more_itertools

from dns_tunnel.protocol import DNSPacket, MessageType
from dns_tunnel.selectables.proxy_socket import ProxySocket
from dns_tunnel.selectables.tcp_client_socket import TCPClientSocket


class BaseHandler(abc.ABC):
    def __init__(self, logger: Logger):
        self._rlist = []
        self._wlist = []
        self._logger = logger

    @abc.abstractmethod
    def run(self) -> None: ...

    @property
    @abc.abstractmethod
    def address(self) -> str: ...

    @property
    @abc.abstractmethod
    def port(self) -> int: ...

    @property
    @abc.abstractmethod
    def ingress_socket(self) -> ProxySocket: ...

    @property
    @abc.abstractmethod
    def edges(self) -> list[TCPClientSocket]: ...

    @abc.abstractmethod
    def get_edge_by_session_id(self, session_id) -> TCPClientSocket: ...

    @abc.abstractmethod
    def remove_edge_by_session_id(self, session_id: int) -> None: ...

    def init_ingress_socket(self, address: str, port: int) -> ProxySocket:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((self.address, self.port))
        return ProxySocket(
            s,
            (address, port),
        )

    def init_wlist(self) -> None:
        self._wlist = [edge for edge in self.edges if edge and edge.needs_to_write()]
        if self.ingress_socket.needs_to_write():
            self._wlist.append(self.ingress_socket)

    def handle_ingress_socket_read(self, r_ready: list):
        if self.ingress_socket in r_ready:
            msgs = self.ingress_socket.read()
            for msg in msgs:
                self._handle_incoming_ingress_message(msg)

    def handle_read_edges(self, r_ready: list):
        # Read from tcp clients, and queue messages for sending
        read_ready_clients = [ready for ready in r_ready if ready in self.edges]
        for read_ready_client in read_ready_clients:
            # read as much as possible, non blocking
            data = read_ready_client.read()

            if not data:
                self._logger.info(f"Client {read_ready_client.session_id} closed")
                self.remove_edge_by_session_id(read_ready_client.session_id)
                self.ingress_socket.end_session(read_ready_client.session_id)
                continue

            self._logger.debug(f"Read data from client {read_ready_client.session_id}: {data}")
            for chunk in more_itertools.chunked(data, DNSPacket.MAX_PAYLOAD):
                self.ingress_socket.add_to_write_queue(bytes(chunk), read_ready_client.session_id)

    def write_wlist(self, wlist: list) -> None:
        write_ready = [ready for ready in wlist if ready and ready in itertools.chain(self.edges, [self.ingress_socket])]
        for w in write_ready:
            w.write()

    def _handle_incoming_ingress_message(self, msg: DNSPacket) -> None:
        self._logger.debug(f"Handling incoming message for session {msg.header.session_id}")

        if msg.header.message_type == MessageType.ACK_MESSAGE:
            self.ingress_socket.ack_message(msg.header.session_id, msg.header.sequence_number)
            self._logger.debug(
                f"ACK message for session {msg.header.session_id}, sequence {msg.header.sequence_number}"
            )
            return

        if msg.header.message_type == MessageType.CLOSE_SESSION:
            self._logger.info(f"Closing session {msg.header.session_id}")
            self.ingress_socket.remove_session(msg.header.session_id)
            self.remove_edge_by_session_id(msg.header.session_id)
            return

        edge = self.get_edge_by_session_id(msg.header.session_id)
        if not edge:
            self._logger.debug("No edge for session %s", msg.header.session_id)
            return

        edge.add_to_write_queue(msg.payload)
        self._logger.debug(f"Queued message for edge {edge.session_id}: {msg.payload}")

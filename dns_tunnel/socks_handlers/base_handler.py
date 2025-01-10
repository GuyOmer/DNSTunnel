import abc
import socket
from logging import Logger

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

    def init_wlist(self, ingress_socket: ProxySocket) -> None:
        self._wlist = [edge for edge in self.edges if edge and edge.needs_to_write()]
        if ingress_socket.needs_to_write():
            self._wlist.append(ingress_socket)

    def handle_ingress_socket_read(self, ingress_socket: ProxySocket, r_ready: list, w_ready: list):
        if ingress_socket in r_ready:
            msgs = ingress_socket.read()
            for msg in msgs:
                self._handle_incoming_ingress_message(ingress_socket, msg)

    @staticmethod
    def write_wlist(wlist: list) -> None:
        for w in wlist:
            if isinstance(w, (ProxySocket, TCPClientSocket)):
                w.write()

    def _handle_incoming_ingress_message(self, ingress: ProxySocket, msg: DNSPacket) -> None:
        self._logger.debug(f"Handling incoming message for session {msg.header.session_id}")

        if msg.header.message_type == MessageType.ACK_MESSAGE:
            ingress.ack_message(msg.header.session_id, msg.header.sequence_number)
            self._logger.debug(
                f"ACK message for session {msg.header.session_id}, sequence {msg.header.sequence_number}"
            )
            return

        if msg.header.message_type == MessageType.CLOSE_SESSION:
            self._logger.info(f"Closing session {msg.header.session_id}")
            ingress.remove_session(msg.header.session_id)
            self.remove_edge_by_session_id(msg.header.session_id)
            return

        edge = self.get_edge_by_session_id(msg.header.session_id)
        if not edge:
            self._logger.debug("No edge for session %s", msg.header.session_id)
            return

        edge.add_to_write_queue(msg.payload)
        self._logger.debug(f"Queued message for edge {edge.session_id}: {msg.payload}")

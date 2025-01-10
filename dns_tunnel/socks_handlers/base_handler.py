import abc
import socket
from logging import Logger

from dns_tunnel.protocol import DNSPacket, MessageType
from dns_tunnel.selectables.proxy_socket import ProxySocket


class BaseHandler(abc.ABC):
    def __init__(self, logger: Logger):
        self._rlist = []
        self._wlist = []
        self._logger = logger

    @abc.abstractmethod
    def run(self):
        ...

    @property
    @abc.abstractmethod
    def address(self):
        ...

    @property
    @abc.abstractmethod
    def port(self):
        ...

    @abc.abstractmethod
    def get_edge_by_session_id(self, session_id):
        ...

    def init_ingress_socket(self, address: str, port: int) -> ProxySocket:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((self.address(), self.port()))
        return ProxySocket(
            s,
            (address, port),
        )

    def _handle_incoming_ingress_message(self, ingress: ProxySocket, msg: DNSPacket):
        self._logger.debug(f"Handling incoming message for session {msg.header.session_id}")

        if msg.header.message_type == MessageType.ACK_MESSAGE:
            ingress.ack_message(msg.header.session_id, msg.header.sequence_number)
            self._logger.debug(f"ACK message for session {msg.header.session_id}, sequence {msg.header.sequence_number}")
            return

        edge = self.get_edge_by_session_id(msg.header.session_id)
        if not edge:
            self._logger.debug("No edge for session %s", msg.header.session_id)
            return

        edge.add_to_write_queue(msg.payload)
        self._logger.debug(f"Queued message for edge {edge.session_id}: {msg.payload}")

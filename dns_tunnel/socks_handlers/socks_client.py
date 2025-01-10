import logging
import random
import select
import socket

import more_itertools

from dns_tunnel.consts import (
    PROXY_CLIENT_ADDRESS,
    PROXY_CLIENT_PORT,
    PROXY_SERVER_ADDRESS,
    PROXY_SERVER_PORT,
    PROXY_CLIENT_SOCKS5_PORT,
)
from dns_tunnel.protocol import DNSPacket
from dns_tunnel.selectables.tcp_client_socket import TCPClientSocket
from dns_tunnel.socks_handlers.base_handler import BaseHandler

CLIENTS_BACKLOG = 5

# Initialize logger
logging.basicConfig(level=logging.DEBUG, format="Client %(module)s %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


class ClientHandler(BaseHandler):
    def __init__(self, logger: logging.Logger):
        super().__init__(logger)
        self._clients: list[TCPClientSocket] = []
        self._used_session_ids = set()

    @property
    def address(self):
        return PROXY_CLIENT_ADDRESS

    @property
    def port(self):
        return PROXY_CLIENT_PORT

    @property
    def edges(self):
        return self._clients

    def run(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((PROXY_CLIENT_ADDRESS, PROXY_CLIENT_SOCKS5_PORT))
        server_socket.listen(CLIENTS_BACKLOG)
        self._logger.info(f"Sockets client: Server started and listening on port {PROXY_CLIENT_SOCKS5_PORT}")

        ingress_socket = self.init_ingress_socket(PROXY_SERVER_ADDRESS, PROXY_SERVER_PORT)
        self._rlist = [server_socket]  # On startup - only listen for new server clients

        while True:
            self.init_wlist(ingress_socket)
            self._rlist = [server_socket, ingress_socket] + self._clients

            r_ready, w_ready, _ = select.select(self._rlist, self._wlist, [])

            # Accept new clients as needed
            if server_socket in r_ready:
                tcp_client, _ = server_socket.accept()
                self._logger.info("Accepted new TCP client")
                self._clients.append(
                    TCPClientSocket(
                        tcp_client,
                        self._get_session_id(),
                    )
                )

            self.handle_ingress_socket_read(ingress_socket, r_ready, w_ready)

            # Read from tcp clients, and queue messages for sending
            read_ready_clients = [ready for ready in r_ready if ready in self._clients]
            for read_ready_client in read_ready_clients:
                # read as much as possible, non blocking
                data = read_ready_client.read()

                if not data:
                    self._logger.info(f"Client {read_ready_client.session_id} closed")
                    self._clients.remove(read_ready_client)
                    ingress_socket.end_session(read_ready_client.session_id)
                    continue

                self._logger.debug(f"Read data from client {read_ready_client.session_id}: {data}")
                for chunk in more_itertools.chunked(data, DNSPacket.MAX_PAYLOAD):
                    ingress_socket.add_to_write_queue(bytes(chunk), read_ready_client.session_id)

            write_ready_clients = [ready for ready in w_ready if ready in self._clients]
            for write_ready_client in write_ready_clients:
                write_ready_client.write()
                self._logger.debug(f"Sent data for client {write_ready_client.session_id}")

            self.write_wlist(w_ready)

    def get_edge_by_session_id(self, session_id: int) -> TCPClientSocket:
        return self._get_client_by_session_id(session_id)

    def remove_edge_by_session_id(self, session_id: int):
        client = self._get_client_by_session_id(session_id)
        client.close()
        self._clients.remove(client)

    def _get_client_by_session_id(self, session_id):
        for client in self._clients:
            if client.session_id == session_id:
                return client

    def _get_session_id(self) -> int:
        session_id = random.randint(0, 2**32)
        while session_id in self._used_session_ids:
            session_id = random.randint(0, 2**32)
        self._used_session_ids.add(session_id)
        return session_id


if __name__ == "__main__":
    ClientHandler(logger).run()

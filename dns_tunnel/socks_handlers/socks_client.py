import logging
import random
import select
import socket

import more_itertools

from dns_tunnel.consts import PROXY_CLIENT_ADDRESS, PROXY_CLIENT_PORT, PROXY_SERVER_ADDRESS, PROXY_SERVER_PORT
from dns_tunnel.protocol import DNSPacket
from dns_tunnel.selectables.tcp_client_socket import TCPClientSocket
from dns_tunnel.socks_handlers.base_handler import BaseHandler

# Initialize logger
logging.basicConfig(level=logging.DEBUG, format="Client %(module)s %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


class ClientHandler(BaseHandler):
    def __init__(self, logger: logging.Logger):
        super().__init__(logger)
        self._clients: list[TCPClientSocket] = []
        self._used_session_ids = set()

    def address(self):
        return PROXY_CLIENT_ADDRESS

    def port(self):
        return PROXY_CLIENT_PORT

    def run(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # TODO: only for dev
        server_socket.bind((PROXY_CLIENT_ADDRESS, 1080))
        server_socket.listen(5)
        self._logger.info("Sockets client: Server started and listening on port 1080")

        ingress_socket = self.init_ingress_socket(PROXY_SERVER_ADDRESS, PROXY_SERVER_PORT)
        self._rlist = [server_socket]  # On startup - only listen for new server clients

        while True:
            self._wlist = []
            if ingress_socket.needs_to_write():
                self._wlist.append(ingress_socket)

            for client in self._clients:
                if client.needs_to_write():
                    self._wlist.append(client)

            self._rlist = [server_socket, ingress_socket] + self._clients

            r_ready, w_ready, _ = select.select(self._rlist, self._wlist, [])

            # Accept new clients as needed
            if server_socket in r_ready:
                tcp_client, _ = server_socket.accept()
                self._logger.info("Accepted new TCP client")
                # tcp_client.setblocking(False) # TODO: ????
                self._clients.append(
                    TCPClientSocket(
                        tcp_client,
                        self._get_session_id(),
                    )
                )

            if ingress_socket in r_ready:
                msgs = ingress_socket.read()
                for msg in msgs:
                    self._handle_incoming_ingress_message(ingress_socket, msg)

            # Read from tcp clients, and queue messages for sending
            read_ready_clients = [ready for ready in r_ready if ready in self._clients]
            for read_ready_client in read_ready_clients:
                # read as much as possible, non blocking
                data = read_ready_client.read()

                if not data:
                    self._logger.info(f"Client {read_ready_client.session_id} closed")
                    self._clients.remove(read_ready_client)
                    continue

                self._logger.debug(f"Read data from client {read_ready_client.session_id}: {data}")
                for chunk in more_itertools.chunked(data, DNSPacket.MAX_PAYLOAD):
                    ingress_socket.add_to_write_queue(bytes(chunk), read_ready_client.session_id)

            write_ready_clients = [ready for ready in w_ready if ready in self._clients]
            for write_ready_client in write_ready_clients:
                write_ready_client.write()
                self._logger.debug(f"Sent data for client {write_ready_client.session_id}")
            if ingress_socket in w_ready:
                ingress_socket.write()

    def get_edge_by_session_id(self, session_id: int) -> TCPClientSocket:
        return self._get_client_by_session_id(session_id)

    def remove_edge_by_session_id(self, session_id: int) -> None:
        ...

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

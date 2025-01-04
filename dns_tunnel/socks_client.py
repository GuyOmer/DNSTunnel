import logging
import os
import select
import socket

import more_itertools

from dns_tunnel.protocol import DNSPacket, MessageType, create_ack_message
from dns_tunnel.selectables.proxy_socket import ProxySocket
from dns_tunnel.selectables.tcp_client_socket import TCPClientSocket

# Initialize logger
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# TODO: CHange defaults
PROXY_SERVER_ADDRESS = os.getenv("PROXY_SERVER_ADDRESS", "dns-server")
PROXY_SERVER_PORT = int(os.getenv("PROXY_SERVER_PORT", "53"))
PROXY_CLIENT_ADDRESS = os.getenv("PROXY_CLIENT_ADDRESS", "dns-server")
PROXY_CLIENT_PORT = int(os.getenv("PROXY_CLIENT_PORT", "53"))


class ClientHandler:
    def __init__(self):
        self._rlist = []
        self._wlist = []
        self._clients: list[TCPClientSocket] = []
        self._session_id_counter = 0

    def run(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # TODO: only for dev
        server_socket.bind(("0.0.0.0", 1080))
        server_socket.listen(5)
        logger.info("Sockets client: Server started and listening on port 1080")

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", PROXY_CLIENT_PORT))
        ingress_socket = ProxySocket(
            s,
            (PROXY_SERVER_ADDRESS, PROXY_SERVER_PORT),
        )
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
                logger.info("Accepted new TCP client")
                # tcp_client.setblocking(False) # TODO: ????
                self._clients.append(
                    TCPClientSocket(
                        tcp_client,
                        self._session_id_counter,
                        # _,
                    )
                )
                self._session_id_counter += 1

            # Read from tcp clients, and queue messages for sending
            read_ready_clients = [ready for ready in r_ready if ready in self._clients]
            for read_ready_client in read_ready_clients:
                # read as much as possible, non blocking
                data = read_ready_client.read()
                logger.debug(f"Read data from client {read_ready_client.session_id}: {data}")
                for chunk in more_itertools.chunked(data, DNSPacket.MAX_PAYLOAD):
                    chunk_bytes = bytes(chunk)
                    ingress_socket.queue_to_session(chunk_bytes, read_ready_client.session_id)

            if ingress_socket in r_ready:
                msgs = ingress_socket.read()
                for msg in msgs:
                    client = self._get_client_by_session_id(msg.header.session_id)
                    if msg.header.message_type == MessageType.ACK_MESSAGE:
                        ingress_socket.ack_message(msg.header.session_id, msg.header.sequence_number)
                        continue
                    ingress_socket.add_to_write_queue(
                        create_ack_message(msg.header.session_id, msg.header.sequence_number).to_bytes()
                    )
                    client.add_to_write_queue(msg.payload)
                    logger.debug(f"Queued message for client {client.session_id}: {msg.payload}")

            write_ready_clients = [ready for ready in w_ready if ready in self._clients]
            for write_ready_client in write_ready_clients:
                write_ready_client.write()
                logger.debug(f"Sent data for client {write_ready_client.session_id}")
            if ingress_socket in w_ready:
                ingress_socket.write()
                logger.debug("Sent data to ingress socket")

    def _get_client_by_session_id(self, session_id):
        for client in self._clients:
            if client.session_id == session_id:
                return client


if __name__ == "__main__":
    ClientHandler().run()

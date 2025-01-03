import select
import socket

import more_itertools

from dns_tunnel.protocol import DNSPacket, MessageType, create_ack_message
from dns_tunnel.selectables.proxy_socket import ProxySocket
from dns_tunnel.selectables.tcp_client_socket import TCPClientSocket


class ClientHandler:
    def __init__(self):
        self._rlist = []
        self._wlist = []
        self._clients: list[TCPClientSocket] = []
        self._session_id_counter = 0

    def run(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(("0.0.0.0", 1080))
        server_socket.listen(5)

        ingress_socket = ProxySocket(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        self._rlist = [server_socket]  # On startup - only listen for new server clients

        while True:
            if ingress_socket.needs_to_write():
                self._wlist.append(ingress_socket)

            r_ready, w_ready, _ = select.select(self._rlist, self._wlist, [])

            # Accept new clients as needed
            if server_socket in r_ready:
                tcp_client, _ = server_socket.accept()
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
                for chunk in more_itertools.chunked(data, DNSPacket.MAX_PAYLOAD):
                    ingress_socket.queue_to_session(chunk, read_ready_client.session_id)

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

            write_ready_clients = [ready for ready in w_ready if ready in self._clients or ready == ingress_socket]
            for write_ready_client in write_ready_clients:
                write_ready_client.write()

    # def _handle_by_type(self, sock: TunnelSocket | TCPClientSocket):
    #     match type(sock):
    #         case TunnelSocket():
    #             self._handle_tunnel_by_state(sock)
    #         case TCPClientSocket():
    #             ...
    #         case _ as t:
    #             raise TypeError(f"Handling '{t}' is not supported")

    # def _handle_tcp_client_by_state(self, tcp_client: TunnelSocket):
    #     match tcp_client.get_state():
    #         case TCPClientSocketState.ACCEPTED:
    #             self._rlist.append(tcp_client)
    #             tcp_client.set_state(TCPClientSocket.PENDING_GREET_MESSAGE)

    #         case TCPClientSocket.PENDING_GREET_MESSAGE:
    #             tcp_client.read(3)  # Should be greet message
    #             # TODO: assert
    #             tcp_client.add_to_write_queue(get_greet_response_message())
    #             self._wlist.append(tcp_client)
    #             tcp_client.set_state(TCPClientSocket.PENDING_TO_SET_GREET_RESPONSE)

    #         case TCPClientSocket.PENDING_TO_SET_GREET_RESPONSE:
    #             tcp_client.write()  # Assume we sent the entire greet response
    #             tcp_client.set_state(TCPClientSocketState.PENDING_CONNECT_REQUEST)
    #             self._rlist.append(tcp_client)
    #         case TCPClientSocketState.PENDING_CONNECT_REQUEST:
    #             host, port = tcp_client.read(10)
    #             # assert valid connect request

    # def _handle_tunnel_by_state(self, tunnel: TunnelSocket):
    #     match tunnel.get_state():
    #         case TunnelSocketState.ACCEPTED:
    #             greet_message = get_socks_greeting_message()
    #             tunnel.add_to_write_queue(greet_message)
    #             self._wlist.append(tunnel)
    #             tunnel.set_state(TunnelSocketState.PENDING_GREETING_TRANSMISSION)

    #         # Should be write ready
    #         case TunnelSocketState.PENDING_GREETING_TRANSMISSION:
    #             tunnel.write()  # Assume entire greeting was sent

    #             self._rlist.append(tunnel)
    #             tunnel.set_state(TunnelSocketState.PENDING_GREETING_ACK)

    #         # Should be read ready
    #         case TunnelSocketState.PENDING_GREETING_ACK:
    #             tunnel.read(2)  # read_greet_ack
    #             # assert socks 5 greet

    #             # Queue connect message

    # def _handle_accepted_tcp_client(self, tcp_client: socket):
    #     selectable_tcp_client = TCPClientSocket(tcp_client, TCPClientSocketState.SETTING_UP_TUNNEL)
    #     tunnel = TunnelSocket(
    #         socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
    #         TunnelSocketState.ACCEPTED,
    #     )
    #     self._tcp_client_to_tunnel[selectable_tcp_client] = tunnel
    #     self._handle_by_type(selectable_tcp_client)
    #     # self._handle_by_type(tunnel)

    def _get_client_by_session_id(self, sessoin_id):
        for client in self._clients:
            if client.session_id == sessoin_id:
                return client


if __name__ == "__main__":
    ClientHandler().run()

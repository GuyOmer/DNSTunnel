import select
import socket

import more_itertools

from dns_tunnel.protocol import DNSPacket, MessageType, create_ack_message
from dns_tunnel.selectables.proxy_socket import ProxySocket
from dns_tunnel.selectables.tcp_client_socket import TCPClientSocket

## client -> serve
# https://medium.com/@nimit95/socks-5-a-proxy-protocol-b741d3bec66c
# def perform_socks5_handshake(server_ip: str, domain_name: str, socks_server_ip: str, socks_server_port: int) -> None:
#     """
#     Performs a SOCKS5 handshake using DNS queries to send the handshake payload.

#     :param server_ip: The IP address of the DNS server (e.g., '8.8.8.8').
#     :param domain_name: The domain name to query.
#     :param socks_server_ip: The IP address of the SOCKS5 server.
#     :param socks_server_port: The port of the SOCKS5 server.
#     """

#     with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
#         sock.bind(("0.0.0.0", 13132))
#         print("Waiting for SOCKS5 responses...")

#         # Receive and validate greeting response
#         data, _ = sock.recvfrom(2)
#     # SOCKS5 greeting (version 5, 1 authentication method, no authentication)
#     greeting = bytes([0x05, 0x01, 0x00])
#     send_custom_dns_query(server_ip, domain_name, greeting)

#     # SOCKS5 connection request (version 5, connect command, reserved, address type IPv4, target IP and port)
#     address_bytes = bytes(map(int, socks_server_ip.split(".")))
#     port_bytes = socks_server_port.to_bytes(2, "big")
#     connection_request = bytes([0x05, 0x01, 0x00, 0x01]) + address_bytes + port_bytes
#     send_custom_dns_query(server_ip, domain_name, connection_request)


class ClientHandler:
    def __init__(self):
        self._rlist = []
        self._wlist = []
        self._clients: list[TCPClientSocket] = []
        self._session_id_counter = 0

    def run(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(("0.0.0.0", 1080))

        proxy_socket = ProxySocket(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))

        # self._rlist = [server_socket, proxy_socket] + self._clients
        self._rlist = [server_socket]  # On startup - only listen for new server clients

        while True:
            if proxy_socket.needs_to_write():
                self._wlist.append(proxy_socket)

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
                    proxy_socket.queue_to_session(chunk, read_ready_client.session_id)

            if proxy_socket in r_ready:
                msgs = proxy_socket.read()
                for msg in msgs:
                    client = self._get_client_by_session_id(msg.header.session_id)
                    if msg.header.message_type == MessageType.ACK_MESSAGE:
                        proxy_socket.ack_message(msg.header.session_id, msg.header.sequence_number)
                        continue
                    # TODO: check if it is the expected sequence
                    proxy_socket.add_to_write_queue(
                        create_ack_message(msg.header.session_id, msg.header.sequence_number).to_bytes()
                    )
                    client.add_to_write_queue(msg.payload)

            write_ready_clients = [ready for ready in w_ready if ready in self._clients or ready == proxy_socket]
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


def main():
    pass


if __name__ == "__main__":
    # Example usage
    dns_server = "8.8.8.8"  # Google's public DNS server
    domain = "example.com"
    socks_server = "192.168.1.100"  # Example SOCKS5 server IP
    socks_port = 1080  # Example SOCKS5 server port

    perform_socks5_handshake(dns_server, domain, socks_server, socks_port)

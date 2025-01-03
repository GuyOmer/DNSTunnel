import select
import socket
import struct
from typing import Final

from dns_tunnel.protocol import create_ack_message
from dns_tunnel.selectables.proxy_socket import ProxySocket
from dns_tunnel.selectables.tcp_client_socket import TCPClientSocket
from dns_tunnel.socks5_protocol import SOCKS5Greeting

def int_to_bytes(*ints) -> bytes:
    return b''.join(int(i).to_bytes() for i in ints)

# SOCKS5_GREETING: Final = int_to_bytes(5,1,0) # Use SOCKS v5, 1 auth method, (which is) "no-auth"
# SOCKS5_GREETING_ACK:Final = int_to_bytes(5,0) # ACK using SOCKS v5, chosen auth method is "no-auth"
# # 5 (SOCKS v5), 1 (establish a TCP/IP stream connection), 0 (reserved), 1 (IPv4 address), <HOST>, <PORT>
# SOCKS5_CONNECT_REQUEST_PREAMBLE:Final = int_to_bytes(5,1,0,1) 
# # 5 (SOCKS v5), 0 (request granted), 0 (reserved), 1 (IPv4 address), <HOST>, <PORT>
# SOCKS5_CONNECT_RESPONSE_PREAMBLE:Final = int_to_bytes(5,0,0,1) # 5, 0, 0, 1, <HOST>, <PORT>

def receive_socks5_handshake_response(server_ip: str) -> tuple[bytes, bytes]:
    """
    Receives the SOCKS5 handshake responses (greeting and connection response).

    :param server_ip: The IP address of the DNS server (e.g., '8.8.8.8').
    :return: A tuple containing the greeting response and connection response as bytes.
    """
    # Create a UDP socket to receive data
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((server_ip, 13131))
        print("Waiting for SOCKS5 responses...")

        # Receive and validate greeting response
        data, _ = sock.recvfrom(2)  # SOCKS5 greeting is 2 bytes
        if data != SOCKS5_GREETINT:
            raise ValueError(f"Invalid SOCKS5 greeting response: {data}")

        print(f"Received valid SOCKS5 greeting response: {data}")
        # greeting_response = data

        sock.send

        # Receive and validate connection response
        data, _ = sock.recvfrom(10)  # Minimum size for SOCKS5 connection response
        if len(data) < 10 or data[0] != 0x05 or data[1] != 0x00:
            raise ValueError(f"Invalid SOCKS5 connection response: {data}")
        print(f"Received valid SOCKS5 connection response: {data}")

        # Parse the address and port from the connection response
        address_type = data[3]
        if address_type == 0x01:  # IPv4
            address = ".".join(map(str, data[4:8]))
            port = struct.unpack("!H", data[8:10])[0]
        else:
            raise ValueError(
                f"Unsupported address type in SOCKS5 response: {address_type}"
            )

        print(f"Parsed address: {address}, port: {port}")
        connection_response = (address, port)

    return connection_response


class ProxyServerHandler:
    def __init__(self):
        self._rlist = []
        self._wlist = []
        self._destinations: list[TCPClientSocket] = []

        # self._tcp_destination_to_tunnel: dict[TCPClientSocket, TunnelSocket] = {}
        self._session_id_to_destination: dict[int, TCPClientSocket] = {}
        # self._session_id_counter = 0

    def run(self):
        ingress = ProxySocket(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        self._rlist.append(ingress)

        while True:
            r_ready, w_ready, _ = select.select(self._rlist, self._wlist, [])

            if ingress in self._rlist:
                msgs = ingress.read()

                for msg in msgs:
                    # Add ack to send queue
                    ingress.add_to_write_queue(
                        create_ack_message(
                            msg.header.session_id,
                            msg.header.sequence_number,
                        )
                    )

                    # Handle the message
                    if msg.header.session_id not in self._session_id_to_destination:
                        # Still initializing socks5
                        if SOCKS5Greeting.from_bytes(msg.payload))
                    else:
                        # proxy tunnel already setup, just forward messages
                        destination = self._session_id_to_destination[
                            msg.header.session_id
                        ]
                        destination.add_to_write_queue(msg.payload)

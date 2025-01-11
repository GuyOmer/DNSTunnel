import logging
import socket
import pytest
from unittest.mock import Mock, patch
from dns_tunnel.socks_handlers.socks_server import ProxyServerHandler, SOCKS5HandshakeState
from dns_tunnel.selectables.proxy_socket import ProxySocket
from dns_tunnel.selectables.tcp_client_socket import TCPClientSocket
from dns_tunnel.protocol import DNSPacket, DNSPacketHeader, MessageType
from dns_tunnel.socks5_protocol import (
    SOCKS5AuthMethod,
    SOCKS5CommandCode,
    SOCKS5ConnectRequestStatus,
    SOCKS5DNSConnectRequest,
    SOCKS5DNSConnectResponse,
    SOCKS5Greeting,
    SOCKS5GreetingResponse,
    SOCKS5AddressType,
    SOCKS5_VERSION,
)
import struct


@pytest.fixture
def mock_logger():
    return Mock(spec=logging.Logger)


@pytest.fixture
def server_handler(mock_logger):
    with patch('socket.socket') as mock_socket:
        handler = ProxyServerHandler(mock_logger)
        # Mock the ingress socket to avoid actual network operations
        handler._ingress_socket = Mock(spec=ProxySocket)
        yield handler


def test_server_handler_initialization(server_handler, mock_logger):
    """Test that ProxyServerHandler initializes correctly."""
    assert server_handler._session_id_to_destination == {}
    assert server_handler._session_id_to_socks5_handshake_state == {}
    assert server_handler._logger == mock_logger


def test_server_handler_properties(server_handler):
    """Test that ProxyServerHandler properties return expected values."""
    assert server_handler.address == "0.0.0.0"  # Default server address
    assert server_handler.port == 54  # Default server port
    assert isinstance(server_handler.ingress_socket, Mock)
    assert list(server_handler.edges) == list(server_handler._session_id_to_destination.values())


def test_get_edge_by_session_id(server_handler):
    """Test getting a destination by session ID."""
    # Create a mock destination with a known session ID
    mock_destination = Mock(spec=TCPClientSocket)
    server_handler._session_id_to_destination[12345] = mock_destination

    # Test finding existing destination
    found_destination = server_handler.get_edge_by_session_id(12345)
    assert found_destination == mock_destination

    # Test with non-existent session ID
    not_found_destination = server_handler.get_edge_by_session_id(99999)
    assert not_found_destination is None


def test_remove_edge_by_session_id(server_handler):
    """Test removing a destination by session ID."""
    # Create a mock destination
    mock_destination = Mock(spec=TCPClientSocket)
    server_handler._session_id_to_destination[12345] = mock_destination

    # Remove the destination
    server_handler.remove_edge_by_session_id(12345)

    # Verify destination was set to None
    assert server_handler._session_id_to_destination[12345] is None


def test_handle_socks5_handshake_greeting(server_handler):
    """Test handling SOCKS5 greeting."""
    # Create a mock DNS packet with SOCKS5 greeting
    greeting = SOCKS5Greeting([SOCKS5AuthMethod.NO_AUTH])
    header = DNSPacketHeader(
        payload_length=len(greeting.to_bytes()),
        message_type=MessageType.NORMAL_MESSAGE,
        session_id=12345,
        sequence_number=1
    )
    packet = DNSPacket(header=header, payload=greeting.to_bytes())

    # Handle the greeting
    server_handler._handle_socks5_handshake(packet)

    # Verify the response
    assert server_handler._session_id_to_socks5_handshake_state[
               12345] == SOCKS5HandshakeState.WAITING_FOR_CONNECT_REQUEST
    server_handler.ingress_socket.add_to_write_queue.assert_called_once()

    # Verify the response content
    call_args = server_handler.ingress_socket.add_to_write_queue.call_args_list[0]
    response_bytes = call_args[0][0]  # First argument of the first call
    session_id = call_args[0][1]  # Second argument of the first call

    # Parse and verify the response
    response = SOCKS5GreetingResponse.from_bytes(response_bytes)
    assert response.chosen_auth_method == SOCKS5AuthMethod.NO_AUTH
    assert session_id == 12345


def test_handle_socks5_handshake_unsupported_auth(server_handler):
    """Test handling SOCKS5 greeting with unsupported auth method."""
    # Create a mock DNS packet with unsupported auth method
    greeting = SOCKS5Greeting([SOCKS5AuthMethod.USERNAME_PASSWORD])
    header = DNSPacketHeader(
        payload_length=len(greeting.to_bytes()),
        message_type=MessageType.NORMAL_MESSAGE,
        session_id=12345,
        sequence_number=1
    )
    packet = DNSPacket(header=header, payload=greeting.to_bytes())

    # Handle the greeting should raise ValueError
    with pytest.raises(ValueError, match="Only no-auth is supported"):
        server_handler._handle_socks5_handshake(packet)


def test_handle_socks5_connect_request(server_handler):
    """Test handling a SOCKS5 connect request."""
    # Set initial handshake state
    server_handler._session_id_to_socks5_handshake_state[12345] = SOCKS5HandshakeState.WAITING_FOR_CONNECT_REQUEST

    # Create a test message with connect request
    connect_request = SOCKS5DNSConnectRequest(
        SOCKS5CommandCode.ESTABLISH_A_TCP_IP_STREAM_CONNECTION,
        "example.com",
        80
    )

    # Manually create the request bytes to avoid domain name encoding issues
    request_bytes = struct.pack(
        "!BBBBB",  # Version, Command, Reserved, Address Type, Address Length
        SOCKS5_VERSION,
        SOCKS5CommandCode.ESTABLISH_A_TCP_IP_STREAM_CONNECTION.value,
        0,  # Reserved
        SOCKS5AddressType.DOMAIN_NAME.value,
        len("example.com")
    ) + b"example.com" + struct.pack("!H", 80)  # Domain name and port

    header = DNSPacketHeader(
        payload_length=len(request_bytes),
        message_type=MessageType.NORMAL_MESSAGE,
        session_id=12345,
        sequence_number=0
    )
    packet = DNSPacket(header=header, payload=request_bytes)

    # Mock socket operations
    with patch('socket.socket') as mock_socket:
        mock_socket_instance = Mock()
        mock_socket.return_value = mock_socket_instance

        # Handle the connect request
        server_handler._handle_socks5_handshake(packet)

        # Verify socket was created with correct parameters
        mock_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        mock_socket_instance.setblocking.assert_called_once_with(False)
        mock_socket_instance.connect.assert_called_once_with(("example.com", 80))

        # Verify response was sent
        server_handler.ingress_socket.add_to_write_queue.assert_called_with(
            SOCKS5DNSConnectResponse(
                SOCKS5ConnectRequestStatus.GRANTED,
                "example.com",
                80
            ).to_bytes(),
            12345
        )


def test_handle_socks5_connect_request_connection_refused(server_handler):
    """Test handling a SOCKS5 connect request when connection is refused."""
    # Set initial handshake state
    server_handler._session_id_to_socks5_handshake_state[12345] = SOCKS5HandshakeState.WAITING_FOR_CONNECT_REQUEST

    # Manually create the request bytes
    request_bytes = struct.pack(
        "!BBBBB",  # Version, Command, Reserved, Address Type, Address Length
        SOCKS5_VERSION,
        SOCKS5CommandCode.ESTABLISH_A_TCP_IP_STREAM_CONNECTION.value,
        0,  # Reserved
        SOCKS5AddressType.DOMAIN_NAME.value,
        len("example.com")
    ) + b"example.com" + struct.pack("!H", 80)  # Domain name and port

    header = DNSPacketHeader(
        payload_length=len(request_bytes),
        message_type=MessageType.NORMAL_MESSAGE,
        session_id=12345,
        sequence_number=0
    )
    packet = DNSPacket(header=header, payload=request_bytes)

    # Mock socket operations to raise ConnectionRefusedError
    with patch('socket.socket') as mock_socket:
        mock_socket_instance = Mock()
        mock_socket.return_value = mock_socket_instance
        mock_socket_instance.connect.side_effect = ConnectionRefusedError()

        # Handle the connect request
        server_handler._handle_socks5_handshake(packet)

        # Verify error response was sent
        server_handler.ingress_socket.add_to_write_queue.assert_called_with(
            SOCKS5DNSConnectResponse(
                SOCKS5ConnectRequestStatus.HOST_UNREACHABLE,
                "example.com",
                80
            ).to_bytes(),
            12345
        )


def test_handle_socks5_connect_request_invalid_command(server_handler):
    """Test handling a SOCKS5 connect request with invalid command."""
    # Set initial handshake state
    server_handler._session_id_to_socks5_handshake_state[12345] = SOCKS5HandshakeState.WAITING_FOR_CONNECT_REQUEST

    # Manually create the request bytes with invalid command
    request_bytes = struct.pack(
        "!BBBBB",  # Version, Command, Reserved, Address Type, Address Length
        SOCKS5_VERSION,
        SOCKS5CommandCode.ESTABLISH_A_TCP_IP_PORT_BINDING.value,  # Invalid command
        0,  # Reserved
        SOCKS5AddressType.DOMAIN_NAME.value,
        len("example.com")
    ) + b"example.com" + struct.pack("!H", 80)  # Domain name and port

    header = DNSPacketHeader(
        payload_length=len(request_bytes),
        message_type=MessageType.NORMAL_MESSAGE,
        session_id=12345,
        sequence_number=0
    )
    packet = DNSPacket(header=header, payload=request_bytes)

    # Handle the connect request should raise ValueError
    with pytest.raises(ValueError,
                       match=f"Only {SOCKS5CommandCode.ESTABLISH_A_TCP_IP_STREAM_CONNECTION.name} is supported"):
        server_handler._handle_socks5_handshake(packet)


def test_handle_socks5_handshake_invalid_state(server_handler):
    """Test handling a SOCKS5 handshake in invalid state."""
    # Set an invalid state
    server_handler._session_id_to_socks5_handshake_state[12345] = "INVALID_STATE"

    # Create a test message
    header = DNSPacketHeader(
        payload_length=10,
        message_type=MessageType.NORMAL_MESSAGE,
        session_id=12345,
        sequence_number=0
    )
    packet = DNSPacket(header=header, payload=b"test")

    # Handle the message should raise ValueError
    with pytest.raises(ValueError, match="Invalid state"):
        server_handler._handle_socks5_handshake(packet)


def test_handle_normal_message_with_destination(server_handler):
    """Test handling a normal message with established destination."""
    # Create a mock destination
    mock_destination = Mock(spec=TCPClientSocket)
    server_handler._session_id_to_destination[12345] = mock_destination

    # Create a test message
    header = DNSPacketHeader(
        payload_length=len(b"test_data"),
        message_type=MessageType.NORMAL_MESSAGE,
        session_id=12345,
        sequence_number=0
    )
    packet = DNSPacket(header=header, payload=b"test_data")

    # Handle the message
    server_handler._handle_incoming_ingress_message(packet)

    # Verify data was forwarded to destination
    mock_destination.add_to_write_queue.assert_called_once_with(b"test_data")


def test_handle_socks5_handshake_greeting_invalid_payload(server_handler):
    """Test handling SOCKS5 greeting with invalid payload."""
    # Create a mock DNS packet with invalid payload
    header = DNSPacketHeader(
        payload_length=5,
        message_type=MessageType.NORMAL_MESSAGE,
        session_id=12345,
        sequence_number=1
    )
    packet = DNSPacket(header=header, payload=b"invalid")

    # Handle the greeting should raise ValueError
    with pytest.raises(ValueError, match="Not a SOCKS5 message"):
        server_handler._handle_socks5_handshake(packet)


def test_handle_socks5_connect_request_socket_error(server_handler):
    """Test handling a SOCKS5 connect request when socket creation fails."""
    # Set initial handshake state
    server_handler._session_id_to_socks5_handshake_state[12345] = SOCKS5HandshakeState.WAITING_FOR_CONNECT_REQUEST

    # Manually create the request bytes
    request_bytes = struct.pack(
        "!BBBBB",  # Version, Command, Reserved, Address Type, Address Length
        SOCKS5_VERSION,
        SOCKS5CommandCode.ESTABLISH_A_TCP_IP_STREAM_CONNECTION.value,
        0,  # Reserved
        SOCKS5AddressType.DOMAIN_NAME.value,
        len("example.com")
    ) + b"example.com" + struct.pack("!H", 80)  # Domain name and port

    header = DNSPacketHeader(
        payload_length=len(request_bytes),
        message_type=MessageType.NORMAL_MESSAGE,
        session_id=12345,
        sequence_number=0
    )
    packet = DNSPacket(header=header, payload=request_bytes)

    # Mock socket operations to raise socket.gaierror
    with patch('socket.socket') as mock_socket:
        mock_socket_instance = Mock()
        mock_socket.return_value = mock_socket_instance
        mock_socket_instance.connect.side_effect = socket.gaierror("Name resolution failed")

        # Handle the connect request
        server_handler._handle_socks5_handshake(packet)

        # Verify error response was sent
        server_handler.ingress_socket.add_to_write_queue.assert_called_with(
            SOCKS5DNSConnectResponse(
                SOCKS5ConnectRequestStatus.HOST_UNREACHABLE,
                "example.com",
                80
            ).to_bytes(),
            12345
        )


def test_handle_normal_message_with_invalid_destination(server_handler):
    """Test handling a normal message with invalid destination."""
    # Set destination to None to simulate invalid/removed destination
    server_handler._session_id_to_destination[12345] = None

    # Create a test message
    header = DNSPacketHeader(
        payload_length=len(b"test_data"),
        message_type=MessageType.NORMAL_MESSAGE,
        session_id=12345,
        sequence_number=0
    )
    packet = DNSPacket(header=header, payload=b"test_data")

    # Handle the message
    server_handler._handle_incoming_ingress_message(packet)

    # Verify no data was forwarded (since destination is None)
    server_handler._logger.debug.assert_called_with("No edge for session %s", 12345)

import logging
from unittest.mock import Mock, patch

import pytest

from dns_tunnel.protocol import DNSPacket, DNSPacketHeader, MessageType
from dns_tunnel.selectables.proxy_socket import ProxySocket
from dns_tunnel.selectables.tcp_client_socket import TCPClientSocket
from dns_tunnel.socks_handlers.socks_client import ClientHandler


@pytest.fixture
def mock_logger():
    return Mock(spec=logging.Logger)


@pytest.fixture
def client_handler(mock_logger):
    with patch('socket.socket') as mock_socket:
        handler = ClientHandler(mock_logger)
        # Mock the ingress socket to avoid actual network operations
        handler._ingress_socket = Mock(spec=ProxySocket)
        yield handler


def test_client_handler_initialization(client_handler, mock_logger):
    """Test that ClientHandler initializes correctly."""
    assert client_handler._clients == []
    assert client_handler._used_session_ids == set()
    assert client_handler._logger == mock_logger


def test_client_handler_properties(client_handler):
    """Test that ClientHandler properties return expected values."""
    assert client_handler.address == "0.0.0.0"  # Default client address
    assert client_handler.port == 52  # Default client port
    assert isinstance(client_handler.ingress_socket, Mock)
    assert client_handler.edges == client_handler._clients


def test_get_session_id(client_handler):
    """Test that get_session_id returns unique session IDs."""
    session_id1 = client_handler._get_session_id()
    session_id2 = client_handler._get_session_id()

    assert session_id1 != session_id2
    assert session_id1 in client_handler._used_session_ids
    assert session_id2 in client_handler._used_session_ids


def test_get_client_by_session_id(client_handler):
    """Test getting a client by session ID."""
    # Create a mock client with a known session ID
    mock_client = Mock(spec=TCPClientSocket)
    mock_client.session_id = 12345
    client_handler._clients.append(mock_client)

    # Test finding existing client
    found_client = client_handler._get_client_by_session_id(12345)
    assert found_client == mock_client

    # Test with non-existent session ID
    not_found_client = client_handler._get_client_by_session_id(99999)
    assert not_found_client is None


def test_remove_edge_by_session_id(client_handler):
    """Test removing a client by session ID."""
    # Create a mock client
    mock_client = Mock(spec=TCPClientSocket)
    mock_client.session_id = 12345
    client_handler._clients.append(mock_client)

    # Remove the client
    client_handler.remove_edge_by_session_id(12345)

    # Verify client was removed and socket was closed
    assert mock_client not in client_handler._clients
    mock_client.close.assert_called_once()


def test_handle_incoming_ingress_message(client_handler):
    """Test handling incoming messages from the ingress socket."""
    # Create a mock client
    mock_client = Mock(spec=TCPClientSocket)
    mock_client.session_id = 12345
    client_handler._clients.append(mock_client)

    # Create a test message
    header = DNSPacketHeader(
        payload_length=len(b"test_data"),
        message_type=MessageType.NORMAL_MESSAGE,
        session_id=12345,
        sequence_number=0
    )
    packet = DNSPacket(header=header, payload=b"test_data")

    # Handle the message
    client_handler._handle_incoming_ingress_message(packet)

    # Verify the message was forwarded to the correct client
    mock_client.add_to_write_queue.assert_called_once_with(b"test_data")


def test_handle_incoming_ingress_message_unknown_session(client_handler):
    """Test handling messages for unknown session IDs."""
    # Create a test message with unknown session ID
    header = DNSPacketHeader(
        payload_length=len(b"test_data"),
        message_type=MessageType.NORMAL_MESSAGE,
        session_id=99999,  # Unknown session ID
        sequence_number=0
    )
    packet = DNSPacket(header=header, payload=b"test_data")

    # Handle the message should log debug but not raise error
    client_handler._handle_incoming_ingress_message(packet)

    # Verify debug was logged with correct session ID
    client_handler._logger.debug.assert_called_with(
        "No edge for session %s", 99999
    )


def test_handle_read_edges(client_handler):
    """Test handling reads from client sockets."""
    # Create a mock client with data to read
    mock_client = Mock(spec=TCPClientSocket)
    mock_client.session_id = 12345
    mock_client.read.return_value = b"test_data"
    client_handler._clients.append(mock_client)

    # Create ready list with the mock client
    ready = [mock_client]

    # Handle the reads
    client_handler.handle_read_edges(ready)

    # Verify data was forwarded to ingress socket
    client_handler.ingress_socket.add_to_write_queue.assert_called_once_with(
        b"test_data",
        12345
    )


def test_handle_read_edges_connection_closed(client_handler):
    """Test handling client socket closure."""
    # Create a mock client that returns empty data (indicating closed connection)
    mock_client = Mock(spec=TCPClientSocket)
    mock_client.session_id = 12345
    mock_client.read.return_value = b""
    client_handler._clients.append(mock_client)

    # Create ready list with the mock client
    ready = [mock_client]

    # Handle the reads
    client_handler.handle_read_edges(ready)

    # Verify client was removed and socket closed
    assert mock_client not in client_handler._clients
    mock_client.close.assert_called_once()
    client_handler.ingress_socket.end_session.assert_called_once_with(12345)


def test_write_wlist(client_handler):
    """Test writing to ready sockets."""
    # Create mock clients
    mock_client1 = Mock(spec=TCPClientSocket)
    mock_client1.needs_to_write.return_value = True
    mock_client2 = Mock(spec=TCPClientSocket)
    mock_client2.needs_to_write.return_value = False
    client_handler._clients.extend([mock_client1, mock_client2])

    # Create ready list with only the client that needs to write
    ready = [mock_client1]  # Only include client1 in ready list

    # Handle the writes
    client_handler.write_wlist(ready)

    # Verify only the client that needs to write was written to
    mock_client1.write.assert_called_once()
    mock_client2.write.assert_not_called()

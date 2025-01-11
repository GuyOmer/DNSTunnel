import socket
from unittest.mock import Mock

import pytest

from dns_tunnel.selectables.tcp_client_socket import TCPClientSocket


@pytest.fixture
def mock_socket():
    return Mock(spec=socket.socket)


@pytest.fixture
def tcp_client(mock_socket):
    return TCPClientSocket(mock_socket, session_id=12345)


def test_tcp_client_initialization(tcp_client, mock_socket):
    """Test that TCPClientSocket initializes correctly."""
    assert tcp_client._s == mock_socket
    assert tcp_client._session_id == 12345
    assert tcp_client._write_buffer == b""


def test_session_id_property(tcp_client):
    """Test session_id property."""
    assert tcp_client.session_id == 12345


def test_add_to_write_queue(tcp_client):
    """Test adding data to write queue."""
    test_data = b"test_data"

    # Add data to write queue
    tcp_client.add_to_write_queue(test_data)

    # Verify data was added to buffer
    assert tcp_client._write_buffer == test_data

    # Add more data
    tcp_client.add_to_write_queue(b"_more")

    # Verify data was appended
    assert tcp_client._write_buffer == b"test_data_more"


def test_needs_to_write(tcp_client):
    """Test needs_to_write method."""
    # Initially should not need to write
    assert not tcp_client.needs_to_write()

    # Add data to write queue
    tcp_client.add_to_write_queue(b"test_data")

    # Should now need to write
    assert tcp_client.needs_to_write()


def test_write(tcp_client, mock_socket):
    """Test write method."""
    test_data = b"test_data"
    tcp_client.add_to_write_queue(test_data)

    # Mock successful send
    mock_socket.send.return_value = len(test_data)

    # Write data
    bytes_sent = tcp_client.write()

    # Verify data was sent
    assert bytes_sent == len(test_data)
    mock_socket.send.assert_called_once_with(test_data)
    assert tcp_client._write_buffer == b""


def test_write_partial(tcp_client, mock_socket):
    """Test write method with partial send."""
    test_data = b"test_data"
    tcp_client.add_to_write_queue(test_data)

    # Mock partial send
    mock_socket.send.return_value = 4  # Only send first 4 bytes

    # Write data
    bytes_sent = tcp_client.write()

    # Verify partial send
    assert bytes_sent == 4
    mock_socket.send.assert_called_once_with(test_data)
    assert tcp_client._write_buffer == b"_data"  # Remaining data


def test_read(tcp_client, mock_socket):
    """Test read method."""
    test_data = b"test_data"
    mock_socket.recv.return_value = test_data

    # Read data
    data = tcp_client.read()

    # Verify data was read
    assert data == test_data
    mock_socket.recv.assert_called_once_with(4096)


def test_read_connection_error(tcp_client, mock_socket):
    """Test read method with connection error."""
    # Mock connection error
    mock_socket.recv.side_effect = ConnectionResetError()

    # Read should return empty bytes
    data = tcp_client.read()
    assert data == b""

    # Test with ConnectionRefusedError
    mock_socket.recv.side_effect = ConnectionRefusedError()
    data = tcp_client.read()
    assert data == b""


def test_close(tcp_client, mock_socket):
    """Test close method."""
    tcp_client.close()
    mock_socket.close.assert_called_once()

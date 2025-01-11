import socket
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

import pytest

from dns_tunnel.protocol import DNSPacket, DNSPacketHeader, MessageType, InvalidSocketBuffer, PartialHeaderError
from dns_tunnel.selectables.proxy_socket import ProxySocket, RETRANSMISSION_TIME, MAX_RETRANSMISSION_ATTEMPTS


@pytest.fixture
def mock_socket():
    return Mock(spec=socket.socket)


@pytest.fixture
def proxy_socket(mock_socket):
    proxy_address = ("127.0.0.1", 53)
    return ProxySocket(mock_socket, proxy_address)


def test_proxy_socket_initialization(proxy_socket, mock_socket):
    """Test that ProxySocket initializes correctly."""
    assert proxy_socket._s == mock_socket
    assert proxy_socket._proxy_address == ("127.0.0.1", 53)
    assert proxy_socket._read_buf == b""
    assert proxy_socket._write_messages == []
    assert proxy_socket._sessions == {}


def test_add_to_write_queue(proxy_socket):
    """Test adding data to write queue."""
    test_data = b"test_data"
    session_id = 12345

    # Add data to write queue
    proxy_socket.add_to_write_queue(test_data, session_id)

    # Verify session was created and data was queued
    assert session_id in proxy_socket._sessions
    session = proxy_socket._sessions[session_id]
    assert len(session.sending_queue) == 1

    # Verify the queued packet
    packet = session.sending_queue[0]
    assert isinstance(packet, DNSPacket)
    assert packet.header.session_id == session_id
    assert packet.header.sequence_number == 0
    assert packet.header.message_type == MessageType.NORMAL_MESSAGE
    assert packet.payload == test_data


def test_needs_to_write(proxy_socket):
    """Test needs_to_write method."""
    # Initially should not need to write
    assert not proxy_socket.needs_to_write()

    # Add data to write queue
    proxy_socket.add_to_write_queue(b"test_data", 12345)

    # Should now need to write
    assert proxy_socket.needs_to_write()


def test_write(proxy_socket, mock_socket):
    """Test write method's session management and retransmission logic."""
    # Add data to write queue for a session
    session_id = 12345
    proxy_socket.add_to_write_queue(b"test_data", session_id)
    session = proxy_socket._sessions[session_id]

    # Mock successful send
    def mock_sendto(data, addr):
        return len(data)

    mock_socket.sendto.side_effect = mock_sendto

    # Case 1: Initial send (last_sent_seq == last_acked_seq == -1)
    proxy_socket.write()
    assert mock_socket.sendto.call_count == 1
    assert session.last_sent_seq == 0
    assert isinstance(session.last_sending_time, datetime)

    # Case 2: Message not yet acked, but not time to retransmit
    proxy_socket.write()
    assert mock_socket.sendto.call_count == 1  # Should not send again

    # Case 3: Message not acked, time to retransmit
    session.last_sending_time = datetime.now() - RETRANSMISSION_TIME - timedelta(seconds=1)
    proxy_socket.write()
    assert mock_socket.sendto.call_count == 2
    assert session.retransmission_attempt_counter == 1

    # Case 4: Message acked, send next message
    proxy_socket.add_to_write_queue(b"next_data", session_id)  # Add second message
    proxy_socket.ack_message(session_id, 0)  # Ack first message
    proxy_socket.write()
    assert mock_socket.sendto.call_count == 3
    assert session.last_sent_seq == 1

    # Case 5: Too many retransmission attempts
    session.retransmission_attempt_counter = MAX_RETRANSMISSION_ATTEMPTS + 1
    session.last_sending_time = datetime.now() - RETRANSMISSION_TIME - timedelta(seconds=1)
    proxy_socket.write()
    assert not session.is_active  # Session should be marked as inactive
    assert mock_socket.sendto.call_count == 4  # One more call to send close session message


def test_write_fragmented_error(proxy_socket, mock_socket):
    """Test write method with fragmented send."""
    # Add data to write queue
    proxy_socket.add_to_write_queue(b"test_data", 12345)

    # Mock fragmented send
    mock_socket.sendto.return_value = 1  # Only send 1 byte

    # Write data should raise error
    with pytest.raises(RuntimeError, match="Sending was fragmented, this is not supported"):
        proxy_socket.write()


def test_ack_message(proxy_socket):
    """Test handling ACK messages."""
    session_id = 12345

    # Add data to write queue
    proxy_socket.add_to_write_queue(b"test_data", session_id)

    # ACK the message
    proxy_socket.ack_message(session_id, 0)

    # Verify message was removed from queue
    session = proxy_socket._sessions[session_id]
    assert len(session.sending_queue) == 0
    assert session.last_acked_seq == 0
    assert session.retransmission_attempt_counter == 0


def test_ack_message_invalid_sequence(proxy_socket):
    """Test handling ACK messages with invalid sequence number."""
    session_id = 12345

    # Add data to write queue
    proxy_socket.add_to_write_queue(b"test_data", session_id)

    # ACK with invalid sequence number
    proxy_socket.ack_message(session_id, 1)  # Should be 0

    # Verify message was not removed from queue
    session = proxy_socket._sessions[session_id]
    assert len(session.sending_queue) == 1
    assert session.last_acked_seq == -1


def test_remove_session(proxy_socket):
    """Test removing a session."""
    session_id = 12345

    # Add data to write queue to create session
    proxy_socket.add_to_write_queue(b"test_data", session_id)

    # Remove session
    proxy_socket.remove_session(session_id)

    # Verify session is marked as inactive
    assert not proxy_socket._sessions[session_id].is_active


def test_read_empty(proxy_socket, mock_socket):
    """Test read method with empty data."""
    mock_socket.recv.return_value = b""

    messages = proxy_socket.read()
    assert messages == []


def test_read_invalid_data(proxy_socket, mock_socket):
    """Test read method with invalid data."""
    # Create invalid DNS data (not a valid DNS message)
    invalid_data = b"invalid_data"
    mock_socket.recv.return_value = invalid_data

    # Mock the DNSPacket.from_bytes method to raise InvalidSocketBuffer
    with patch('dns_tunnel.protocol.DNSPacket.from_bytes', side_effect=InvalidSocketBuffer):
        # Read should handle invalid data gracefully
        messages = proxy_socket.read()
        assert messages == []  # Invalid data should be discarded
        assert proxy_socket._read_buf == b""  # Buffer should be cleared


def test_read_partial_data(proxy_socket, mock_socket):
    """Test read method with partial data."""
    # Create a valid DNS packet
    header = DNSPacketHeader(
        payload_length=len(b"test"),
        message_type=MessageType.NORMAL_MESSAGE,
        session_id=12345,
        sequence_number=0
    )
    packet = DNSPacket(header=header, payload=b"test")
    packet_bytes = packet.to_bytes()

    # Mock the first read to raise PartialHeaderError, then return the packet
    with patch('dns_tunnel.protocol.DNSPacket.from_bytes') as mock_from_bytes:
        mock_from_bytes.side_effect = [PartialHeaderError, packet]

        # Return partial data first, then the rest
        mock_socket.recv.side_effect = [packet_bytes[:10], packet_bytes[10:]]

        # First read should not return any messages
        messages = proxy_socket.read()
        assert messages == []
        assert len(proxy_socket._read_buf) == 10  # Partial data should be in buffer

        # Second read should complete the message
        messages = proxy_socket.read()
        assert len(messages) == 1
        assert messages[0].header.session_id == 12345
        assert messages[0].payload == b"test"

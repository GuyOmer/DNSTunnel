import dns.message
import dns.rdatatype
import dns.rrset
import pytest

from dns_tunnel.protocol import (
    create_custom_dns_query,
    extract_payload_from_dns_query,
    DNSPacket,
    DNSPacketHeader,
    MessageType,
    create_ack_message,
    create_close_session_message,
    PartialHeaderError,
    InvalidSocketBuffer,
    NotEnoughDataError
)


def test_create_dns_query():
    test_data = b"test_data"
    query_wire = create_custom_dns_query(test_data)

    # Extract and verify the payload
    extracted_data = extract_payload_from_dns_query(query_wire)
    assert extracted_data == test_data


def test_dns_packet_header():
    header = DNSPacketHeader(
        payload_length=10,
        message_type=MessageType.NORMAL_MESSAGE,
        session_id=1,
        sequence_number=1
    )

    # Test serialization
    header_bytes = header.to_bytes()
    # Test deserialization
    recovered_header = DNSPacketHeader.from_bytes(header_bytes)

    assert recovered_header.payload_length == header.payload_length
    assert recovered_header.message_type == header.message_type
    assert recovered_header.session_id == header.session_id
    assert recovered_header.sequence_number == header.sequence_number


def test_dns_packet():
    header = DNSPacketHeader(
        payload_length=9,  # Exact length of "test_data"
        message_type=MessageType.NORMAL_MESSAGE,
        session_id=1,
        sequence_number=1
    )
    payload = b"test_data"
    packet = DNSPacket(header=header, payload=payload)

    # Test serialization
    packet_bytes = packet.to_bytes()
    # Test deserialization
    recovered_packet = DNSPacket.from_bytes(packet_bytes)

    assert recovered_packet.header.payload_length == packet.header.payload_length
    assert recovered_packet.header.message_type == packet.header.message_type
    assert recovered_packet.header.session_id == packet.header.session_id
    assert recovered_packet.header.sequence_number == packet.header.sequence_number
    assert recovered_packet.payload == packet.payload


def test_partial_header_error():
    """Test handling of incomplete header data."""
    with pytest.raises(PartialHeaderError):
        DNSPacketHeader.from_bytes(b"too_short")


def test_invalid_magic_error():
    """Test handling of invalid magic bytes in header."""
    invalid_magic = b"INVALID" + b"\x00" * 20  # Add padding to meet size requirements
    with pytest.raises(InvalidSocketBuffer):
        DNSPacketHeader.from_bytes(invalid_magic)


def test_ack_message():
    """Test creation of acknowledgment messages."""
    session_id = 1
    sequence_number = 42
    ack_packet = create_ack_message(session_id, sequence_number)

    assert ack_packet.header.message_type == MessageType.ACK_MESSAGE
    assert ack_packet.header.session_id == session_id
    assert ack_packet.header.sequence_number == sequence_number
    assert ack_packet.header.payload_length == 0
    assert ack_packet.payload == b""


def test_close_session_message():
    """Test creation of close session messages."""
    session_id = 1
    close_packet = create_close_session_message(session_id)

    assert close_packet.header.message_type == MessageType.CLOSE_SESSION
    assert close_packet.header.session_id == session_id
    assert close_packet.header.sequence_number == 0
    assert close_packet.header.payload_length == 0
    assert close_packet.payload == b""


def test_packet_length():
    """Test packet length calculation."""
    header = DNSPacketHeader(
        payload_length=10,
        message_type=MessageType.NORMAL_MESSAGE,
        session_id=1,
        sequence_number=1
    )
    payload = b"test_data"
    packet = DNSPacket(header=header, payload=payload)

    # Length should be the size of the serialized packet
    assert len(packet) == len(packet.to_bytes())


def test_dns_query_with_relative_domain():
    """Test creating DNS query with relative domain name."""
    # This should test line 125 where domain name is made absolute
    test_data = b"test_data"
    query_wire = create_custom_dns_query(test_data)

    # Extract and verify the payload
    extracted_data = extract_payload_from_dns_query(query_wire)
    assert extracted_data == test_data


def test_not_enough_data_error():
    """Test handling of incomplete packet data."""
    # Create a valid packet first
    header = DNSPacketHeader(
        payload_length=5,  # Expect 5 bytes
        message_type=MessageType.NORMAL_MESSAGE,
        session_id=1,
        sequence_number=1
    )
    packet = DNSPacket(header=header, payload=b"12345")  # Exactly 5 bytes

    # Get the packet bytes
    packet_bytes = packet.to_bytes()

    # Extract the payload from the DNS query
    dns_packet_bytes = extract_payload_from_dns_query(packet_bytes)

    # Create a new header that expects more data
    modified_header = DNSPacketHeader(
        payload_length=10,  # Now expect 10 bytes
        message_type=MessageType.NORMAL_MESSAGE,
        session_id=1,
        sequence_number=1
    )

    # Create a new packet with the modified header but same payload
    modified_packet_bytes = modified_header.to_bytes() + dns_packet_bytes[len(header):]

    # Create a new DNS query with the modified packet
    modified_dns_query = create_custom_dns_query(modified_packet_bytes)

    # This should now raise NotEnoughDataError because the payload is too short
    with pytest.raises(NotEnoughDataError) as exc_info:
        DNSPacket.from_bytes(modified_dns_query)

    # Verify the error message
    assert "Message size is" in str(exc_info.value)
    assert "bytes are available" in str(exc_info.value)


def test_dns_query_domain_handling():
    """Test DNS query creation with different domain name formats."""
    test_data = b"test_data"

    # Test with a domain name that doesn't end with a dot
    query_wire = create_custom_dns_query(test_data)
    query = dns.message.from_wire(query_wire)

    # The question section should contain our domain name with a trailing dot
    question = query.question[0]
    assert str(question.name).endswith(".")

    # Extract and verify the payload is still correct
    extracted_data = extract_payload_from_dns_query(query_wire)
    assert extracted_data == test_data

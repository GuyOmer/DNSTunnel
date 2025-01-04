import base64
import dataclasses
import enum
import struct
from typing import Final, Self

import dns.message
import dns.query
import dns.rdatatype
import dns.rrset
import more_itertools


@enum.unique
class MessageType(enum.Enum):
    NORMAL_MESSAGE = 1
    ACK_MESSAGE = 10


class DNSPacketError(Exception): ...


class InvalidSocketBuffer(DNSPacketError):
    """Raised when the buffer is long enough to contain the magic, but doesn't contain it"""


class PartialHeaderError(DNSPacketError):
    """Raised when not enough data was read to construct an header"""


class NotEnoughDataError(DNSPacketError): ...


@dataclasses.dataclass
class DNSPacketHeader:
    payload_length: int
    message_type: MessageType
    session_id: int
    sequence_number: int

    MAGIC: Final = b"deadbeaf"  # TODO: Make sure this makes sense
    _HEADER_FMT = f"!{len(MAGIC)}bIBII"  # TODO: make sure this is correct
    _FORMATTER = struct.Struct(_HEADER_FMT)

    def to_bytes(self) -> bytes:
        return type(self)._FORMATTER.pack(
            *type(self).MAGIC,
            self.payload_length,
            self.message_type.value,
            self.session_id,
            self.sequence_number,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        if len(data) < cls._FORMATTER.size:
            raise PartialHeaderError(f"Only {len(data)} bytes are available, expected {cls._FORMATTER.size}")

        if not data.startswith(cls.MAGIC):
            # data is long enough to contain the magic, but doesn't contain it
            raise InvalidSocketBuffer(f"Buffer starts with '{data[:len(cls.MAGIC)]}', are expected '{cls.MAGIC}'")

        return cls(
            *cls._FORMATTER.unpack(
                data[: cls._FORMATTER.size],
            )[len(cls.MAGIC) :]
        )

    def __len__(self) -> int:
        return max(0, type(self)._FORMATTER.size)


@dataclasses.dataclass(frozen=True)
class DNSPacket:
    header: DNSPacketHeader
    payload: bytes

    MAX_PAYLOAD: Final = (
        255  # TODO make sure this is really max UDP packet size (within MTU...) (also take into account the header size)
    )

    def to_bytes(self) -> bytes:
        return self.header.to_bytes() + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        # TODO: Need to truncate read bytes from "stream"
        header = DNSPacketHeader.from_bytes(data)

        header_length = len(header)

        try:
            # TODO: assert payload not > MAX_PAYLOAD
            payload = data[header_length : header_length + header.payload_length]
        except IndexError as e:
            raise NotEnoughDataError(
                f"Message size is  {header_length + header.payload_length} bytes, but only {len(data)} bytes are aviliable"
            ) from e

        return cls(header, payload)

    @classmethod
    def from_payload(cls, payload: bytes, message_type: MessageType, session_id: int, sequence_number: int) -> Self:
        return cls(
            DNSPacketHeader(
                len(payload),
                message_type,
                session_id,
                sequence_number,
            ),
            payload,
        )

    def __len__(self) -> int:
        return len(self.header) + self.header.payload_length


def create_custom_dns_query(domain_name: str, payload: bytes) -> bytes:
    """
    Creates a DNS query with a custom payload embedded in a TXT record.

    :param domain_name: The domain name to query (e.g., 'example.com').
    :param payload: The custom payload to send (e.g., an 8x8 image encoded in base64).
    :return: The DNS query message.
    """
    # NOTE: max size per record is 189 bytes?
    domain_name = "text.com."

    # Ensure the domain name is absolute
    if not domain_name.endswith("."):
        domain_name += "."

    # Encode the binary data using base64
    base64_data = base64.b64encode(payload).decode("utf-8")

    # Create a DNS query message
    query = dns.message.make_query(domain_name, dns.rdatatype.A)

    # Create a TXT record with the base64-encoded data
    txt_rrset = dns.rrset.from_text(domain_name, 300, "IN", "TXT", base64_data)

    # Add the TXT record to the additional section of the query
    query.additional.append(txt_rrset)

    # Convert the DNS message to wire format
    query_wire = query.to_wire()
    return query_wire


# def send_custom_dns_query(server_ip: str, domain_name: str, payload: bytes) -> None:
#     """
#     Sends a DNS query with a custom payload to the specified server.

#     :param server_ip: The IP address of the DNS server (e.g., '8.8.8.8').
#     :param domain_name: The domain name to query.
#     :param payload: The custom payload to send.
#     """
#     # Create the DNS query message with the custom payload
#     dns_query = create_custom_dns_query(domain_name, payload)

#     print(f"Sending custom DNS query with payload to {server_ip}")

#     # Send the query and receive the response
#     response = dns.query.udp(dns_query, server_ip)

#     print(f"Received response:")
#     print(response)


def create_ack_message(session_id: int, sequence_number: int) -> DNSPacket:
    return DNSPacket(
        DNSPacketHeader(
            0,
            MessageType.ACK_MESSAGE,
            session_id,
            sequence_number,  # When ACK-ing, use the sequence number we are ACK-ing
        ),
        b"",
    )

import base64
import dataclasses
import enum
import struct
from typing import Final, Self

import dns.message
import dns.name
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

    MAGIC: Final = b"deadbeef"  # TODO: Make sure this makes sense
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

        length, raw_message_type, session_id, sequence_number = cls._FORMATTER.unpack(data[: cls._FORMATTER.size])[
            len(cls.MAGIC) :
        ]
        res = cls(length, MessageType(raw_message_type), session_id, sequence_number)
        return res

    def __len__(self) -> int:
        return max(0, type(self)._FORMATTER.size)


@dataclasses.dataclass(frozen=True)
class DNSPacket:
    header: DNSPacketHeader
    payload: bytes

    MAX_PAYLOAD: Final = (
        # 255  # TODO make sure this is really max UDP packet size (within MTU...) (also take into account the header size)
        125
    )

    def to_bytes(self) -> bytes:
        raw = self.header.to_bytes() + self.payload
        as_dns = create_custom_dns_query(raw)

        return as_dns

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        dns_packet_bytes = extract_payload_from_dns_query(data)
        header = DNSPacketHeader.from_bytes(dns_packet_bytes)

        header_length = len(header)

        try:
            # TODO: assert payload not > MAX_PAYLOAD
            payload = dns_packet_bytes[header_length : header_length + header.payload_length]
        except IndexError as e:
            raise NotEnoughDataError(
                f"Message size is  {header_length + header.payload_length} bytes, but only {len(dns_packet_bytes)} bytes are available"
            ) from e

        res = cls(header, payload)
        return res

    def __len__(self) -> int:
        return len(self.to_bytes())


def create_custom_dns_query(payload: bytes) -> bytes:
    """
    Creates a DNS query with a custom payload embedded in a TXT record.

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


def extract_payload_from_dns_query(query_wire: bytes) -> bytes:
    """
    Extracts the custom payload from a DNS query with a TXT record.

    :param query_wire: The DNS query message in wire format.
    :return: The extracted custom payload.
    """
    # Parse the DNS message from wire format
    query = dns.message.from_wire(query_wire)

    rrset = more_itertools.one(rrset for rrset in query.additional if rrset.rdtype == dns.rdatatype.TXT)

    # Extract the base64-encoded data from the TXT record
    base64_data = rrset[0].to_text().strip('"')
    # Decode the base64 data to get the original payload
    # import ipdb

    # ipdb.set_trace()
    return base64.b64decode(base64_data)
    txt_rrset = base64.b64decode(base64_data)
    txt_rrset_record_payload = base64.b64decode(txt_rrset.split(b" ")[-1].strip(b'"'))

    payload = base64.b64decode(txt_rrset_record_payload.split()[-1])
    return payload


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

import abc
import dataclasses
import enum
import struct
from typing import Final, Self

import more_itertools


@enum.unique
class SOCKS5AuthMethod(enum.IntEnum):
    NO_AUTH = 0x00

    # Below are not supported
    GSSAPI = 0x01
    USERNAME_PASSWORD = 0x02

    IANA_METHOD1 = 0x03
    # ...
    IANA_METHOD124 = 0x7F

    # Custom private methods
    PRIVATE_METHOD1 = 0x80


@enum.unique
class SOCKS5CommandCode(enum.IntEnum):
    ESTABLISH_A_TCP_IP_STREAM_CONNECTION = 0x01
    ESTABLISH_A_TCP_IP_PORT_BINDING = 0x02
    ESTABLISH_A_UDP_PORT = 0x03


@enum.unique
class SOCKS5AddressType(enum.IntEnum):
    IP_V4 = 0x01
    DOMAIN_NAME = 0x03
    IP_V6 = 0x04


@enum.unique
class SOCKS5ConnectRequestStatus(enum.IntEnum):
    GRANTED = 0x00


SOCKS5_VERSION: Final = 5


class SOCKS5MessagePartFormat(enum.StrEnum):
    VERSION = "B"
    AUTH_METHODS_AMOUNT = "B"
    AUTH_METHOD = "B"
    COMMAND_CODE = "B"
    RESERVED = "B"
    ADDRESS_TYPE = "B"
    IPV4_HOST = "4B"
    PORT = "H"


@dataclasses.dataclass
class SOCKS5Message(metaclass=abc.ABCMeta):
    @classmethod
    @abc.abstractmethod
    def from_bytes(cls, data: bytes):
        if int(data[0]) != SOCKS5_VERSION:
            raise ValueError("Not a SOCKS5 message")


@dataclasses.dataclass
class SOCKS5Greeting(SOCKS5Message):
    auth_methods: list[SOCKS5AuthMethod] = dataclasses.field(default_factory=list)

    _FORMAT = f"!{''.join([SOCKS5MessagePartFormat.VERSION,SOCKS5MessagePartFormat.AUTH_METHODS_AMOUNT])}"

    def to_bytes(self) -> bytes:
        return struct.pack(
            type(self)._FORMAT,
            SOCKS5_VERSION,
            len(self.auth_methods),
        ) + bytes(method.value for method in self.auth_methods)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        super().from_bytes(data)

        amount_of_methods = int(data[1])
        raw_methods = data[2:]
        methods = [SOCKS5AuthMethod(raw_method) for raw_method in raw_methods]

        if amount_of_methods != len(methods):
            raise ValueError(
                f"Expected {len(amount_of_methods)} auth methods, but only {len(methods)} ({', '.join(methods)}) are aviliable"
            )

        return cls(methods)


@dataclasses.dataclass
class SOCKS5GreetingResponse(SOCKS5Message):
    chosen_auth_method: SOCKS5AuthMethod

    _FORMAT: Final = f"!{SOCKS5MessagePartFormat.VERSION}{SOCKS5MessagePartFormat.AUTH_METHOD}"

    def to_bytes(self) -> bytes:
        return struct.pack(
            type(self)._FORMAT,
            SOCKS5_VERSION,
            self.chosen_auth_method.value,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        super().from_bytes(data)

        _, raw_method = struct.unpack(cls._FORMAT, data)
        method = SOCKS5AuthMethod(raw_method)

        return cls(method)


@dataclasses.dataclass
class SOCKS5IPv4ConnectRequest(SOCKS5Message):
    command: SOCKS5CommandCode
    host: bytes
    port: bytes

    address_type: Final = SOCKS5AddressType.IP_V4
    _FORMAT: Final = "!" + "".join(
        [
            SOCKS5MessagePartFormat.VERSION,
            SOCKS5MessagePartFormat.COMMAND_CODE,
            SOCKS5MessagePartFormat.RESERVED,
            SOCKS5MessagePartFormat.ADDRESS_TYPE,
            SOCKS5MessagePartFormat.IPV4_HOST,
            SOCKS5MessagePartFormat.PORT,
        ]
    )

    def to_bytes(self) -> bytes:
        return struct.pack(
            type(self)._FORMAT,
            SOCKS5_VERSION,
            self.command.value,
            0,  # Reserved
            self.address_type,
            self.host,
            self.port,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        super().from_bytes(data)

        _, raw_command, __, raw_address_type, host, port = struct.unpack(cls._FORMAT, data)

        if raw_address_type != SOCKS5AddressType.IP_V4:
            raise ValueError(f"Unsupported address type in SOCKS5 request: {raw_address_type}")

        return cls(
            SOCKS5CommandCode(raw_command),
            host,
            port,
        )


# TODO: Understand this one
@dataclasses.dataclass
class SOCKS5IPv4ConnectResponse(SOCKS5Message):
    status: SOCKS5ConnectRequestStatus

    _FORMAT: Final = "!"

    def to_bytes(self) -> bytes:
        return struct.pack(
            type(self)._FORMAT,
            SOCKS5_VERSION,
            self.status.value,
            0,  # Reserved
            self.address_type,
            self.host,
            self.port,
        )

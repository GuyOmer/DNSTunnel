import abc
import logging
import socket

logger = logging.getLogger(__name__)


class SelectableSocket:
    def __init__(self, s: socket.socket):
        self._s = s

        self._write_buffer = b""
        # self._read_buf = b""

    def fileno(self) -> int:
        return self._s.fileno()

    def add_to_write_queue(self, data: bytes):
        self._write_buffer += data

    def needs_to_write(self) -> bool:
        return len(self._write_buffer) != 0

    def write(self) -> int:
        bytes_sent = self._s.send(self._write_buffer)
        self._write_buffer = self._write_buffer[bytes_sent:]
        return bytes_sent

    def read(self):
        data = self._s.recv(2**10)
        # self._read_buf += data

        return data

    # def read(self) -> list[DNSPacket]:
    #     # TODO: Needs to be non blocking
    #     data = self._s.recv(2**10)
    #     if len(data) == 0:
    #         # TODO: This means the socket closed?
    #         return []

    #     self._read_buf += data

    #     msgs = []
    #     while self._read_buf:
    #         try:
    #             msg = DNSPacket.from_bytes(self._read_buf)
    #             msgs.append(msg)

    #             # Consume read bytes from buffer
    #             self._read_buf = self._read_buf[len(msg) :]
    #         except InvalidSocketBuffer:
    #             logger.debug("Invalid starting bytes in buffer, flushing them")
    #             self._read_buf = (
    #                 self._read_buf[self._read_buf.index(DNSPacketHeader.MAGIC) :]
    #                 if DNSPacketHeader.MAGIC in self._read_buf
    #                 else b""
    #             )
    #             continue
    #         except (PartialHeaderError, NotEnoughDataError):
    #             logger.debug("Not enough data in buffer")
    #             break

    #     return msgs

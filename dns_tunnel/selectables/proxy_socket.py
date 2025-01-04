import collections
import dataclasses
import datetime
from typing import Final
from venv import logger

from dns_tunnel.protocol import (
    DNSPacket,
    DNSPacketHeader,
    InvalidSocketBuffer,
    MessageType,
    NotEnoughDataError,
    PartialHeaderError,
)
from dns_tunnel.selectables.selectable_socket import SelectableSocket


@dataclasses.dataclass
class SessionInfo:
    sending_queue: list[DNSPacket] = dataclasses.field(default_factory=list)
    seq_counter: int = 0
    last_sent_seq: int = -1
    last_acked_seq: int = -1
    last_sending_time: datetime = dataclasses.field(default_factory=datetime.datetime.now)
    retransmission_attempt_counter = 0
    last_seq_got: int = -1


RETRANSMISSION_TIME: Final = datetime.timedelta(seconds=10)
MAX_RETRANSMISSION_ATTEMPTS: Final = 3


class ProxySocket(SelectableSocket):
    def __init__(self, s, proxy_address: tuple[str, int]):
        super().__init__(s)

        self._proxy_address = proxy_address

        self._read_buf = b""
        # self._state = initial_state
        self._sessions: dict[int, SessionInfo] = collections.defaultdict(SessionInfo)

    def needs_to_write(self):
        if super().needs_to_write():
            return True

        for session in self._sessions.values():
            if session.sending_queue:
                return True
        return False

    def queue_to_session(self, payload: bytes, session_id: int):
        session = self._sessions[session_id]
        session.sending_queue.append(
            DNSPacket(
                DNSPacketHeader(len(payload), MessageType.NORMAL_MESSAGE, session_id, session.seq_counter), payload
            )
        )
        session.seq_counter += 1

    def write(self):
        pending_send = [session for session in self._sessions.values() if session.sending_queue]
        for session in pending_send:
            # Last message was acked, can send the next one
            if session.last_sent_seq == session.last_acked_seq:
                msg_to_send = session.sending_queue[0]

            # Last message wasnt acked, check if we need to retransmit it)
            elif session.last_sending_time + RETRANSMISSION_TIME < datetime.datetime.now():
                # If too many retransmission attempts, quit
                if session.retransmission_attempt_counter > MAX_RETRANSMISSION_ATTEMPTS:
                    raise RuntimeError()
                else:
                    msg_to_send = session.sending_queue[0]
                    session.retransmission_attempt_counter += 1
            # Not acked, but no need to retransmit yet
            else:
                continue

            self._write_buffer += msg_to_send.to_bytes()
            session.last_sent_seq = msg_to_send.header.sequence_number
            session.last_sending_time = datetime.datetime.now()

            bytes_sent = self._s.sendto(self._write_buffer, self._proxy_address)
            if bytes_sent != len(self._write_buffer):
                raise RuntimeError("Sending was fragmented, this is not supported")

    def ack_message(self, session_id: int, sequence_number: int):
        if sequence_number > self._sessions[session_id].last_acked_seq:
            self._sessions[session_id].last_acked_seq = sequence_number
            self._sessions[session_id].sending_queue.pop(0)

    def read(self) -> list[DNSPacket]:
        # TODO: Needs to be non blocking
        data = self._s.recv(2**10)
        if len(data) == 0:
            # TODO: This means the socket closed?
            return []

        self._read_buf += data

        msgs = []
        while self._read_buf:
            try:
                msg = DNSPacket.from_bytes(self._read_buf)
                if self._sessions[msg.header.session_id].last_seq_got + 1 != msg.header.sequence_number:
                    logger.debug(f"Invalid sequence number for session {msg.header.session_id}, got sequence {msg.header.sequence_number} instead of {self._sessions[msg.header.session_id].last_seq_got + 1}")
                else:
                    self._sessions[msg.header.session_id].last_seq_got += 1
                    msgs.append(msg)

                # Consume read bytes from buffer
                self._read_buf = self._read_buf[len(msg) :]
            except InvalidSocketBuffer:
                logger.debug("Invalid starting bytes in buffer, flushing them")
                self._read_buf = (
                    self._read_buf[self._read_buf.index(DNSPacketHeader.MAGIC) :]
                    if DNSPacketHeader.MAGIC in self._read_buf
                    else b""
                )
                continue
            except (PartialHeaderError, NotEnoughDataError):
                logger.debug("Not enough data in buffer")
                break

        return msgs

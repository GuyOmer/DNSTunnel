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
    create_ack_message, create_close_session_message,
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
    is_active: bool = True


RETRANSMISSION_TIME: Final = datetime.timedelta(seconds=10)
MAX_RETRANSMISSION_ATTEMPTS: Final = 5


class ProxySocket(SelectableSocket):
    def __init__(self, s, proxy_address: tuple[str, int]):
        super().__init__(s)

        self._proxy_address = proxy_address

        self._read_buf = b""
        self._sessions: dict[int, SessionInfo] = collections.defaultdict(SessionInfo)
        self._write_messages: list[bytes] = []

    def needs_to_write(self):
        if self._write_messages:
            return True

        for session in self._sessions.values():
            if session.sending_queue:
                return True
        return False

    def add_to_write_queue(self, data: bytes, session_id: int | None = None):
        session = self._sessions[session_id]
        session.sending_queue.append(
            DNSPacket(DNSPacketHeader(len(data), MessageType.NORMAL_MESSAGE, session_id, session.seq_counter), data)
        )
        session.seq_counter += 1

    def end_session(self, session_id: int):
        self._write_messages.append(
            create_close_session_message(session_id).to_bytes()
        )

    def write(self):
        pending_send = [session for session in self._sessions.values() if session.sending_queue and session.is_active]
        for session in pending_send:
            # Last message was acked, can send the next one
            if session.last_sent_seq == session.last_acked_seq:
                msg_to_send = session.sending_queue[0]

            # Last message wasn't acked, check if we need to retransmit it)
            elif session.last_sending_time + RETRANSMISSION_TIME < datetime.datetime.now():
                # If too many retransmission attempts, quit
                if session.retransmission_attempt_counter > MAX_RETRANSMISSION_ATTEMPTS:
                    logger.error(
                        f"Too many retransmission attempts for session {session.sending_queue[0].header.session_id}"
                    )
                    session.is_active = False
                    self.end_session(session.sending_queue[0].header.session_id)
                    continue
                else:
                    msg_to_send = session.sending_queue[0]
                    session.retransmission_attempt_counter += 1
            # Not acked, but no need to retransmit yet
            else:
                continue

            self._write_messages.append(msg_to_send.to_bytes())
            session.last_sent_seq = msg_to_send.header.sequence_number
            session.last_sending_time = datetime.datetime.now()

        for message in self._write_messages:
            bytes_sent = self._s.sendto(message, self._proxy_address)
            if bytes_sent != len(message):
                raise RuntimeError("Sending was fragmented, this is not supported")
        self._write_messages = []

    def ack_message(self, session_id: int, sequence_number: int):
        logger.info(f"Got ACK for session {session_id} and sequence {sequence_number}")
        if sequence_number == self._sessions[session_id].last_acked_seq + 1:
            logger.info(f"ACK-ed: session {session_id} and sequence {sequence_number}")
            self._sessions[session_id].last_acked_seq = sequence_number
            self._sessions[session_id].sending_queue.pop(0)

            self._sessions[session_id].retransmission_attempt_counter = 0
        else:
            logger.debug(
                f"Got invalid sequence number for session {session_id}, "
                f"got sequence {sequence_number} instead of {self._sessions[session_id].last_acked_seq + 1}"
            )

    def remove_session(self, session_id: int):
        logger.info(f"Removing session {session_id}")
        if session_id in self._sessions:
            self._sessions[session_id].is_active = False

    def read(self) -> list[DNSPacket]:
        data = self._s.recv(2**10)
        if len(data) == 0:
            return []

        self._read_buf += data

        msgs = []
        while self._read_buf:
            try:
                msg = DNSPacket.from_bytes(self._read_buf)
                if msg.header.message_type in [MessageType.ACK_MESSAGE, MessageType.CLOSE_SESSION]:
                    msgs.append(msg)
                else:
                    if self._sessions[msg.header.session_id].last_seq_got + 1 == msg.header.sequence_number:
                        self._sessions[msg.header.session_id].last_seq_got += 1
                        msgs.append(msg)
                    else:
                        logger.warning(
                            f"Read invalid sequence number for session {msg.header.session_id}, "
                            f"got sequence {msg.header.sequence_number} instead of "
                            f"{self._sessions[msg.header.session_id].last_seq_got + 1}"
                        )

                    logger.info(
                        f"Sending ACK for session {msg.header.session_id} and sequence {msg.header.sequence_number}"
                    )
                    self._write_messages.append(
                        create_ack_message(msg.header.session_id, msg.header.sequence_number).to_bytes()
                    )

                # Consume read bytes from buffer
                self._read_buf = self._read_buf[len(msg):]
            except InvalidSocketBuffer:
                logger.debug("Invalid starting bytes in buffer, flushing them")
                self._read_buf = b""
                continue
            except (PartialHeaderError, NotEnoughDataError):
                logger.debug("Not enough data in buffer")
                break

        return msgs

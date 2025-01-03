import collections
import dataclasses
import datetime
from typing import Final

from dns_tunnel.protocol import DNSPacket, DNSPacketHeader, MessageType
from dns_tunnel.selectables.selectable_socket import SelectableSocket


@dataclasses.dataclass
class SessionInfo:
    sending_queue: list[DNSPacket] = dataclasses.field(default_factory=list)
    seq_counter: int = 0
    last_sent_seq: int = 0
    last_acked_seq: int = -1
    last_sending_time: datetime = 0
    retransmission_attempt_counter = 0


RETRANSMISSION_TIME: Final = datetime.timedelta(seconds=10)
MAX_RETRANSMISSION_ATTEMPTS: Final = 3


class ProxySocket(SelectableSocket):
    def __init__(self, s):
        super().__init__(s)

        # self._state = initial_state
        self._sessions: dict[int, SessionInfo] = collections.defaultdict(SessionInfo)

    def queue_to_session(self, payload: bytes, session_id: int):
        session = self._sessions[session_id]
        session.sending_queue.append(
            DNSPacket(DNSPacketHeader(len(payload), MessageType.NORMAL_MESSAGE, session_id, session.seq_counter), payload))
        session.seq_counter += 1

    def write(self):
        pending_send = [session for session in self._sessions.values() if session.sending_queue]
        for session in pending_send:
            # Last message was acked, can send the next one
            if session.last_sent_seq == session.last_acked_seq:
                msg_to_send = session.sending_queue[0]

            # Last message wasnt acked, check if we need to retransmit it)
            elif session.last_sending_time + RETRANSMISSION_TIME > datetime.datetime.now():
                # If too many retransmission attempts, quit
                if session.retransmission_attempt_counter > MAX_RETRANSMISSION_ATTEMPTS:
                    raise RuntimeError()
                else:
                    msg_to_send = session.sending_queue[0]
                    session.retransmission_attempt_counter += 1
            # Not acked, but no need to retransmit yet
            else:
                continue

            bytes_sent = self._s.send(msg_to_send.to_bytes())
            if bytes_sent != len(msg_to_send):
                # In packet fragmentation is not supported
                raise RuntimeError()

            session.last_sent_seq = msg_to_send.header.sequence_number
            session.last_sending_time = datetime.datetime.now()

    def ack_message(self, session_id: int, sequence_number: int):
        if sequence_number > self._sessions[session_id].last_acked_seq:
            self._sessions[session_id].last_acked_seq = sequence_number
            self._sessions[session_id].sending_queue.pop(0)

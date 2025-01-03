import collections
import dataclasses
import datetime
import random
from typing import Final

from dns_tunnel.protocol import DNSPacket
from dns_tunnel.selectables.selectable_socket import SelectableSocket


@dataclasses.dataclass
class SessionInfo:
    sending_queue: list[DNSPacket] = []
    seq_counter: int = 0
    last_sent_seq: int = 0
    last_acked_seq: int = -1
    last_sending_time: datetime = 0
    retransission_attempt_counter = 0


RETRANSMISSOIN_TIME: Final = datetime.timedelta(seconds=10)
MAX_RETRANSSMISSION_ATTEMPTS: Final = 3


class ProxySocket(SelectableSocket):
    def __init__(self, s):
        super().__init__(s)

        # self._state = initial_state
        self._sessions: dict[int, SessionInfo] = collections.defaultdict(SessionInfo)

    def queue_to_session(self, payload: bytes, session_id: int):
        session = self._sessions[session_id]
        session.sending_queue.append(DNSPacket(..., session_id, session.seq_counter, payload))
        session.seq_counter += 1

    def write(self):
        pending_send = [session for session in self._sessions.values() if session.sending_queue]

        chosen_to_send = random.choice(pending_send)
        # msg_to_send = more_itertools.first(chosen_to_send.sending_queue)

        # Last message was acked, can send the next one
        if chosen_to_send.last_sent_seq == chosen_to_send.last_acked_seq:
            msg_to_send = chosen_to_send.sending_queue[0]

        # Last message wasnt acked, check if we need to retransmit it)
        elif chosen_to_send.last_sending_time + RETRANSMISSOIN_TIME > datetime.datetime.now():
            # If too many retransmission attempts, quit
            if chosen_to_send.retransission_attempt_counter > MAX_RETRANSSMISSION_ATTEMPTS:
                raise RuntimeError()
            else:
                msg_to_send = chosen_to_send.sending_queue[0]
                chosen_to_send.retransission_attempt_counter += 1
        # Not acked, but no need to retranssmit
        else:
            return

        bytes_sent = self._s.write(msg_to_send.serialize())
        if bytes_sent != msg_to_send.size():
            # In packet fragmentation is not supported
            raise RuntimeError()

        chosen_to_send.last_sent_seq = msg_to_send.sequence_number
        chosen_to_send.last_sending_time = datetime.datetime.now()

    def ack_message(self, session_id: int, sequence_number: int): ...

import enum

from dns_tunnel.selectables.selectable_socket import SelectableSocket


@enum.unique
class TCPClientSocketState(enum.StrEnum):
    # TCP clients state
    ACCEPTED = "accepted"  # Progress after greeting is added to send queue
    PENDING_GREETING_TRANSMISSION = "pending_greeting_transmissions"
    PENDING_GREETING_ACK = "pending_greeting_ack"  # progress after greeting was sent
    GREETING_ACKWNOLEDGED = "greeting_acknoledged"  # Progress after sending connect
    CONNECT_ACKNOLODGED = "connect_acknoledged"  #
    TUNNELING = "tunneling"


class TCPClientSocket(SelectableSocket):
    def __init__(self, s, session_id: int):
        super().__init__(s)

        self._session_id = session_id

    @property
    def session_id(self) -> int:
        return self._session_id

    # def get_state(self) -> TCPClientSocketState:
    #     return self._state

    # def set_state(self, new_state: TCPClientSocketState):
    #     self._state = new_state

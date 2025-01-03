import enum

from dns_tunnel.selectables.selectable_socket import SelectableSocket


@enum.unique
class TunnelSocketState(enum.StrEnum):

    # TCP clients state
    SETTING_UP_TUNNEL = "SETTING_UP_TUNNEL"


class TunnelSocket(SelectableSocket):
    def __init__(self, s, initial_state: TunnelSocketState):
        super().__init__(s)

        self._state = initial_state

    def get_state(self) -> TunnelSocketState:
        return self._state

    def set_state(self, new_state: TunnelSocketState):
        self._state = new_state

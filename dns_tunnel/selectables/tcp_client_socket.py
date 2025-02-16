from dns_tunnel.selectables.selectable_socket import SelectableSocket


class TCPClientSocket(SelectableSocket):
    def __init__(self, s, session_id: int):
        super().__init__(s)

        self._session_id = session_id
        self._write_buffer = b""

    @property
    def session_id(self) -> int:
        return self._session_id

    def add_to_write_queue(self, data: bytes, session_id: int | None = None):
        self._write_buffer += data

    def needs_to_write(self) -> bool:
        return len(self._write_buffer) != 0

    def write(self) -> int:
        bytes_sent = self._s.send(self._write_buffer)
        self._write_buffer = self._write_buffer[bytes_sent:]
        return bytes_sent

    def read(self) -> bytes:
        try:
            return self._s.recv(4096)
        except (ConnectionResetError, ConnectionRefusedError):
            return b""

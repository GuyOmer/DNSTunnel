import abc
import logging
import socket

logger = logging.getLogger(__name__)


class SelectableSocket(abc.ABC):
    def __init__(self, s: socket.socket):
        self._s = s

    def fileno(self) -> int:
        return self._s.fileno()

    def close(self) -> None:
        self._s.close()

    @abc.abstractmethod
    def add_to_write_queue(self, data: bytes, session_id: int | None = None):
        ...

    @abc.abstractmethod
    def needs_to_write(self) -> bool:
        ...

    @abc.abstractmethod
    def write(self) -> int:
        ...

    @abc.abstractmethod
    def read(self):
        ...

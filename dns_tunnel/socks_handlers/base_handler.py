import abc
import socket

from dns_tunnel.selectables.proxy_socket import ProxySocket


class BaseHandler(abc.ABC):
    def __init__(self):
        self._rlist = []
        self._wlist = []

    @abc.abstractmethod
    def run(self):
        ...

    @property
    @abc.abstractmethod
    def address(self):
        ...

    @property
    @abc.abstractmethod
    def port(self):
        ...

    def init_ingress_socket(self, address: str, port: int) -> ProxySocket:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((self.address(), self.port()))
        return ProxySocket(
            s,
            (address, port),
        )

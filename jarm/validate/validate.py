import socket
from jarm.exceptions.exceptions import PyJARMInvalidTarget


class Validate:
    @staticmethod
    def validate_target(target_host, target_port=443, address_family=0):
        try:
            info = socket.getaddrinfo(
                host=target_host, port=target_port, family=address_family
            )
        except socket.gaierror:
            raise PyJARMInvalidTarget("Invalid Target Host")
        if info and isinstance(info, list):
            return info[0]
        raise PyJARMInvalidTarget("Invalid Target Host")

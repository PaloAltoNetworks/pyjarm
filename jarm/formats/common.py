from random import choice
from typing import Set

from jarm.constants import (
    ALLOWED_CIPHER_LISTS,
    ALLOWED_CIPHER_ORDER,
    ALLOWED_EXTENSION_ORDER,
    ALLOWED_SUPPORT,
    ALLOWED_TLS_VERSIONS,
    ALPN,
    RARE_ALPN,
    GREASE,
    NO_GREASE,
)
from jarm.exceptions.exceptions import PyJARMUnsupportValueException
from jarm.packet.packet import Packet


class CommonTLSFormat:
    """
    A base TLS format object.
    """

    # Format
    _version: str = ""
    _cipher_choice: str = ""
    _client_suites_length: str = ""
    _grease: str = ""
    _alpn: str = ""
    _cipher_order: str = ""
    _support: str = ""
    _extension_order: str = ""

    def __init__(
        self,
        version: str,
        cipher_list: str,
        cipher_order: str,
        is_grease: bool,
        is_rare_alpn: bool,
        support: str,
        extension_order: str,
    ):
        """
        Initializes a hello format.

        Args:
            version (str):
                The TLS version for the hello.
            cipher_list (str):
                The Cipher list for the hello.
            ...
        """
        if version not in ALLOWED_TLS_VERSIONS:
            raise (
                PyJARMUnsupportValueException(
                    f"{version} is not in supported TLS versions: {ALLOWED_TLS_VERSIONS}"
                )
            )
        if cipher_list not in ALLOWED_CIPHER_LISTS:
            raise (
                PyJARMUnsupportValueException(
                    f"{cipher_list} is not in supported Cipher Lists: {ALLOWED_CIPHER_LISTS}"
                )
            )
        if cipher_order not in ALLOWED_CIPHER_ORDER:
            raise (
                PyJARMUnsupportValueException(
                    f"{cipher_order} is not in supported Ordering: {ALLOWED_CIPHER_ORDER}"
                )
            )
        if extension_order not in ALLOWED_EXTENSION_ORDER:
            raise (
                PyJARMUnsupportValueException(
                    f"{extension_order} is not in supported Ordering: {ALLOWED_EXTENSION_ORDER}"
                )
            )
        if support not in ALLOWED_SUPPORT:
            raise (
                PyJARMUnsupportValueException(
                    f"{support} is not in supported support types: {ALLOWED_SUPPORT}"
                )
            )

        self._version = version
        self._cipher_choice = cipher_list
        self._cipher_order = cipher_order
        self._grease = GREASE if is_grease else NO_GREASE
        self._alpn = RARE_ALPN if is_rare_alpn else ALPN
        self._support = support
        self._extension_order = extension_order

    def build_packet(self, dest_host, dest_port):
        """"""
        return Packet(dest_host=dest_host, dest_port=dest_port, jarm_hello_format=self)

    @property
    def version(self):
        return self._version

    @property
    def cipher_choice(self):
        return self._cipher_choice

    @property
    def cipher_order(self):
        return self._cipher_order

    @property
    def grease(self):
        return self._grease

    @property
    def support(self):
        return self._support

    @property
    def extension_order(self):
        return self._extension_order

    @property
    def alpn(self):
        return self._alpn

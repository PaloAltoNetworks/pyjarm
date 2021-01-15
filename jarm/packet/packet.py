import os
import random
from struct import pack
from typing import Any, List, NamedTuple

from jarm.constants import (
    FORWARD,
    REVERSE,
    BOTTOM_HALF,
    TOP_HALF,
    MIDDLE_OUT,
    GREASE,
    TLS_1_3,
    SUPPORT_1_2,
)
from jarm.alpns.alpns import ALPNS, Alpns, ALL
from jarm.ciphers.ciphers import CIPHERS, CipherSet
from jarm.exceptions.exceptions import PyJARMUnexpectedException
from jarm.grease.grease import GREASE_VALUES
from jarm.versions.versions import TLS_VERSIONS, TLSVersion


class Packet:
    """"""

    PAYLOAD_BASE: bytes = b"\x16"
    ALPN_BASE: bytes = b"\x00\x10"
    KEY_SHARE_BASE: bytes = b"\x00\x33"
    KEY_SHARE_GREASE_PAD: bytes = b"\x00\x01\x00"
    KEY_SHARE_GROUP: bytes = b"\x00\x1d"
    KEY_SHARE_KEY_EXCHANGE_LENGTH: bytes = b"\x00\x20"
    SINGLE_PAD: bytes = b"\x00"
    DOUBLE_PAD: bytes = b"\x00\x00"
    EXTENSION_MASTER_SECRET: bytes = b"\x00\x17\x00\x00"
    MAX_FRAG_LENGTH: bytes = b"\x00\x01\x00\x01\x01"
    RENEGOTIATION_INFO: bytes = b"\xff\x01\x00\x01\x00"
    SUPPORTED_GROUPS: bytes = (
        b"\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19"
    )
    EC_POINT_FORMATS: bytes = b"\x00\x0b\x00\x02\x01\x00"
    SESSION_TICKET: bytes = b"\x00\x23\x00\x00"
    SIGNATURE_ALGORITHMS: bytes = b"\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01"
    PSK_KEY_EXCHANGE_MODES: bytes = b"\x00\x2d\x00\x02\x01\x01"
    SUB_TLS_1_2_SUPPORT: List[bytes] = [b"\x03\x01", b"\x03\x02", b"\x03\x03"]
    TLS_1_3_SUPPORT: List[bytes] = [b"\x03\x01", b"\x03\x02", b"\x03\x03", b"\x03\x04"]
    SUPPORTED_VERSION_BASE: bytes = b"\x00\x2b"
    HANDSHAKE_PROTOCOL_PAD: bytes = b"\x01"

    def __init__(self, dest_host: str, dest_port: int, jarm_hello_format: Any):
        self.host = dest_host
        self.port = dest_port
        self.jarm_hello_format = jarm_hello_format

    def build(self) -> bytes:
        """"""
        payload: bytes = Packet.PAYLOAD_BASE
        client_hello: bytes = b""

        version = TLS_VERSIONS.get(self.jarm_hello_format.version)
        if version is not None and isinstance(version, TLSVersion):
            payload += version.payload
            client_hello += version.hello
        else:
            raise PyJARMUnexpectedException()

        # Add random values to hello
        client_hello += os.urandom(32)
        session_id = os.urandom(32)
        session_id_length = pack(">B", len(session_id))
        client_hello += session_id_length
        client_hello += session_id

        # Get ciphers
        ciphers = self._get_ciphers(
            cipher=self.jarm_hello_format.cipher_choice,
            order=self.jarm_hello_format.cipher_order,
            grease=self.jarm_hello_format.grease,
        )
        client_suites_length = pack(">H", len(ciphers))
        client_hello += client_suites_length
        client_hello += ciphers
        client_hello += b"\x01"  # cipher methods
        client_hello += b"\x00"  # compression_methods

        # Get Extensions
        client_hello += self._get_extensions(
            dest_host=self.host,
            grease=self.jarm_hello_format.grease,
            version=self.jarm_hello_format.version,
            support=self.jarm_hello_format.support,
            alpn=self.jarm_hello_format.alpn,
            extension_order=self.jarm_hello_format.extension_order,
        )

        # Finish packet assembly
        inner_length = Packet.SINGLE_PAD
        inner_length += pack(">H", len(client_hello))
        handshake_protocol = Packet.HANDSHAKE_PROTOCOL_PAD
        handshake_protocol += inner_length
        handshake_protocol += client_hello

        outer_length = pack(">H", len(handshake_protocol))
        payload += outer_length
        payload += handshake_protocol
        return payload

    def _get_ciphers(self, cipher: str, order: str, grease: str):
        """"""
        preliminary_ciphers: List[bytes] = []
        cipher_choice = CIPHERS.get(cipher)
        if cipher_choice is not None and isinstance(cipher_choice, CipherSet):
            preliminary_ciphers = cipher_choice.values
        else:
            raise PyJARMUnexpectedException(
                "Could not find expected output for cipher choice"
            )
        # Mung Cipher order
        preliminary_ciphers = self._reorder(pre_list=preliminary_ciphers, order=order)
        # Grease
        preliminary_ciphers = self._cipher_grease(
            pre_list=preliminary_ciphers, grease=grease
        )
        if preliminary_ciphers is not None:
            return b"".join(preliminary_ciphers)
        return b""

    def _reorder(self, pre_list: List[bytes], order: str) -> List[bytes]:
        """
        Mung the cipher list ordering.

        Args:
            pre_list (list<bytes>):
                A list of bytes for the cipher choice.
            order
        """
        output: List[bytes] = []
        length: int = len(pre_list)
        if order == FORWARD:
            output = pre_list
        elif order == REVERSE:
            output = pre_list[::-1]
        elif order == BOTTOM_HALF:
            if length % 2 == 1:
                output = pre_list[int(length / 2) + 1 :]
            else:
                output = pre_list[int(length / 2) :]
        elif order == TOP_HALF:
            if length % 2 == 1:
                output.append(pre_list[int(length / 2)])
                # Top half gets the middle cipher
            output += self._reorder(
                pre_list=self._reorder(pre_list=pre_list, order=REVERSE),
                order=BOTTOM_HALF,
            )
        elif order == MIDDLE_OUT:
            middle = int(length / 2)
            # if ciphers are uneven, start with the center.  Second half before first half
            if length % 2 == 1:
                output.append(pre_list[middle])
                for i in range(1, middle + 1):
                    output.append(pre_list[middle + i])
                    output.append(pre_list[middle - i])
            else:
                for i in range(1, middle + 1):
                    output.append(pre_list[middle - 1 + i])
                    output.append(pre_list[middle - i])
        else:
            raise PyJARMUnexpectedException("Unexpected order variable for cipher mung")
        return output

    def _cipher_grease(self, pre_list, grease):
        """
        Applies a grease value if necessary.
        """
        if grease == GREASE:
            pre_list.insert(0, random.choice(GREASE_VALUES))
            return pre_list
        return pre_list

    def _get_extensions(
        self,
        dest_host: str,
        grease: str,
        version: str,
        support: str,
        alpn: str,
        extension_order: str,
    ):
        """"""
        extension_bytes: bytes = b""
        all_extensions: bytes = b""

        # Add Grease
        if grease == GREASE:
            all_extensions += random.choice(GREASE_VALUES)
            all_extensions += Packet.DOUBLE_PAD

        # Append Host Extension
        all_extensions += self._extension_host_name(dest_host=dest_host)

        # Misc. Extensions
        all_extensions += Packet.EXTENSION_MASTER_SECRET
        all_extensions += Packet.MAX_FRAG_LENGTH
        all_extensions += Packet.RENEGOTIATION_INFO
        all_extensions += Packet.SUPPORTED_GROUPS
        all_extensions += Packet.EC_POINT_FORMATS
        all_extensions += Packet.SESSION_TICKET

        # Application Layer Protocol Negotiation Extension
        all_extensions += self._app_layer_proto_negotiation(
            alpn=alpn, extension_order=extension_order
        )
        all_extensions += Packet.SIGNATURE_ALGORITHMS

        # Key Share Extension
        all_extensions += self._key_share(grease=grease)
        all_extensions += Packet.PSK_KEY_EXCHANGE_MODES

        # Supported Versions Extension
        if version == TLS_1_3 or support == SUPPORT_1_2:
            all_extensions += self._supported_versions(
                support=support, grease=grease, extension_order=extension_order
            )

        # Finish assembly
        extension_length = len(all_extensions)
        extension_bytes += pack(">H", extension_length)
        extension_bytes += all_extensions
        return extension_bytes

    def _extension_host_name(self, dest_host: str) -> bytes:
        """"""
        ext_sni = Packet.DOUBLE_PAD
        ext_sni_length = len(dest_host) + 5
        ext_sni += pack(">H", ext_sni_length)
        ext_sni_length2 = len(dest_host) + 3
        ext_sni += pack(">H", ext_sni_length2)
        ext_sni += Packet.SINGLE_PAD
        ext_sni_length3 = len(dest_host)
        ext_sni += pack(">H", ext_sni_length3)
        ext_sni += dest_host.encode()
        return ext_sni

    def _app_layer_proto_negotiation(self, alpn: str, extension_order: str) -> bytes:
        """"""
        alpns: List[bytes] = []
        ext = Packet.ALPN_BASE
        alpn_set = ALPNS.get(alpn)
        if alpn_set is not None and isinstance(alpn_set, Alpns):
            alpns = alpn_set.values
        # Mung alpns
        alpns = self._reorder(pre_list=alpns, order=extension_order)
        all_alpns = b"".join(alpns)
        second_length = len(all_alpns)
        first_length = second_length + 2
        ext += pack(">H", first_length)
        ext += pack(">H", second_length)
        ext += all_alpns
        return ext

    def _key_share(self, grease: str):
        """"""
        ext: bytes = Packet.KEY_SHARE_BASE
        share_ext: bytes = b""

        if grease == GREASE:
            share_ext += random.choice(GREASE_VALUES)
            share_ext += Packet.KEY_SHARE_GREASE_PAD

        share_ext += Packet.KEY_SHARE_GROUP
        share_ext += Packet.KEY_SHARE_KEY_EXCHANGE_LENGTH
        share_ext += os.urandom(32)
        second_length = len(share_ext)
        first_length = second_length + 2
        ext += pack(">H", first_length)
        ext += pack(">H", second_length)
        ext += share_ext
        return ext

    def _supported_versions(self, support: str, grease: str, extension_order: str):
        """"""
        # TLS values
        tls: List[bytes] = (
            Packet.SUB_TLS_1_2_SUPPORT
            if support == SUPPORT_1_2
            else Packet.TLS_1_3_SUPPORT
        )
        # Mung
        tls = self._reorder(pre_list=tls, order=extension_order)
        ext: bytes = Packet.SUPPORTED_VERSION_BASE
        versions: bytes = b""

        # Add GREASE if necessary
        if grease == GREASE:
            versions = random.choice(GREASE_VALUES)

        versions += b"".join(tls)

        second_length = len(versions)
        first_length = second_length + 1
        ext += pack(">H", first_length)
        ext += pack(">B", second_length)
        ext += versions
        return ext

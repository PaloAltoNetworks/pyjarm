import hashlib
import logging
from typing import List

from jarm.constants import TOTAL_FAILURE


class Hasher:

    CIPHER_LIST: List[bytes] = [
        b"\x00\x04",
        b"\x00\x05",
        b"\x00\x07",
        b"\x00\x0a",
        b"\x00\x16",
        b"\x00\x2f",
        b"\x00\x33",
        b"\x00\x35",
        b"\x00\x39",
        b"\x00\x3c",
        b"\x00\x3d",
        b"\x00\x41",
        b"\x00\x45",
        b"\x00\x67",
        b"\x00\x6b",
        b"\x00\x84",
        b"\x00\x88",
        b"\x00\x9a",
        b"\x00\x9c",
        b"\x00\x9d",
        b"\x00\x9e",
        b"\x00\x9f",
        b"\x00\xba",
        b"\x00\xbe",
        b"\x00\xc0",
        b"\x00\xc4",
        b"\xc0\x07",
        b"\xc0\x08",
        b"\xc0\x09",
        b"\xc0\x0a",
        b"\xc0\x11",
        b"\xc0\x12",
        b"\xc0\x13",
        b"\xc0\x14",
        b"\xc0\x23",
        b"\xc0\x24",
        b"\xc0\x27",
        b"\xc0\x28",
        b"\xc0\x2b",
        b"\xc0\x2c",
        b"\xc0\x2f",
        b"\xc0\x30",
        b"\xc0\x60",
        b"\xc0\x61",
        b"\xc0\x72",
        b"\xc0\x73",
        b"\xc0\x76",
        b"\xc0\x77",
        b"\xc0\x9c",
        b"\xc0\x9d",
        b"\xc0\x9e",
        b"\xc0\x9f",
        b"\xc0\xa0",
        b"\xc0\xa1",
        b"\xc0\xa2",
        b"\xc0\xa3",
        b"\xc0\xac",
        b"\xc0\xad",
        b"\xc0\xae",
        b"\xc0\xaf",
        b"\xcc\x13",
        b"\xcc\x14",
        b"\xcc\xa8",
        b"\xcc\xa9",
        b"\x13\x01",
        b"\x13\x02",
        b"\x13\x03",
        b"\x13\x04",
        b"\x13\x05",
    ]

    @staticmethod
    def jarm(scan_result: str):
        """"""
        logging.debug(f"Raw JARM: {scan_result}")
        if scan_result == TOTAL_FAILURE:
            return "0" * 62
        fuzzy_hash = ""
        alpns_and_ext = ""
        for handshake in scan_result.split(","):
            components = handshake.split("|")
            # Custom jarm hash includes a fuzzy hash of the ciphers and versions
            fuzzy_hash += Hasher._cipher_bytes(components[0])
            fuzzy_hash += Hasher._version_byte(components[1])
            alpns_and_ext += components[2]
            alpns_and_ext += components[3]
        # Custom jarm hash has the sha256 of alpns and extensions added to the end
        sha256 = (hashlib.sha256(alpns_and_ext.encode())).hexdigest()
        fuzzy_hash += sha256[0:32]
        return fuzzy_hash

    @staticmethod
    def _cipher_bytes(cipher: str):
        if cipher == "":
            return "00"
        count = 1
        for bytes_ in Hasher.CIPHER_LIST:
            strtype_bytes = str(bytes_.hex())
            if cipher == strtype_bytes:
                break
            count += 1
        hexvalue = str(hex(count))[2:]
        # This part must always be two bytes
        if len(hexvalue) < 2:
            return_bytes = "0" + hexvalue
        else:
            return_bytes = hexvalue
        return return_bytes

    @staticmethod
    def _version_byte(version: str):
        if version == "":
            return "0"
        options = "abcdef"
        count = int(version[3:4])
        return options[count]

from collections import namedtuple
from typing import Dict, NamedTuple

from jarm.constants import SSL_V3, TLS_1, TLS_1_1, TLS_1_2, TLS_1_3

TLSVersion = namedtuple("TLSVersion", "name payload hello")

TLS_VERSIONS = {
    SSL_V3: TLSVersion(SSL_V3, b"\x03\x00", b"\x03\x00"),
    TLS_1: TLSVersion(TLS_1, b"\x03\x01", b"\x03\x01"),
    TLS_1_1: TLSVersion(TLS_1_1, b"\x03\x02", b"\x03\x02"),
    TLS_1_2: TLSVersion(TLS_1_2, b"\x03\x03", b"\x03\x03"),
    TLS_1_3: TLSVersion(TLS_1_3, b"\x03\x01", b"\x03\x03"),
}

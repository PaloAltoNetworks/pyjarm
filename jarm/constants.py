from typing import Set

# CONSTANTS
# TLS VERSIONS
SSL_V3: str = "SSLv3"
TLS_1: str = "TLS_1"
TLS_1_1: str = "TLS_1.1"
TLS_1_2: str = "TLS_1.2"
TLS_1_3: str = "TLS_1.3"
ALLOWED_TLS_VERSIONS: Set[str] = {
    SSL_V3,
    TLS_1,
    TLS_1_1,
    TLS_1_2,
    TLS_1_3,
}

# CIPHER LISTS
ALL: str = "ALL"
NO_1_3: str = "NO1.3"
ALLOWED_CIPHER_LISTS: Set[str] = {ALL, NO_1_3}

# GREASE
GREASE: str = "GREASE"
NO_GREASE: str = "NO_GREASE"

# APLN
ALPN: str = "ALPN"
RARE_ALPN: str = "RARE_ALPN"

# SUPPORT
SUPPORT_1_2: str = "1.2_SUPPPORT"
SUPPORT_1_3: str = "1.3_SUPPORT"
NO_SUPPORT: str = "NO_SUPPORT"
ALLOWED_SUPPORT: Set[str] = {
    SUPPORT_1_2,
    SUPPORT_1_3,
    NO_SUPPORT,
}

# EXTENSION ORDER
FORWARD = "FORWARD"
REVERSE = "REVERSE"
ALLOWED_EXTENSION_ORDER: Set[str] = {
    FORWARD,
    REVERSE,
}

# CIPHER ORDER
TOP_HALF = "TOP_HALF"
BOTTOM_HALF = "BOTTOM_HALF"
MIDDLE_OUT = "MIDDLE_OUT"
ALLOWED_CIPHER_ORDER: Set[str] = {
    FORWARD,
    REVERSE,
    TOP_HALF,
    BOTTOM_HALF,
    MIDDLE_OUT,
}

TOTAL_FAILURE: str = "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||"
FAILED_PACKET: str = "|||"
ERROR_INC_1: bytes = b"\x0e\xac\x0b"
ERROR_INC_2: bytes = b"\x0f\xf0\x0b"

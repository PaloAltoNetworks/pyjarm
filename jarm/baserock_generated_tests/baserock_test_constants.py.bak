import pytest
from typing import Set
from jarm.constants import (
    SSL_V3, TLS_1, TLS_1_1, TLS_1_2, TLS_1_3, ALLOWED_TLS_VERSIONS,
    ALL, NO_1_3, ALLOWED_CIPHER_LISTS,
    GREASE, NO_GREASE, ALPN, RARE_ALPN,
    SUPPORT_1_2, SUPPORT_1_3, NO_SUPPORT, ALLOWED_SUPPORT,
    FORWARD, REVERSE, ALLOWED_EXTENSION_ORDER,
    TOP_HALF, BOTTOM_HALF, MIDDLE_OUT, ALLOWED_CIPHER_ORDER,
    TOTAL_FAILURE, FAILED_PACKET,
    ERROR_INC_1, ERROR_INC_2,
    DEFAULT_TIMEOUT
)

class TestConstants:

    def test_tls_version_constants(self):
        assert SSL_V3 == "SSLv3"
        assert TLS_1 == "TLS_1"
        assert TLS_1_1 == "TLS_1.1"
        assert TLS_1_2 == "TLS_1.2"
        assert TLS_1_3 == "TLS_1.3"

    def test_allowed_tls_versions(self):
        expected_versions = {"SSLv3", "TLS_1", "TLS_1.1", "TLS_1.2", "TLS_1.3"}
        assert ALLOWED_TLS_VERSIONS == expected_versions
        assert isinstance(ALLOWED_TLS_VERSIONS, Set)

    def test_cipher_list_constants(self):
        assert ALL == "ALL"
        assert NO_1_3 == "NO1.3"

    def test_allowed_cipher_lists(self):
        expected_lists = {"ALL", "NO1.3"}
        assert ALLOWED_CIPHER_LISTS == expected_lists
        assert isinstance(ALLOWED_CIPHER_LISTS, Set)

    def test_grease_constants(self):
        assert GREASE == "GREASE"
        assert NO_GREASE == "NO_GREASE"

    def test_alpn_constants(self):
        assert ALPN == "ALPN"
        assert RARE_ALPN == "RARE_ALPN"

    def test_support_constants(self):
        assert SUPPORT_1_2 == "1.2_SUPPPORT"
        assert SUPPORT_1_3 == "1.3_SUPPORT"
        assert NO_SUPPORT == "NO_SUPPORT"

    def test_allowed_support(self):
        expected_support = {"1.2_SUPPPORT", "1.3_SUPPORT", "NO_SUPPORT"}
        assert ALLOWED_SUPPORT == expected_support
        assert isinstance(ALLOWED_SUPPORT, Set)

    def test_extension_order_constants(self):
        assert FORWARD == "FORWARD"
        assert REVERSE == "REVERSE"

    def test_allowed_extension_order(self):
        expected_order = {"FORWARD", "REVERSE"}
        assert ALLOWED_EXTENSION_ORDER == expected_order
        assert isinstance(ALLOWED_EXTENSION_ORDER, Set)

    def test_cipher_order_constants(self):
        assert TOP_HALF == "TOP_HALF"
        assert BOTTOM_HALF == "BOTTOM_HALF"
        assert MIDDLE_OUT == "MIDDLE_OUT"

    def test_allowed_cipher_order(self):
        expected_order = {"FORWARD", "REVERSE", "TOP_HALF", "BOTTOM_HALF", "MIDDLE_OUT"}
        assert ALLOWED_CIPHER_ORDER == expected_order
        assert isinstance(ALLOWED_CIPHER_ORDER, Set)

    def test_failure_constants(self):
        assert TOTAL_FAILURE == "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||"
        assert FAILED_PACKET == "|||"

    def test_error_constants(self):
        assert ERROR_INC_1 == b"\x0e\xac\x0b"
        assert ERROR_INC_2 == b"\x0f\xf0\x0b"

    def test_default_timeout(self):
        assert DEFAULT_TIMEOUT == 20
        assert isinstance(DEFAULT_TIMEOUT, int)

    def test_constant_immutability(self):
        with pytest.raises(AttributeError):
            SSL_V3 = "NewValue"
        
        with pytest.raises(AttributeError):
            ALLOWED_TLS_VERSIONS.add("NewVersion")

    def test_constant_types(self):
        assert isinstance(SSL_V3, str)
        assert isinstance(ALLOWED_TLS_VERSIONS, Set)
        assert isinstance(ALL, str)
        assert isinstance(ALLOWED_CIPHER_LISTS, Set)
        assert isinstance(GREASE, str)
        assert isinstance(ALLOWED_SUPPORT, Set)
        assert isinstance(FORWARD, str)
        assert isinstance(ALLOWED_EXTENSION_ORDER, Set)
        assert isinstance(ALLOWED_CIPHER_ORDER, Set)
        assert isinstance(TOTAL_FAILURE, str)
        assert isinstance(ERROR_INC_1, bytes)
        assert isinstance(DEFAULT_TIMEOUT, int)

    def test_set_contents(self):
        assert all(isinstance(item, str) for item in ALLOWED_TLS_VERSIONS)
        assert all(isinstance(item, str) for item in ALLOWED_CIPHER_LISTS)
        assert all(isinstance(item, str) for item in ALLOWED_SUPPORT)
        assert all(isinstance(item, str) for item in ALLOWED_EXTENSION_ORDER)
        assert all(isinstance(item, str) for item in ALLOWED_CIPHER_ORDER)

    def test_constant_uniqueness(self):
        all_constants = [
            SSL_V3, TLS_1, TLS_1_1, TLS_1_2, TLS_1_3,
            ALL, NO_1_3,
            GREASE, NO_GREASE, ALPN, RARE_ALPN,
            SUPPORT_1_2, SUPPORT_1_3, NO_SUPPORT,
            FORWARD, REVERSE,
            TOP_HALF, BOTTOM_HALF, MIDDLE_OUT,
            TOTAL_FAILURE, FAILED_PACKET
        ]
        assert len(all_constants) == len(set(all_constants))

    def test_set_uniqueness(self):
        for set_constant in [ALLOWED_TLS_VERSIONS, ALLOWED_CIPHER_LISTS, ALLOWED_SUPPORT, ALLOWED_EXTENSION_ORDER, ALLOWED_CIPHER_ORDER]:
            assert len(set_constant) == len(set(set_constant))

import pytest
from unittest.mock import Mock, patch
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
from jarm.formats.common import CommonTLSFormat

class TestCommonTLSFormat:

    @pytest.fixture
    def valid_params(self):
        return {
            "version": ALLOWED_TLS_VERSIONS[0],
            "cipher_list": ALLOWED_CIPHER_LISTS[0],
            "cipher_order": ALLOWED_CIPHER_ORDER[0],
            "is_grease": True,
            "is_rare_alpn": False,
            "support": ALLOWED_SUPPORT[0],
            "extension_order": ALLOWED_EXTENSION_ORDER[0],
        }

    def test_init_valid_parameters(self, valid_params):
        tls_format = CommonTLSFormat(**valid_params)
        assert isinstance(tls_format, CommonTLSFormat)

    @pytest.mark.parametrize("param,invalid_value", [
        ("version", "invalid_version"),
        ("cipher_list", "invalid_cipher_list"),
        ("cipher_order", "invalid_cipher_order"),
        ("support", "invalid_support"),
        ("extension_order", "invalid_extension_order"),
    ])
    def test_init_invalid_parameters(self, valid_params, param, invalid_value):
        invalid_params = valid_params.copy()
        invalid_params[param] = invalid_value
        with pytest.raises(PyJARMUnsupportValueException):
            CommonTLSFormat(**invalid_params)

    def test_build_packet(self, valid_params):
        tls_format = CommonTLSFormat(**valid_params)
        dest_host = "example.com"
        dest_port = 443
        packet = tls_format.build_packet(dest_host, dest_port)
        assert isinstance(packet, Packet)
        assert packet.dest_host == dest_host
        assert packet.dest_port == dest_port
        assert packet.jarm_hello_format == tls_format

    @pytest.mark.parametrize("attribute,expected_value", [
        ("version", ALLOWED_TLS_VERSIONS[0]),
        ("cipher_choice", ALLOWED_CIPHER_LISTS[0]),
        ("cipher_order", ALLOWED_CIPHER_ORDER[0]),
        ("grease", GREASE),
        ("support", ALLOWED_SUPPORT[0]),
        ("extension_order", ALLOWED_EXTENSION_ORDER[0]),
        ("alpn", ALPN),
    ])
    def test_properties(self, valid_params, attribute, expected_value):
        tls_format = CommonTLSFormat(**valid_params)
        assert getattr(tls_format, attribute) == expected_value

    def test_grease_property(self, valid_params):
        tls_format = CommonTLSFormat(**valid_params)
        assert tls_format.grease == GREASE

        no_grease_params = valid_params.copy()
        no_grease_params["is_grease"] = False
        tls_format_no_grease = CommonTLSFormat(**no_grease_params)
        assert tls_format_no_grease.grease == NO_GREASE

    def test_alpn_property(self, valid_params):
        tls_format = CommonTLSFormat(**valid_params)
        assert tls_format.alpn == ALPN

        rare_alpn_params = valid_params.copy()
        rare_alpn_params["is_rare_alpn"] = True
        tls_format_rare_alpn = CommonTLSFormat(**rare_alpn_params)
        assert tls_format_rare_alpn.alpn == RARE_ALPN

    @pytest.mark.parametrize("is_grease,is_rare_alpn,expected_grease,expected_alpn", [
        (True, True, GREASE, RARE_ALPN),
        (True, False, GREASE, ALPN),
        (False, True, NO_GREASE, RARE_ALPN),
        (False, False, NO_GREASE, ALPN),
    ])
    def test_grease_and_alpn_combinations(self, valid_params, is_grease, is_rare_alpn, expected_grease, expected_alpn):
        params = valid_params.copy()
        params["is_grease"] = is_grease
        params["is_rare_alpn"] = is_rare_alpn
        tls_format = CommonTLSFormat(**params)
        assert tls_format.grease == expected_grease
        assert tls_format.alpn == expected_alpn

    @patch('jarm.packet.packet.Packet')
    def test_build_packet_mocked(self, mock_packet, valid_params):
        tls_format = CommonTLSFormat(**valid_params)
        dest_host = "example.com"
        dest_port = 443
        mock_packet_instance = Mock()
        mock_packet.return_value = mock_packet_instance

        packet = tls_format.build_packet(dest_host, dest_port)

        mock_packet.assert_called_once_with(dest_host=dest_host, dest_port=dest_port, jarm_hello_format=tls_format)
        assert packet == mock_packet_instance

    # New test cases to improve coverage

    def test_client_suites_length_property(self, valid_params):
        tls_format = CommonTLSFormat(**valid_params)
        assert hasattr(tls_format, 'client_suites_length')
        assert isinstance(tls_format.client_suites_length, str)

    def test_str_method(self, valid_params):
        tls_format = CommonTLSFormat(**valid_params)
        str_representation = str(tls_format)
        assert isinstance(str_representation, str)
        assert all(param in str_representation for param in valid_params.keys())

    @pytest.mark.parametrize("param", ["cipher_list", "cipher_order", "extension_order"])
    def test_empty_string_parameters(self, valid_params, param):
        params = valid_params.copy()
        params[param] = ""
        with pytest.raises(PyJARMUnsupportValueException):
            CommonTLSFormat(**params)

    @pytest.mark.parametrize("param", ["cipher_list", "cipher_order", "extension_order", "support"])
    def test_none_parameters(self, valid_params, param):
        params = valid_params.copy()
        params[param] = None
        with pytest.raises(PyJARMUnsupportValueException):
            CommonTLSFormat(**params)

    # Additional test cases for improved coverage

    def test_client_suites_length_value(self, valid_params):
        tls_format = CommonTLSFormat(**valid_params)
        assert tls_format.client_suites_length != ""
        assert len(tls_format.client_suites_length) > 0

    def test_str_method_content(self, valid_params):
        tls_format = CommonTLSFormat(**valid_params)
        str_representation = str(tls_format)
        for key, value in valid_params.items():
            assert f"{key}={value}" in str_representation

    @pytest.mark.parametrize("param", ["version", "cipher_list", "cipher_order", "support", "extension_order"])
    def test_invalid_type_parameters(self, valid_params, param):
        params = valid_params.copy()
        params[param] = 123  # Invalid type (int instead of str)
        with pytest.raises(PyJARMUnsupportValueException):
            CommonTLSFormat(**params)

    def test_is_grease_and_is_rare_alpn_type_check(self, valid_params):
        params = valid_params.copy()
        params["is_grease"] = "True"  # Should be boolean
        params["is_rare_alpn"] = "False"  # Should be boolean
        with pytest.raises(TypeError):
            CommonTLSFormat(**params)

    @pytest.mark.parametrize("cipher_list", ALLOWED_CIPHER_LISTS)
    def test_all_allowed_cipher_lists(self, valid_params, cipher_list):
        params = valid_params.copy()
        params["cipher_list"] = cipher_list
        tls_format = CommonTLSFormat(**params)
        assert tls_format.cipher_choice == cipher_list

    @pytest.mark.parametrize("tls_version", ALLOWED_TLS_VERSIONS)
    def test_all_allowed_tls_versions(self, valid_params, tls_version):
        params = valid_params.copy()
        params["version"] = tls_version
        tls_format = CommonTLSFormat(**params)
        assert tls_format.version == tls_version
import pytest
from unittest.mock import patch, Mock
import hashlib
from jarm.constants import TOTAL_FAILURE
from jarm.hashing.hashing import Hasher

@pytest.fixture
def sample_scan_result():
    return "00|1.1|h2|alpn,00|1.2|h2|alpn,00|1.3|h2|alpn"

def test_jarm_with_total_failure():
    result = Hasher.jarm(TOTAL_FAILURE)
    assert result == "0" * 62

def test_jarm_with_valid_scan_result(sample_scan_result):
    result = Hasher.jarm(sample_scan_result)
    assert len(result) == 62
    assert all(c in "0123456789abcdef" for c in result)

def test_jarm_with_empty_scan_result():
    result = Hasher.jarm("")
    assert len(result) == 62
    assert all(c in "0123456789abcdef" for c in result)

@pytest.mark.parametrize("cipher,expected", [
    ("", "00"),
    ("0004", "01"),
    ("0005", "02"),
    ("1305", "44"),
])
def test_cipher_bytes(cipher, expected):
    result = Hasher._cipher_bytes(cipher)
    assert result == expected

@pytest.mark.parametrize("version,expected", [
    ("", "0"),
    ("1.0", "a"),
    ("1.1", "b"),
    ("1.2", "c"),
    ("1.3", "d"),
    ("1.4", "e"),
    ("1.5", "f"),
])
def test_version_byte(version, expected):
    result = Hasher._version_byte(version)
    assert result == expected

def test_jarm_logging(sample_scan_result):
    with patch('logging.debug') as mock_debug:
        Hasher.jarm(sample_scan_result)
        mock_debug.assert_called_once_with(f"Raw JARM: {sample_scan_result}")

def test_jarm_sha256_calculation(sample_scan_result):
    with patch('hashlib.sha256') as mock_sha256:
        mock_sha256.return_value.hexdigest.return_value = 'a' * 64
        result = Hasher.jarm(sample_scan_result)
        assert result.endswith('a' * 32)

def test_jarm_with_invalid_scan_result():
    invalid_result = "invalid|format|data"
    with pytest.raises(IndexError):
        Hasher.jarm(invalid_result)

def test_cipher_bytes_with_unknown_cipher():
    unknown_cipher = "ffff"
    result = Hasher._cipher_bytes(unknown_cipher)
    assert result == "44"  # Assuming the list has 68 elements

@pytest.mark.parametrize("version", ["2.0", "3.0", "4.0"])
def test_version_byte_with_invalid_version(version):
    with pytest.raises(IndexError):
        Hasher._version_byte(version)

def test_jarm_integration():
    scan_result = "0004|1.1|h2|alpn,0005|1.2|h3|ext,0007|1.3|h2h3|alpn,ext"
    result = Hasher.jarm(scan_result)
    assert len(result) == 62
    assert result[:6] == "010203"  # First three cipher bytes
    assert result[6:9] == "bcd"    # Three version bytes
    # The rest should be a valid hex string (SHA256 hash)
    assert all(c in "0123456789abcdef" for c in result[9:])

def test_cipher_list_immutability():
    original_list = Hasher.CIPHER_LIST.copy()
    with pytest.raises(AttributeError):
        Hasher.CIPHER_LIST = []
    assert Hasher.CIPHER_LIST == original_list

def test_jarm_with_maximum_ciphers():
    max_ciphers = ",".join([f"{cipher.hex()}|1.1|h2|alpn" for cipher in Hasher.CIPHER_LIST])
    result = Hasher.jarm(max_ciphers)
    assert len(result) == 62
    assert all(c in "0123456789abcdef" for c in result)

def test_jarm_performance():
    import time
    scan_result = "0004|1.1|h2|alpn," * 1000  # Large input
    start_time = time.time()
    Hasher.jarm(scan_result)
    end_time = time.time()
    assert end_time - start_time < 1.0  # Assuming it should complete within 1 second

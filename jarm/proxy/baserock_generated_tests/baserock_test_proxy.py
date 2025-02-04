import pytest
from unittest.mock import patch, MagicMock
from urllib.parse import urlparse
from base64 import b64encode
from jarm.exceptions.exceptions import PyJARMProxyError
from jarm.proxy.proxy import Proxy

@pytest.fixture
def mock_reader():
    return MagicMock(spec=asyncio.StreamReader)

@pytest.fixture
def mock_writer():
    return MagicMock(spec=asyncio.StreamWriter)

class TestProxy:
    def test_get_http_headers(self):
        assert Proxy.get_http_headers() == {}

    @pytest.mark.parametrize("input_proxy,expected_result", [
        (None, urlparse("https://proxy.example.com")),
        ("ignore", None),
        ("http://custom.proxy.com", urlparse("http://custom.proxy.com")),
    ])
    def test_parse_proxy(self, input_proxy, expected_result):
        with patch('jarm.proxy.proxy.getproxies') as mock_getproxies:
            mock_getproxies.return_value = {"https": "https://proxy.example.com"}
            result = Proxy.parse_proxy(input_proxy)
            assert result == expected_result

    @pytest.mark.asyncio
    async def test_handle_proxy_success(self, mock_reader, mock_writer):
        mock_reader.readline.side_effect = [
            b"HTTP/1.1 200 OK\r\n",
            b"Header: Value\r\n",
            b"\r\n"
        ]
        
        await Proxy.handle_proxy(
            mock_reader,
            mock_writer,
            "example.com:443",
            auth="Bearer token123"
        )
        
        expected_buf = (
            "CONNECT example.com:443 HTTP/1.1\r\n"
            "Proxy-Authorization: Bearer token123\r\n"
            "Host: example.com:443\r\n\r\n"
        )
        mock_writer.write.assert_called_once_with(expected_buf.encode())
        mock_writer.drain.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_proxy_with_username_password(self, mock_reader, mock_writer):
        mock_reader.readline.side_effect = [
            b"HTTP/1.1 200 OK\r\n",
            b"\r\n"
        ]
        
        await Proxy.handle_proxy(
            mock_reader,
            mock_writer,
            "example.com:443",
            username="user",
            password="pass"
        )
        
        expected_auth = f"Basic {b64encode(b'user:pass').decode()}"
        expected_buf = (
            "CONNECT example.com:443 HTTP/1.1\r\n"
            f"Proxy-Authorization: {expected_auth}\r\n"
            "Host: example.com:443\r\n\r\n"
        )
        mock_writer.write.assert_called_once_with(expected_buf.encode())

    @pytest.mark.asyncio
    async def test_handle_proxy_no_status(self, mock_reader, mock_writer):
        mock_reader.readline.return_value = b""
        
        with pytest.raises(PyJARMProxyError, match="No status line received from Proxy"):
            await Proxy.handle_proxy(mock_reader, mock_writer, "example.com:443")

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status_line,error_message", [
        (b"HTTP/1.0 200 OK\r\n", "Invalid Proxy Response: b'HTTP/1.0 200 OK\\r\\n'"),
        (b"HTTP/1.1 403 Forbidden\r\n", "Invalid Proxy Response: b'HTTP/1.1 403 Forbidden\\r\\n'"),
        (b"Invalid Response\r\n", "Invalid Proxy Response: b'Invalid Response\\r\\n'"),
    ])
    async def test_handle_proxy_invalid_response(self, mock_reader, mock_writer, status_line, error_message):
        mock_reader.readline.side_effect = [status_line, b"\r\n"]
        
        with pytest.raises(PyJARMProxyError, match=error_message):
            await Proxy.handle_proxy(mock_reader, mock_writer, "example.com:443")

    @pytest.mark.asyncio
    async def test_handle_proxy_custom_headers(self, mock_reader, mock_writer):
        mock_reader.readline.side_effect = [
            b"HTTP/1.1 200 OK\r\n",
            b"\r\n"
        ]
        
        custom_headers = {"User-Agent": "CustomAgent/1.0"}
        await Proxy.handle_proxy(
            mock_reader,
            mock_writer,
            "example.com:443",
            headers=custom_headers
        )
        
        expected_buf = (
            "CONNECT example.com:443 HTTP/1.1\r\n"
            "User-Agent: CustomAgent/1.0\r\n"
            "Host: example.com:443\r\n\r\n"
        )
        mock_writer.write.assert_called_once_with(expected_buf.encode())
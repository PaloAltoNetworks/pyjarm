import pytest
from unittest.mock import patch, MagicMock
from urllib.parse import urlparse
from base64 import b64encode
import asyncio
from jarm.exceptions.exceptions import PyJARMProxyError
from proxy.prox import Proxy

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
        with patch('proxy.prox.getproxies') as mock_getproxies:
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
        
        mock_writer.write.assert_called_once()
        assert b"CONNECT example.com:443 HTTP/1.1" in mock_writer.write.call_args[0][0]
        assert b"Proxy-Authorization: Bearer token123" in mock_writer.write.call_args[0][0]

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
        
        mock_writer.write.assert_called_once()
        expected_auth = b64encode(b"user:pass").decode()
        assert f"Proxy-Authorization: Basic {expected_auth}".encode() in mock_writer.write.call_args[0][0]

    @pytest.mark.asyncio
    async def test_handle_proxy_no_status(self, mock_reader, mock_writer):
        mock_reader.readline.return_value = b""
        
        with pytest.raises(PyJARMProxyError, match="No status line received from Proxy"):
            await Proxy.handle_proxy(mock_reader, mock_writer, "example.com:443")

    @pytest.mark.asyncio
    async def test_handle_proxy_invalid_response(self, mock_reader, mock_writer):
        mock_reader.readline.side_effect = [
            b"HTTP/1.1 403 Forbidden\r\n",
            b"\r\n"
        ]
        
        with pytest.raises(PyJARMProxyError, match="Invalid Proxy Response"):
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
        
        mock_writer.write.assert_called_once()
        assert b"User-Agent: CustomAgent/1.0" in mock_writer.write.call_args[0][0]

    def test_parse_proxy_empty_string(self):
        result = Proxy.parse_proxy("")
        assert result is None

    @pytest.mark.asyncio
    async def test_handle_proxy_multiple_headers(self, mock_reader, mock_writer):
        mock_reader.readline.side_effect = [
            b"HTTP/1.1 200 OK\r\n",
            b"Header1: Value1\r\n",
            b"Header2: Value2\r\n",
            b"\r\n"
        ]
        
        await Proxy.handle_proxy(mock_reader, mock_writer, "example.com:443")
        
        mock_writer.write.assert_called_once()
        assert mock_reader.readline.call_count == 4

    # New test cases to improve coverage

    def test_parse_proxy_with_custom_proxy(self):
        custom_proxy = "http://custom.proxy.com:8080"
        result = Proxy.parse_proxy(custom_proxy)
        assert result == urlparse(custom_proxy)

    def test_parse_proxy_with_none_and_no_system_proxy(self):
        with patch('proxy.prox.getproxies', return_value={}):
            result = Proxy.parse_proxy(None)
            assert result is None

    @pytest.mark.asyncio
    async def test_handle_proxy_with_auth_and_custom_headers(self, mock_reader, mock_writer):
        mock_reader.readline.side_effect = [
            b"HTTP/1.1 200 OK\r\n",
            b"\r\n"
        ]
        
        custom_headers = {"User-Agent": "CustomAgent/1.0"}
        await Proxy.handle_proxy(
            mock_reader,
            mock_writer,
            "example.com:443",
            auth="Bearer token123",
            headers=custom_headers
        )
        
        mock_writer.write.assert_called_once()
        written_data = mock_writer.write.call_args[0][0]
        assert b"CONNECT example.com:443 HTTP/1.1" in written_data
        assert b"Proxy-Authorization: Bearer token123" in written_data
        assert b"User-Agent: CustomAgent/1.0" in written_data

    @pytest.mark.asyncio
    async def test_handle_proxy_invalid_response_format(self, mock_reader, mock_writer):
        mock_reader.readline.side_effect = [
            b"Invalid Response Format\r\n",
            b"\r\n"
        ]
        
        with pytest.raises(PyJARMProxyError, match="Invalid Proxy Response"):
            await Proxy.handle_proxy(mock_reader, mock_writer, "example.com:443")

    @pytest.mark.asyncio
    async def test_handle_proxy_non_200_status(self, mock_reader, mock_writer):
        mock_reader.readline.side_effect = [
            b"HTTP/1.1 302 Found\r\n",
            b"\r\n"
        ]
        
        with pytest.raises(PyJARMProxyError, match="Invalid Proxy Response"):
            await Proxy.handle_proxy(mock_reader, mock_writer, "example.com:443")

    @pytest.mark.asyncio
    async def test_handle_proxy_with_empty_headers(self, mock_reader, mock_writer):
        mock_reader.readline.side_effect = [
            b"HTTP/1.1 200 OK\r\n",
            b"\r\n"
        ]
        
        await Proxy.handle_proxy(
            mock_reader,
            mock_writer,
            "example.com:443",
            headers={}
        )
        
        mock_writer.write.assert_called_once()
        written_data = mock_writer.write.call_args[0][0]
        assert b"CONNECT example.com:443 HTTP/1.1" in written_data
        assert b"Host: example.com:443" in written_data
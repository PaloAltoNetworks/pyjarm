import pytest
import asyncio
import socket
import ssl
from unittest.mock import patch, MagicMock, AsyncMock
from typing import Dict, Any, Tuple

from jarm.constants import DEFAULT_TIMEOUT
from jarm.exceptions.exceptions import PyJARMInvalidProxy
from jarm.proxy.proxy import Proxy
from connection.connection import Connection

# Existing fixtures and tests...

class TestConnection:
    # Existing tests...

    @pytest.mark.asyncio
    async def test_jarm_connect_af_inet6(self, mock_validate_target):
        mock_validate_target.return_value = (socket.AF_INET6, None, None, None, ("2001:db8::1", 443))

        with patch.object(Connection, 'jarm_data', new_callable=AsyncMock) as mock_jarm_data:
            mock_jarm_data.return_value = b"mock_ipv6_response"

            target = ("example.com", 443)
            connect_args: Dict[str, Any] = {"address_family": Connection.AddressFamily.AF_INET6}
            data = b"test_data"
            check = "test_check"

            result = await Connection.jarm_connect(target, connect_args, data, check)

            assert result == ("test_check", b"mock_ipv6_response")
            mock_validate_target.assert_called_once_with("example.com", 443, Connection.AddressFamily.AF_INET6)
            mock_jarm_data.assert_called_once()

    @pytest.mark.asyncio
    async def test_jarm_connect_custom_timeout(self, mock_validate_target):
        mock_validate_target.return_value = (socket.AF_INET, None, None, None, ("192.0.2.1", 443))

        with patch.object(Connection, 'jarm_data', new_callable=AsyncMock) as mock_jarm_data:
            mock_jarm_data.return_value = b"mock_response"

            target = ("example.com", 443)
            custom_timeout = 60
            connect_args: Dict[str, Any] = {"timeout": custom_timeout}
            data = b"test_data"
            check = "test_check"

            result = await Connection.jarm_connect(target, connect_args, data, check)

            assert result == ("test_check", b"mock_response")
            mock_validate_target.assert_called_once_with("example.com", 443, Connection.AddressFamily.AF_ANY)
            mock_jarm_data.assert_called_once()
            args, kwargs = mock_jarm_data.call_args
            assert kwargs.get('timeout') == custom_timeout

    @pytest.mark.asyncio
    async def test_jarm_connect_https_proxy_with_verify(self):
        with patch.object(Proxy, 'parse_proxy') as mock_parse_proxy, \
             patch.object(Connection, 'jarm_data', new_callable=AsyncMock) as mock_jarm_data, \
             patch('ssl.create_default_context') as mock_ssl_context:

            mock_proxy = MagicMock()
            mock_proxy.hostname = "proxy.example.com"
            mock_proxy.scheme = "https"
            mock_proxy.port = 8443
            mock_parse_proxy.return_value = mock_proxy

            mock_ssl_context = MagicMock()
            mock_ssl_context.return_value = mock_ssl_context

            mock_jarm_data.return_value = b"mock_https_proxy_response"

            target = ("example.com", 443)
            connect_args: Dict[str, Any] = {
                "timeout": 30,
                "verify": True,
                "proxy": "https://proxy.example.com:8443",
                "proxy_auth": "basic"
            }
            data = b"test_data"
            check = "test_check"

            result = await Connection.jarm_connect(target, connect_args, data, check)

            assert result == ("test_check", b"mock_https_proxy_response")
            mock_parse_proxy.assert_called_once_with("https://proxy.example.com:8443")
            mock_ssl_context.assert_called_once()
            assert mock_ssl_context.verify_mode != ssl.CERT_NONE
            mock_jarm_data.assert_called_once()

    @pytest.mark.asyncio
    async def test_jarm_connect_proxy_with_auth(self):
        with patch.object(Proxy, 'parse_proxy') as mock_parse_proxy, \
             patch.object(Connection, 'jarm_data', new_callable=AsyncMock) as mock_jarm_data:

            mock_proxy = MagicMock()
            mock_proxy.hostname = "proxy.example.com"
            mock_proxy.scheme = "http"
            mock_proxy.port = 8080
            mock_proxy.username = "user"
            mock_proxy.password = "pass"
            mock_parse_proxy.return_value = mock_proxy

            mock_jarm_data.return_value = b"mock_proxy_auth_response"

            target = ("example.com", 443)
            connect_args: Dict[str, Any] = {
                "timeout": 30,
                "verify": True,
                "proxy": "http://user:pass@proxy.example.com:8080",
                "proxy_auth": "basic"
            }
            data = b"test_data"
            check = "test_check"

            result = await Connection.jarm_connect(target, connect_args, data, check)

            assert result == ("test_check", b"mock_proxy_auth_response")
            mock_parse_proxy.assert_called_once_with("http://user:pass@proxy.example.com:8080")
            mock_jarm_data.assert_called_once()
            args, kwargs = mock_jarm_data.call_args
            assert kwargs['conn_target']['proxy_username'] == "user"
            assert kwargs['conn_target']['proxy_password'] == "pass"

    @pytest.mark.asyncio
    async def test_jarm_connect_partial_timeout(self, mock_validate_target):
        mock_validate_target.return_value = (socket.AF_INET, None, None, None, ("192.0.2.1", 443))

        with patch.object(Connection, 'jarm_data', new_callable=AsyncMock) as mock_jarm_data:
            mock_jarm_data.side_effect = [asyncio.TimeoutError(), b"delayed_response"]

            target = ("example.com", 443)
            connect_args: Dict[str, Any] = {"timeout": 2}
            data = b"test_data"
            check = "test_check"

            start_time = asyncio.get_event_loop().time()
            result = await Connection.jarm_connect(target, connect_args, data, check)
            end_time = asyncio.get_event_loop().time()

            assert result == ("test_check", b"")
            mock_validate_target.assert_called_once_with("example.com", 443, Connection.AddressFamily.AF_ANY)
            assert mock_jarm_data.call_count == 1
            
            # Verify that the function took approximately 2 seconds (with some tolerance)
            assert 1.9 <= (end_time - start_time) <= 2.1

    @pytest.mark.asyncio
    async def test_jarm_connect_invalid_proxy_scheme(self):
        with patch.object(Proxy, 'parse_proxy') as mock_parse_proxy:
            mock_proxy = MagicMock()
            mock_proxy.hostname = "proxy.example.com"
            mock_proxy.scheme = "ftp"
            mock_parse_proxy.return_value = mock_proxy

            target = ("example.com", 443)
            connect_args: Dict[str, Any] = {"proxy": "ftp://proxy.example.com"}
            data = b"test_data"
            check = "test_check"

            with pytest.raises(PyJARMInvalidProxy, match="Invalid proxy connection scheme"):
                await Connection.jarm_connect(target, connect_args, data, check)

    @pytest.mark.asyncio
    async def test_jarm_connect_default_proxy_ports(self):
        with patch.object(Proxy, 'parse_proxy') as mock_parse_proxy, \
             patch.object(Connection, 'jarm_data', new_callable=AsyncMock) as mock_jarm_data:

            # Test HTTP proxy with default port
            mock_proxy_http = MagicMock()
            mock_proxy_http.hostname = "proxy.example.com"
            mock_proxy_http.scheme = "http"
            mock_proxy_http.port = None
            mock_parse_proxy.return_value = mock_proxy_http

            target = ("example.com", 443)
            connect_args: Dict[str, Any] = {"proxy": "http://proxy.example.com"}
            data = b"test_data"
            check = "test_check"

            await Connection.jarm_connect(target, connect_args, data, check)
            args, kwargs = mock_jarm_data.call_args
            assert kwargs['conn_target']['connect_port'] == 8080

            # Test HTTPS proxy with default port
            mock_proxy_https = MagicMock()
            mock_proxy_https.hostname = "proxy.example.com"
            mock_proxy_https.scheme = "https"
            mock_proxy_https.port = None
            mock_parse_proxy.return_value = mock_proxy_https

            connect_args = {"proxy": "https://proxy.example.com", "verify": False}

            await Connection.jarm_connect(target, connect_args, data, check)
            args, kwargs = mock_jarm_data.call_args
            assert kwargs['conn_target']['connect_port'] == 8443

    @pytest.mark.asyncio
    async def test_jarm_connect_address_family_precedence(self, mock_validate_target):
        mock_validate_target.return_value = (socket.AF_INET, None, None, None, ("192.0.2.1", 443))

        with patch.object(Connection, 'jarm_data', new_callable=AsyncMock) as mock_jarm_data:
            mock_jarm_data.return_value = b"mock_response"

            target = ("example.com", 443)
            connect_args: Dict[str, Any] = {"address_family": Connection.AddressFamily.AF_INET}
            data = b"test_data"
            check = "test_check"

            result = await Connection.jarm_connect(target, connect_args, data, check)

            assert result == ("test_check", b"mock_response")
            mock_validate_target.assert_called_once_with("example.com", 443, Connection.AddressFamily.AF_INET)
            mock_jarm_data.assert_called_once()

    @pytest.mark.asyncio
    async def test_jarm_connect_empty_response(self, mock_validate_target):
        mock_validate_target.return_value = (socket.AF_INET, None, None, None, ("192.0.2.1", 443))

        with patch.object(Connection, 'jarm_data', new_callable=AsyncMock) as mock_jarm_data:
            mock_jarm_data.return_value = b""

            target = ("example.com", 443)
            connect_args: Dict[str, Any] = {}
            data = b"test_data"
            check = "test_check"

            result = await Connection.jarm_connect(target, connect_args, data, check)

            assert result == ("test_check", b"")
            mock_validate_target.assert_called_once_with("example.com", 443, Connection.AddressFamily.AF_ANY)
            mock_jarm_data.assert_called_once()

# ... (keep existing tests)
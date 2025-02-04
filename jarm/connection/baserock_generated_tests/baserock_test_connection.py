import asyncio
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from typing import Dict, Any

from jarm.connection.connection import Connection
from jarm.proxy.proxy import Proxy
from jarm.exceptions.exceptions import PyJARMInvalidProxy
from jarm.constants import DEFAULT_TIMEOUT

@pytest.mark.asyncio
async def test_prep_connection():
    connect_target = {
        "connect_host": "example.com",
        "connect_port": 443,
        "use_proxy": False
    }
    
    with patch('asyncio.open_connection', new_callable=AsyncMock) as mock_open_connection:
        mock_reader, mock_writer = MagicMock(), MagicMock()
        mock_open_connection.return_value = (mock_reader, mock_writer)
        
        reader, writer = await Connection.prep_connection(connect_target)
        
        assert reader == mock_reader
        assert writer == mock_writer
        mock_open_connection.assert_called_once_with(
            host="example.com",
            port=443,
            ssl=None,
            server_hostname=None,
            family=0
        )

@pytest.mark.asyncio
async def test_prep_connection_with_proxy():
    connect_target = {
        "connect_host": "example.com",
        "connect_port": 443,
        "use_proxy": True,
        "target_host": "target.com",
        "target_port": 8080,
        "proxy_auth": "basic_auth"
    }
    
    with patch('asyncio.open_connection', new_callable=AsyncMock) as mock_open_connection, \
         patch('jarm.proxy.proxy.Proxy.handle_proxy', new_callable=AsyncMock) as mock_handle_proxy:
        mock_reader, mock_writer = MagicMock(), MagicMock()
        mock_open_connection.return_value = (mock_reader, mock_writer)
        
        reader, writer = await Connection.prep_connection(connect_target)
        
        assert reader == mock_reader
        assert writer == mock_writer
        mock_open_connection.assert_called_once_with(
            host="example.com",
            port=443,
            ssl=None,
            server_hostname=None,
            family=0
        )
        mock_handle_proxy.assert_called_once_with(
            "target.com:8080",
            mock_writer,
            auth="basic_auth"
        )

@pytest.mark.asyncio
async def test_jarm_data():
    conn_target = {
        "connect_host": "example.com",
        "connect_port": 443
    }
    data = b"test_data"
    
    with patch('jarm.connection.connection.Connection.prep_connection', new_callable=AsyncMock) as mock_prep_connection:
        mock_reader, mock_writer = AsyncMock(), AsyncMock()
        mock_prep_connection.return_value = (mock_reader, mock_writer)
        mock_reader.read.return_value = b"response_data"
        
        result = await Connection.jarm_data(conn_target, data)
        
        assert result == b"response_data"
        mock_writer.write.assert_called_once_with(data)
        mock_writer.drain.assert_called_once()
        mock_reader.read.assert_called_once_with(1484)
        mock_writer.close.assert_called_once()
        mock_writer.wait_closed.assert_called_once()

@pytest.mark.asyncio
async def test_jarm_connect():
    target = ("example.com", 443)
    connect_args: Dict[str, Any] = {
        "address_family": Connection.AddressFamily.AF_INET,
        "timeout": 30,
        "verify": True
    }
    data = b"test_data"
    check = "test_check"
    
    with patch('jarm.connection.connection.Connection.jarm_data', new_callable=AsyncMock) as mock_jarm_data, \
         patch('jarm.validate.validate.Validate.validate_target') as mock_validate_target:
        mock_jarm_data.return_value = b"mock_response"
        mock_validate_target.return_value = (2, None, None, None, ("192.0.2.1", 443))
        
        result = await Connection.jarm_connect(target, connect_args, data, check)
        
        assert result == ("test_check", b"mock_response")
        mock_validate_target.assert_called_once_with(target, Connection.AddressFamily.AF_INET)
        mock_jarm_data.assert_called_once()

@pytest.mark.asyncio
async def test_jarm_connect_with_proxy():
    target = ("example.com", 443)
    connect_args = {
        "address_family": Connection.AddressFamily.AF_INET,
        "timeout": 30,
        "verify": True,
        "proxy": "http://proxy.example.com:8080",
        "proxy_auth": "basic"
    }
    data = b"test_data"
    check = "test_check"
    
    with patch('jarm.connection.connection.Connection.jarm_data', new_callable=AsyncMock) as mock_jarm_data, \
         patch('jarm.proxy.proxy.Proxy.parse_proxy') as mock_parse_proxy, \
         patch('jarm.validate.validate.Validate.validate_target') as mock_validate_target:
        mock_jarm_data.return_value = b"mock_response"
        mock_proxy = MagicMock()
        mock_proxy.scheme = "http"
        mock_proxy.hostname = "proxy.example.com"
        mock_proxy.port = 8080
        mock_proxy.username = None
        mock_proxy.password = None
        mock_parse_proxy.return_value = mock_proxy
        mock_validate_target.return_value = (2, None, None, None, ("192.0.2.1", 443))
        
        result = await Connection.jarm_connect(target, connect_args, data, check)
        
        assert result == ("test_check", b"mock_response")
        mock_parse_proxy.assert_called_once_with("http://proxy.example.com:8080")
        mock_validate_target.assert_called_once_with(target, Connection.AddressFamily.AF_INET)
        mock_jarm_data.assert_called_once()

@pytest.mark.asyncio
async def test_jarm_connect_invalid_proxy_hostname():
    target = ("example.com", 443)
    connect_args = {
        "address_family": Connection.AddressFamily.AF_INET,
        "timeout": 30,
        "verify": True,
        "proxy": "http://:8080"  # Invalid proxy (missing hostname)
    }
    data = b"test_data"
    check = "test_check"
    
    with patch('jarm.proxy.proxy.Proxy.parse_proxy') as mock_parse_proxy, \
         patch('jarm.validate.validate.Validate.validate_target') as mock_validate_target:
        mock_proxy = MagicMock()
        mock_proxy.scheme = "http"
        mock_proxy.hostname = ""
        mock_proxy.port = 8080
        mock_parse_proxy.return_value = mock_proxy
        mock_validate_target.return_value = (2, None, None, None, ("192.0.2.1", 443))
        
        with pytest.raises(PyJARMInvalidProxy, match="Invalid or missing proxy hostname"):
            await Connection.jarm_connect(target, connect_args, data, check)

@pytest.mark.asyncio
async def test_jarm_connect_invalid_proxy_scheme():
    target = ("example.com", 443)
    connect_args = {
        "address_family": Connection.AddressFamily.AF_INET,
        "timeout": 30,
        "verify": True,
        "proxy": "ftp://proxy.example.com:8080"  # Invalid proxy scheme
    }
    data = b"test_data"
    check = "test_check"
    
    with patch('jarm.proxy.proxy.Proxy.parse_proxy') as mock_parse_proxy, \
         patch('jarm.validate.validate.Validate.validate_target') as mock_validate_target:
        mock_proxy = MagicMock()
        mock_proxy.scheme = "ftp"
        mock_proxy.hostname = "proxy.example.com"
        mock_proxy.port = 8080
        mock_parse_proxy.return_value = mock_proxy
        mock_validate_target.return_value = (2, None, None, None, ("192.0.2.1", 443))
        
        with pytest.raises(PyJARMInvalidProxy, match="Invalid proxy connection scheme"):
            await Connection.jarm_connect(target, connect_args, data, check)

@pytest.mark.asyncio
async def test_jarm_connect_timeout():
    target = ("example.com", 443)
    connect_args = {
        "address_family": Connection.AddressFamily.AF_INET,
        "timeout": 1,
        "verify": True
    }
    data = b"test_data"
    check = "test_check"
    
    with patch('jarm.connection.connection.Connection.jarm_data', new_callable=AsyncMock) as mock_jarm_data, \
         patch('jarm.validate.validate.Validate.validate_target') as mock_validate_target:
        mock_jarm_data.side_effect = asyncio.TimeoutError()
        mock_validate_target.return_value = (2, None, None, None, ("192.0.2.1", 443))
        
        result = await Connection.jarm_connect(target, connect_args, data, check)
        
        assert result == ("test_check", b"")
        mock_validate_target.assert_called_once_with(target, Connection.AddressFamily.AF_INET)
        mock_jarm_data.assert_called_once()

def test_address_family():
    assert Connection.AddressFamily.AF_ANY == 0
    assert Connection.AddressFamily.AF_INET == 2
    assert Connection.AddressFamily.AF_INET6 == 10

@pytest.mark.asyncio
async def test_jarm_connect_invalid_address_family():
    target = ("example.com", 443)
    connect_args = {
        "address_family": 999,  # Invalid address family
        "timeout": 30,
        "verify": True
    }
    data = b"test_data"
    check = "test_check"
    
    with pytest.raises(ValueError, match="AddressFamily not supported"):
        await Connection.jarm_connect(target, connect_args, data, check)

@pytest.mark.asyncio
async def test_jarm_connect_invalid_timeout():
    target = ("example.com", 443)
    connect_args = {
        "address_family": Connection.AddressFamily.AF_INET,
        "timeout": "invalid",  # Invalid timeout
        "verify": True
    }
    data = b"test_data"
    check = "test_check"
    
    with patch('jarm.connection.connection.Connection.jarm_data', new_callable=AsyncMock) as mock_jarm_data, \
         patch('jarm.validate.validate.Validate.validate_target') as mock_validate_target:
        mock_jarm_data.return_value = b"mock_response"
        mock_validate_target.return_value = (2, None, None, None, ("192.0.2.1", 443))
        
        result = await Connection.jarm_connect(target, connect_args, data, check)
        
        assert result == ("test_check", b"mock_response")
        mock_validate_target.assert_called_once_with(target, Connection.AddressFamily.AF_INET)
        mock_jarm_data.assert_called_once()
        # Verify that DEFAULT_TIMEOUT was used
        assert mock_jarm_data.call_args[0][0]["timeout"] == DEFAULT_TIMEOUT

@pytest.mark.asyncio
async def test_jarm_connect_invalid_proxy_type():
    target = ("example.com", 443)
    connect_args = {
        "address_family": Connection.AddressFamily.AF_INET,
        "timeout": 30,
        "verify": True,
        "proxy": 12345  # Invalid proxy type
    }
    data = b"test_data"
    check = "test_check"
    
    with pytest.raises(ValueError, match="Proxy string must be str"):
        await Connection.jarm_connect(target, connect_args, data, check)

@pytest.mark.asyncio
async def test_jarm_connect_invalid_proxy_auth_type():
    target = ("example.com", 443)
    connect_args = {
        "address_family": Connection.AddressFamily.AF_INET,
        "timeout": 30,
        "verify": True,
        "proxy": "http://proxy.example.com:8080",
        "proxy_auth": 12345  # Invalid proxy_auth type
    }
    data = b"test_data"
    check = "test_check"
    
    with pytest.raises(ValueError, match="proxy auth must be str"):
        await Connection.jarm_connect(target, connect_args, data, check)

@pytest.mark.asyncio
async def test_jarm_connect_invalid_verify_type():
    target = ("example.com", 443)
    connect_args = {
        "address_family": Connection.AddressFamily.AF_INET,
        "timeout": 30,
        "verify": "invalid"  # Invalid verify type
    }
    data = b"test_data"
    check = "test_check"
    
    with pytest.raises(ValueError, match="verify must be boolean"):
        await Connection.jarm_connect(target, connect_args, data, check)

@pytest.mark.asyncio
async def test_jarm_connect_https_proxy():
    target = ("example.com", 443)
    connect_args = {
        "address_family": Connection.AddressFamily.AF_INET,
        "timeout": 30,
        "verify": False,
        "proxy": "https://proxy.example.com:8443"
    }
    data = b"test_data"
    check = "test_check"
    
    with patch('jarm.connection.connection.Connection.jarm_data', new_callable=AsyncMock) as mock_jarm_data, \
         patch('jarm.proxy.proxy.Proxy.parse_proxy') as mock_parse_proxy, \
         patch('jarm.validate.validate.Validate.validate_target') as mock_validate_target, \
         patch('ssl.create_default_context') as mock_create_default_context:
        mock_jarm_data.return_value = b"mock_response"
        mock_proxy = MagicMock()
        mock_proxy.scheme = "https"
        mock_proxy.hostname = "proxy.example.com"
        mock_proxy.port = 8443
        mock_proxy.username = None
        mock_proxy.password = None
        mock_parse_proxy.return_value = mock_proxy
        mock_validate_target.return_value = (2, None, None, None, ("192.0.2.1", 443))
        mock_ssl_context = MagicMock()
        mock_create_default_context.return_value = mock_ssl_context
        
        result = await Connection.jarm_connect(target, connect_args, data, check)
        
        assert result == ("test_check", b"mock_response")
        mock_parse_proxy.assert_called_once_with("https://proxy.example.com:8443")
        mock_validate_target.assert_called_once_with(target, Connection.AddressFamily.AF_INET)
        mock_jarm_data.assert_called_once()
        mock_create_default_context.assert_called_once()
        assert mock_ssl_context.verify_mode == ssl.CERT_NONE

# Add more tests here to cover other scenarios and edge cases

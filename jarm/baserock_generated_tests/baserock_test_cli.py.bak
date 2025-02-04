import pytest
from unittest.mock import patch, MagicMock
from argparse import Namespace
import asyncio
from datetime import datetime, timezone
from io import StringIO
import sys

# Assuming the module is named jarm_cli.py
from jarm.cli import _scan, run

@pytest.fixture
def mock_scanner():
    with patch('jarm.cli.Scanner') as mock:
        yield mock

@pytest.fixture
def mock_asyncio_run():
    with patch('asyncio.run') as mock:
        yield mock

@pytest.fixture
def mock_open():
    with patch('builtins.open', new_callable=MagicMock) as mock:
        yield mock

def test_scan_with_port(mock_scanner, mock_asyncio_run):
    mock_asyncio_run.return_value = ['test_jarm', 'test_host', 'test_port']
    result = _scan('example.com:8443')
    
    assert result == ['test_jarm', 'test_host', 'test_port']
    mock_scanner.scan_async.assert_called_once_with(
        dest_host='example.com',
        dest_port=8443,
        timeout=20,
        address_family=0,
        proxy=None,
        proxy_auth=None,
        proxy_insecure=None,
        concurrency=2,
        suppress=False
    )

def test_scan_without_port(mock_scanner, mock_asyncio_run):
    mock_asyncio_run.return_value = ['test_jarm', 'test_host', '443']
    result = _scan('example.com')
    
    assert result == ['test_jarm', 'test_host', '443']
    mock_scanner.scan_async.assert_called_once_with(
        dest_host='example.com',
        dest_port=443,
        timeout=20,
        address_family=0,
        proxy=None,
        proxy_auth=None,
        proxy_insecure=None,
        concurrency=2,
        suppress=False
    )

@pytest.mark.parametrize("args, expected_calls", [
    (
        Namespace(scan='example.com', input=None, debug=False, output=None, ipv4only=False, ipv6only=False, 
                  concurrency=None, proxy=None, proxy_auth=None, proxy_insecure=None, timeout=None, suppress=False),
        [('example.com', 0, None, None, None, 2, None, False)]
    ),
    (
        Namespace(scan=None, input='input.txt', debug=True, output='output.csv', ipv4only=True, ipv6only=False, 
                  concurrency=5, proxy='http://proxy.com', proxy_auth='auth', proxy_insecure=True, timeout=30, suppress=True),
        [('target1', 1, 'http://proxy.com', 'auth', True, 5, 30, True),
         ('target2', 1, 'http://proxy.com', 'auth', True, 5, 30, True)]
    )
])
def test_run(args, expected_calls, mock_open, monkeypatch):
    mock_scan = MagicMock(return_value=['test_jarm', 'test_host', 'test_port'])
    monkeypatch.setattr('jarm.cli._scan', mock_scan)
    
    if args.input:
        mock_file = mock_open.return_value.__enter__.return_value
        mock_file.read.return_value = "target1\ntarget2"
    
    with patch('argparse.ArgumentParser.parse_args', return_value=args):
        with patch('sys.stdout', new=StringIO()) as fake_out:
            run()
    
    assert mock_scan.call_count == len(expected_calls)
    mock_scan.assert_has_calls([pytest.call(*call) for call in expected_calls])
    
    if args.output:
        mock_open.assert_called_with('output.csv', 'w')
        write_mock = mock_open.return_value.__enter__.return_value.write
        assert write_mock.call_count == 3  # Header + 2 result lines
        assert 'Host,Port,JARM,ScanTime' in write_mock.call_args_list[0][0][0]

def test_run_no_args():
    with pytest.raises(SystemExit):
        with patch('sys.argv', ['jarm_cli.py']):
            run()

@pytest.mark.parametrize("argv, error_msg", [
    (['jarm_cli.py', '--ipv4only', '--ipv6only'], "Cannot specify both --ipv4only and --ipv6only at the same time"),
])
def test_run_invalid_args(argv, error_msg):
    with pytest.raises(SystemExit):
        with patch('sys.argv', argv), patch('sys.stderr', new=StringIO()) as fake_err:
            run()
    assert error_msg in fake_err.getvalue()

def test_run_with_debug(monkeypatch):
    args = Namespace(scan='example.com', input=None, debug=True, output=None, ipv4only=False, ipv6only=False, 
                     concurrency=None, proxy=None, proxy_auth=None, proxy_insecure=None, timeout=None, suppress=False)
    mock_logging = MagicMock()
    monkeypatch.setattr('jarm.cli.logging', mock_logging)
    monkeypatch.setattr('argparse.ArgumentParser.parse_args', lambda x: args)
    monkeypatch.setattr('jarm.cli._scan', MagicMock(return_value=['test_jarm', 'test_host', 'test_port']))
    
    run()
    
    mock_logging.basicConfig.assert_called_once_with(level=logging.DEBUG)


from mocket import Mocket
import socket
import os
import asyncio

from jarm.scanner.scanner import Scanner
from jarm.proxy.proxy import Proxy


def test_scanner_google_noproxy_ipv4_sync(mocker):
    fqdn = "google.com"
    ip = "142.250.184.174"
    port = 443
    MOCK_JARM = "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d"
    family = socket.AF_INET
    TEST_NAME = "google_com_443_noproxy_ipv4"

    mocker.patch(
        "os.urandom",
        return_value=b"\x17]\x18r\xb2\xe7\x14L\x82\x9anR\xe59{D\xb9\xf8\xb2P\x9cd\xb5\x03g3<\x99)\x176n",
    )
    mocker.patch("random.choice", return_value=b"\x5a\x5a")
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))],
    )

    Mocket.enable(TEST_NAME, "./tests/data")

    jarm = Scanner.scan(fqdn, port, address_family=family, concurrency=1)
    assert jarm == (MOCK_JARM, fqdn, port)


def test_scanner_google_noproxy_ipv4(mocker):
    fqdn = "google.com"
    ip = "142.250.184.174"
    port = 443
    MOCK_JARM = "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d"
    family = socket.AF_INET
    TEST_NAME = "google_com_443_noproxy_ipv4"

    mocker.patch(
        "os.urandom",
        return_value=b"\x17]\x18r\xb2\xe7\x14L\x82\x9anR\xe59{D\xb9\xf8\xb2P\x9cd\xb5\x03g3<\x99)\x176n",
    )
    mocker.patch("random.choice", return_value=b"\x5a\x5a")
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))],
    )

    Mocket.enable(TEST_NAME, "./tests/data")

    jarm = asyncio.run(
        Scanner.scan_async(fqdn, port, address_family=family, concurrency=1)
    )
    assert jarm == (MOCK_JARM, fqdn, port)


def test_scanner_google_httpproxy_param_ipv4(mocker):
    fqdn = "google.com"
    port = 443
    MOCK_JARM = "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d"
    family = socket.AF_INET
    TEST_NAME = "google_com_443_httpproxy_param_ipv4"
    proxy = "http://user:pass@127.0.0.1:3128"

    global conn_idx
    conn_idx = 0

    def get_user_agent():
        global conn_idx
        print(f"Called at {conn_idx}")
        hdr = {"User-Agent": f"pyJARM/UnitTest/{TEST_NAME}/{conn_idx}"}
        conn_idx += 1
        return hdr

    mocker.patch(
        "os.urandom",
        return_value=b"\x17]\x18r\xb2\xe7\x14L\x82\x9anR\xe59{D\xb9\xf8\xb2P\x9cd\xb5\x03g3<\x99)\x176n",
    )
    mocker.patch("random.choice", return_value=b"\x5a\x5a")

    mocker.patch.object(Proxy, "get_http_headers", side_effect=get_user_agent)
    Mocket.enable(TEST_NAME, "./tests/data")

    jarm = asyncio.run(
        Scanner.scan_async(
            fqdn, port, proxy=proxy, address_family=family, concurrency=1
        )
    )
    assert jarm == (MOCK_JARM, fqdn, port)


def test_scanner_google_httpproxy_env_ipv4(mocker):
    fqdn = "google.com"
    port = 443
    MOCK_JARM = "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d"
    family = socket.AF_INET
    TEST_NAME = "google_com_443_httpproxy_env_ipv4"
    os.environ["HTTPS_PROXY"] = "http://user:pass@127.0.0.1:3128"

    global conn_idx
    conn_idx = 0

    def get_user_agent():
        global conn_idx
        print(f"Called at {conn_idx}")
        hdr = {"User-Agent": f"pyJARM/UnitTest/{TEST_NAME}/{conn_idx}"}
        conn_idx += 1
        return hdr

    mocker.patch(
        "os.urandom",
        return_value=b"\x17]\x18r\xb2\xe7\x14L\x82\x9anR\xe59{D\xb9\xf8\xb2P\x9cd\xb5\x03g3<\x99)\x176n",
    )
    mocker.patch("random.choice", return_value=b"\x5a\x5a")

    mocker.patch.object(Proxy, "get_http_headers", side_effect=get_user_agent)
    Mocket.enable(TEST_NAME, "./tests/data")

    jarm = asyncio.run(
        Scanner.scan_async(fqdn, port, address_family=family, concurrency=1)
    )
    assert jarm == (MOCK_JARM, fqdn, port)


def test_scanner_google_ignoreproxy_env_ipv4(mocker):
    fqdn = "google.com"
    port = 443
    MOCK_JARM = "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d"
    family = socket.AF_INET
    TEST_NAME = "google_com_443_ignoreproxy_env_ipv4"
    os.environ["HTTPS_PROXY"] = "http://user:pass@127.0.0.1:3128"
    proxy = "ignore"

    global conn_idx
    conn_idx = 0

    def get_user_agent():
        global conn_idx
        print(f"Called at {conn_idx}")
        hdr = {"User-Agent": f"pyJARM/UnitTest/{TEST_NAME}/{conn_idx}"}
        conn_idx += 1
        return hdr

    mocker.patch(
        "os.urandom",
        return_value=b"\x17]\x18r\xb2\xe7\x14L\x82\x9anR\xe59{D\xb9\xf8\xb2P\x9cd\xb5\x03g3<\x99)\x176n",
    )
    mocker.patch("random.choice", return_value=b"\x5a\x5a")

    mocker.patch.object(Proxy, "get_http_headers", side_effect=get_user_agent)
    Mocket.enable(TEST_NAME, "./tests/data")

    jarm = asyncio.run(
        Scanner.scan_async(
            fqdn, port, proxy=proxy, address_family=family, concurrency=1
        )
    )
    assert jarm == (MOCK_JARM, fqdn, port)

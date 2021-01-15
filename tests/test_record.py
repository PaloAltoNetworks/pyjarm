from mocket import Mocket

import socket
import os
import io

import json
from jarm.scanner.scanner import Scanner


def test_scanner_google(mocker):
    mocker.patch(
        "os.urandom",
        return_value=b"\x17]\x18r\xb2\xe7\x14L\x82\x9anR\xe59{D\xb9\xf8\xb2P\x9cd\xb5\x03g3<\x99)\x176n",
    )
    mocker.patch("random.choice", return_value=b"\x5a\x5a")

    fqdn = "google.com"
    ip = "172.217.22.100"
    port = 443
    mock_jarm = "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d"

    Mocket.enable("mock_google_com", "./tests")

    jarm = Scanner.scan(fqdn, port)
    assert jarm == (mock_jarm, fqdn, port)

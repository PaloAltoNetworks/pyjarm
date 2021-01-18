from mocket import Mocket, mocketize
from mocket.async_mocket import async_mocketize

import socket
import os
import io
import asyncio

import json
from jarm.scanner.scanner import Scanner


# @mocketize
# def test_scanner_google(mocker):
#     mocker.patch(
#         "os.urandom",
#         return_value=b"\x17]\x18r\xb2\xe7\x14L\x82\x9anR\xe59{D\xb9\xf8\xb2P\x9cd\xb5\x03g3<\x99)\x176n",
#     )
#     mocker.patch("random.choice", return_value=b"\x5a\x5a")

#     fqdn = "google.com"
#     ip = "172.217.22.100"
#     port = 443
#     mock_jarm = "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d"

#     Mocket.enable("mock_google_com2", "./tests")

#     async def _scan(l):
#         jarm =  await Scanner.scan(fqdn, port, proxy='ignore')
#         assert jarm == (mock_jarm, fqdn, port)
#     loop = asyncio.get_event_loop()
#     loop.set_debug(True)
#     loop.run_until_complete(_scan(loop))


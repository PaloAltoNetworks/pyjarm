from urllib.request import getproxies
from urllib.parse import urlparse, ParseResult
import socket
from base64 import b64encode
from typing import Dict
from jarm.exceptions.exceptions import PyJARMInvalidProxy, PyJARMProxyError
import asyncio


class Proxy:
    @staticmethod
    def parse_proxy(p: str = None):
        proxy = ""
        if not p:
            proxy = getproxies().get("https")
        elif p != "ignore":
            proxy = p
        return urlparse(proxy) if proxy else None

    @staticmethod
    async def handle_proxy(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target_str: str,
        auth: str = None,
        username: str = None,
        password: str = None,
        headers: Dict[str, str] = {},
    ):
        # Check if authorization is provided
        # auth has priority over username/password
        if auth:
            headers["Proxy-Authorization"] = auth
        elif username and password:
            basic_auth = b64encode(f"{username}:{password}".encode()).decode()
            headers["Proxy-Authorization"] = f"Basic {basic_auth}"

        headers["Host"] = target_str

        buf = f"CONNECT {target_str} HTTP/1.1\r\n"
        buf += "\r\n".join(f"{k}: {v}" for (k, v) in headers.items())
        buf += "\r\n\r\n"
        writer.write(buf.encode())
        await writer.drain()

        status = await reader.readline()
        if not status:
            raise PyJARMProxyError("No status line received from Proxy")
        response = status.decode().rstrip("\r\n").split(" ")
        if (
            not response
            or len(response) < 2
            or response[0] != "HTTP/1.1"
            or response[1] != "200"
        ):
            raise PyJARMProxyError(f"Invalid Proxy Response: {status}")

        # Ignore headers
        while l := await reader.readline():
            if not l or l == b"\r\n":
                break
        return

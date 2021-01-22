from urllib.request import getproxies
from urllib.parse import urlparse
from base64 import b64encode
from typing import Dict, Optional
from jarm.exceptions.exceptions import PyJARMProxyError
import asyncio


class Proxy:
    @staticmethod
    def get_http_headers() -> Dict[str, str]:
        return {}

    @staticmethod
    def parse_proxy(p: Optional[str] = None):
        proxy: Optional[str] = None
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
        headers = Proxy.get_http_headers()
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
            raise PyJARMProxyError(f"Invalid Proxy Response: {status!r}")
        # Ignore all headers
        while True:
            line = await reader.readline()
            if not line or line == b"\r\n":
                break
        return

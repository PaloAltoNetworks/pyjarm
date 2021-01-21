import asyncio
import socket
from typing import Tuple, Dict, Any
from enum import IntEnum
import ssl

from jarm.proxy.proxy import Proxy
from jarm.exceptions.exceptions import PyJARMInvalidProxy
from jarm.validate.validate import Validate


class Connection:

    DEFAULT_TIMEOUT = 20  # default timeout in seconds

    class AddressFamily(IntEnum):
        AF_ANY = 0
        AF_INET = 2
        AF_INET6 = 10

    @staticmethod
    async def prep_connection(
        connect_target: Dict[str, Any]
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader, writer = await asyncio.open_connection(
            host=connect_target.get("connect_host"),
            port=connect_target.get("connect_port"),
            family=connect_target.get("address_family"),
            proto=socket.IPPROTO_TCP,
            ssl=connect_target.get("ssl"),
            server_hostname=connect_target.get("server_hostname"),
        )
        if connect_target.get("use_proxy"):
            target = f'{connect_target.get("target_host")}:{connect_target.get("target_port")}'
            await Proxy.handle_proxy(
                reader,
                writer,
                target,
                connect_target.get("proxy_auth"),
                connect_target.get("proxy_username"),
                connect_target.get("proxy_password"),
            )
        return reader, writer

    @staticmethod
    async def jarm_data(conn_target: Dict[str, Any], data: bytes) -> bytes:
        reader, writer = await Connection.prep_connection(conn_target)
        writer.write(data)
        await writer.drain()
        out = await reader.read(1484)
        writer.close()
        await writer.wait_closed()
        return out

    @staticmethod
    async def jarm_connect(
        target: Tuple[str, int], connect_args: Dict[str, Any], data: bytes, check: str
    ) -> Any:
        address_family = connect_args.get("address_family")

        if not address_family:
            address_family = Connection.AddressFamily.AF_ANY
        elif address_family not in tuple(x.value for x in Connection.AddressFamily):
            raise ValueError("AddressFamily not supported")

        timeout = connect_args.get("timeout")
        if not timeout or not isinstance(timeout, int):
            timeout = Connection.DEFAULT_TIMEOUT

        proxy_string = connect_args.get("proxy")
        if proxy_string and not isinstance(proxy_string, str):
            raise ValueError("Proxy string must be str")

        proxy_auth = connect_args.get("proxy_auth")
        if proxy_auth and not isinstance(proxy_auth, str):
            raise ValueError("proxy auth must be str")

        verify = connect_args.get("verify", True)
        if not isinstance(verify, bool):
            raise ValueError("verify must be boolean")

        proxy = Proxy.parse_proxy(proxy_string)

        conn_target: Dict[str, Any] = {
            "target_host": target[0],
            "target_port": target[1],
            "address_family": address_family,
            "timeout": timeout,
            "verify": verify,
        }

        if proxy:
            if not proxy.hostname:
                raise PyJARMInvalidProxy("Invalid or missing proxy hostname")
            connection_host = proxy.hostname
            conn_target["proxy_auth"] = proxy_auth
            conn_target["use_proxy"] = True
            conn_target["proxy_username"] = proxy.username if proxy.username else None
            conn_target["proxy_password"] = proxy.password if proxy.password else None

            if proxy.scheme == "https":
                ctx = ssl.create_default_context()
                if verify is False:
                    ctx.verify_mode = ssl.CERT_NONE
                connection_port = proxy.port if proxy.port else 8443
                conn_target["ssl"] = ctx
                conn_target["server_hostname"] = connection_host
            elif proxy.scheme == "http":
                connection_port = proxy.port if proxy.port else 8080
            else:
                raise PyJARMInvalidProxy("Invalid proxy connection scheme")
        else:
            connection_host = target[0]
            connection_port = target[1]

        # Validate and resolve the connection target (either real target or proxy)
        target_family, _, _, _, target_addr = Validate.validate_target(
            connection_host, connection_port, address_family
        )
        conn_target["connect_host"] = target_addr[0]
        conn_target["connect_port"] = connection_port
        conn_target["address_family"] = target_family
        fut = Connection.jarm_data(conn_target, data)
        output = await asyncio.wait_for(fut, timeout=timeout)
        return (check, output)

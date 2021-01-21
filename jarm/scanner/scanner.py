from collections import namedtuple
import logging
import asyncio
from typing import List, Any

from jarm.constants import TOTAL_FAILURE, FAILED_PACKET, ERROR_INC_1, ERROR_INC_2
from jarm.formats import V1
from jarm.hashing.hashing import Hasher
from jarm.packet.packet import Packet
from jarm.connection.connection import Connection


class Scanner:

    ScanTarget = namedtuple("ScanTarget", "host port")

    @staticmethod
    async def gather_with_concurrency(n, *tasks):
        sem = asyncio.Semaphore(n)

        async def sem_task(task):
            async with sem:
                return await task

        return await asyncio.gather(*(sem_task(task) for task in tasks))

    @staticmethod
    async def scan(
        dest_host: str,
        dest_port: int,
        timeout: int = 20,
        address_family=Connection.AddressFamily.AF_ANY,
        proxy: str = None,
        proxy_auth: str = None,
        proxy_insecure: bool = None,
        concurrency: int = 2,
    ):
        """
        Kicks off a number of TLS hello packets to a server then parses and hashes the response.

        Args:
            dest_host (str):
                The target host. This can be an IPv4 address, IPv6 address, or domain name.
            dest_port (int):
                The target port.
            timeout (int, optional):
                How long to wait for the server to response. Default is 20 seconds.
            address_family (int, optional):
                The address family for the scan. This will default to ANY and is used to validate the target.
            proxy (str, optional):
                The proxy server to use. Use format http[s]://username:password@proxy:port. By default the HTTPS_PROXY
                environment variable is evaluated if proxy is not set. If you want to ignore the HTTPS_PROXY variable
                without specifying a proxy, set this to 'ignore'. username/password are used for Basic authentication.
            proxy_auth (str, optional):
                Use this argument if you don't want to use username/password with Basic authentication. This value is
                sent as us using the "Proxy-Authorization" header.
            proxy_insecure (bool, optional):
                If you are connecting through an HTTPS proxy via TLS, this flag disables the verification of the proxy
                certificate.
            concurrency (int, optional, default=2)
                Number of concurrent TCP connections to generate.
        Returns:
            :tuple:
                Returns a tuple with three items. The first item is the JARM hash, which is a string. Second is
                the target host, also a string. The final item is the target port which is an int.
        Examples:
            >>> from jarm.scanner.scanner import Scanner
            >>> jarm, host, port = Scanner.scan("google.com", 443)

        """
        results: List[Any] = []

        target = Scanner.ScanTarget(dest_host, dest_port)
        connect_args = {
            "address_family": address_family,
            "proxy": proxy,
            "proxy_auth": proxy_auth,
            "verify": False if proxy_insecure else True,
        }
        packet_tuples = Scanner._generate_packets(
            dest_host=dest_host, dest_port=dest_port
        )
        tasks = [
            Connection.jarm_connect(
                (dest_host, dest_port), connect_args, packet_tuple[1], packet_tuple[0]
            )
            for packet_tuple in packet_tuples
        ]
        try:
            result_list = await Scanner.gather_with_concurrency(concurrency, *tasks)
            for p in packet_tuples:
                for r in result_list:
                    if p[0] == r[0]:
                        results.append(Scanner._parse_server_hello(r[1], p))
        except Exception:
            logging.exception(f"Unknown Exception scanning {target}")
            return TOTAL_FAILURE, target.host, target.port
        return Hasher.jarm(",".join(results)), target.host, target.port

    @staticmethod
    def _generate_packets(dest_host: str, dest_port: int):
        return [
            (
                f().__class__.__name__,
                f().build_packet(dest_host=dest_host, dest_port=dest_port).build(),
            )
            for f in V1
        ]

    @staticmethod
    def _parse_server_hello(hello, src_packet):
        try:
            if hello is None:
                logging.debug(f"Format Packet Results: {src_packet[0]} {FAILED_PACKET}")
                return FAILED_PACKET
            if hello[0] == 21:
                selected_cipher = b""
                logging.debug(f"Format Packet Results: {src_packet[0]} {FAILED_PACKET}")
                return FAILED_PACKET
            elif (hello[0] == 22) and (hello[5] == 2):
                counter = hello[43]
                selected_cipher = hello[counter + 44 : counter + 46]
                version = hello[9:11]
                ret = f"{selected_cipher.hex()}|{version.hex()}|{Scanner._extract_extension_info(hello, counter)}"
                logging.debug(f"Format Packet Results: {src_packet[0]} {ret}")
                return ret
            else:
                logging.debug(f"Format Packet Results: {src_packet[0]} {FAILED_PACKET}")
                return FAILED_PACKET
        except Exception:
            logging.debug(f"Format Packet Results: {src_packet[0]} {FAILED_PACKET}")
            return FAILED_PACKET

    @staticmethod
    def _extract_extension_info(hello, counter):
        try:
            # Error handling
            if (
                (hello[counter + 47] == 11)
                or (hello[counter + 50 : counter + 53] == ERROR_INC_1)
                or (hello[82:85] == ERROR_INC_2)
            ):
                return FAILED_PACKET
            count = 49 + counter
            length = int.from_bytes(hello[counter + 47 : counter + 49], byteorder="big")
            maximum = length + (count - 1)
            types = []
            values = []
            # Collect all extension types and values for later reference
            while count < maximum:
                types.append(hello[count : count + 2])
                ext_length = int.from_bytes(
                    hello[count + 2 : count + 4], byteorder="big"
                )
                if ext_length == 0:
                    count += 4
                    values.append("")
                else:
                    values.append(hello[count + 4 : count + 4 + ext_length])
                    count += ext_length + 4
            # Read application_layer_protocol_negotiation
            alpn = Scanner._find_extension(Packet.ALPN_BASE, types, values)
            result = f"{str(alpn)}|"
            # Add formating hyphens
            add_hyphen = 0
            while add_hyphen < len(types):
                result += types[add_hyphen].hex()
                add_hyphen += 1
                if add_hyphen == len(types):
                    break
                else:
                    result += "-"
            return result
        except IndexError:
            return "|"

    @staticmethod
    def _find_extension(ext_type, types, values):
        iter = 0
        if ext_type == Packet.ALPN_BASE:
            while iter < len(types):
                if types[iter] == ext_type:
                    return (values[iter][3:]).decode()
                iter += 1
        else:
            while iter < len(types):
                if types[iter] == ext_type:
                    return values[iter].hex()
                iter += 1
        return ""

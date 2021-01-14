from collections import namedtuple
from ipaddress import ip_address, IPv4Address, IPv6Address
import logging
import socket

from jarm.constants import TOTAL_FAILURE, FAILED_PACKET, ERROR_INC_1, ERROR_INC_2
from jarm.formats import V1
from jarm.hashing.hashing import Hasher
from jarm.packet.packet import Packet


class Scanner:

    ScanTarget = namedtuple("ScanTarget", "host port")

    @staticmethod
    def scan(dest_host, dest_port, timeout: int = 20):
        results = []
        for packet_tuple in Scanner._generate_packets(
            dest_host=dest_host, dest_port=dest_port
        ):
            try:
                target = Scanner.ScanTarget(dest_host, dest_port)
                if ":" in target.host:
                    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
                        s.settimeout(timeout)
                        s.connect((target.host, target.port, 0, 0))
                        s.sendall(packet_tuple[1])
                        data = s.recv(1484)
                        results.append(Scanner._parse_server_hello(data, packet_tuple))
                else:
                    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
                        s.settimeout(timeout)
                        s.connect((target.host, target.port))
                        s.sendall(packet_tuple[1])
                        data = s.recv(1484)
                        results.append(Scanner._parse_server_hello(data, packet_tuple))
            except (TimeoutError, socket.timeout) as e:
                logging.exception(f"Timeout scanning {target}")
                return TOTAL_FAILURE, target.host, target.port
            except Exception as e:
                logging.exception(f"Unknown Exception scanning {target}")
                return None, target.host, target.port
        return Hasher.jarm(",".join(results)), target.host, target.port

    @staticmethod
    def _generate_packets(dest_host: str, dest_port: str):
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
            if hello == None:
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
        except Exception as e:
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
        except IndexError as e:
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

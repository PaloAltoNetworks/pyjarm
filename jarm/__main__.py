import argparse
from datetime import datetime, timezone
import asyncio

try:
    from jarm.scanner.scanner import Scanner
    from jarm.connection.connection import Connection
except ImportError:
    import os
    import sys

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from jarm.scanner.scanner import Scanner
    from jarm.connection.connection import Connection


def _scan(
    target: str,
    address_family: int = 0,
    proxy: str = None,
    proxy_auth: str = None,
    proxy_insecure: bool = None,
    concurrency: int = 2,
):
    if ":" in target:
        parts = target.split(":")
        host = parts[0]
        port = int(parts[1])
    else:
        host = target
        port = 443
    print(f"Target: {host}:{port}")
    results = asyncio.run(
        Scanner.scan(
            dest_host=host,
            dest_port=port,
            address_family=address_family,
            proxy=proxy,
            proxy_auth=proxy_auth,
            proxy_insecure=proxy_insecure,
            concurrency=concurrency,
        )
    )
    print(f"JARM: {results[0]}")
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Enter an IP address/domain and port to scan or supply an input file."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("scan", nargs="?", help="Enter an IP or domain to scan.")
    group.add_argument(
        "-i",
        "--input",
        help="Provide a list of IP addresses or domains to scan, one domain or IP address per line. Ports can be specified with a colon (ex. 8.8.8.8:8443)",
        type=str,
    )
    parser.add_argument(
        "-d",
        "--debug",
        help="[OPTIONAL] Debug mode: Displays additional debug details",
        action="store_true",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="[OPTIONAL] Provide a filename to output/append results to a CSV file.",
        type=str,
    )
    parser.add_argument(
        "-4",
        "--ipv4only",
        help="[OPTIONAL] Use only IPv4 connections (incompatible with --ipv6only).",
        action="store_true",
    )
    parser.add_argument(
        "-6",
        "--ipv6only",
        help="[OPTIONAL] Use only IPv6 connections (incompatible with --ipv4only).",
        action="store_true",
    )
    parser.add_argument(
        "-c",
        "--concurrency",
        nargs="?",
        help="[OPTIONAL] Number of concurrent connections (default is 2).",
        type=int,
    )
    parser.add_argument(
        "--proxy",
        help="[OPTIONAL] Use proxy (format http[s]://user:pass@proxy:port). HTTPS_PROXY env variable is used by default if this is not set. Set this to 'ignore' to ignore HTTPS_PROXY and use no proxy.",
        type=str,
    )
    parser.add_argument(
        "--proxy-auth",
        help="[OPTIONAL] Send this header in Proxy-Authorization (when using proxy).",
        type=str,
    )
    parser.add_argument(
        "--proxy-insecure",
        help="[OPTIONAL] Do not verify SSL_CERTIFICATES (only when HTTPS proxy is set).",
        action="store_true",
    )
    args = parser.parse_args()
    concurrency = args.concurrency if args.concurrency else 2
    if args.ipv4only and args.ipv6only:
        parser.error("Cannot specify both --ipv4only and --ipv6only at the same time")
    address_family = Connection.AddressFamily.AF_ANY  # either IPv4 or IPv6 allowed
    if args.ipv4only:
        address_family = Connection.AddressFamily.AF_INET
    elif args.ipv6only:
        address_family = Connection.AddressFamily.AF_INET6
    if args.scan is None and args.input is None:
        parser.error("A domain/IP to scan or an input file is required to run")
    elif args.scan is not None:
        results = [
            _scan(
                args.scan,
                address_family=address_family,
                proxy=args.proxy,
                proxy_auth=args.proxy_auth,
                proxy_insecure=args.proxy_insecure,
                concurrency=concurrency,
            )
        ]
    else:
        targets = []
        results = []
        with open(args.input, "r") as inpt:
            targets = [*inpt.read().splitlines()]
        for target in targets:
            results.append(
                _scan(
                    target,
                    address_family=address_family,
                    proxy=args.proxy,
                    proxy_auth=args.proxy_auth,
                    proxy_insecure=args.proxy_insecure,
                    concurrency=concurrency,
                )
            )
    if args.output is not None:
        with open(args.output, "w") as out:
            utc_now = datetime.now(timezone.utc).isoformat()
            out.write("Host,Port,JARM,ScanTime\n")
            for res in results:
                out.write(f"{res[1]},{res[2]},{res[0]},{utc_now}\n")

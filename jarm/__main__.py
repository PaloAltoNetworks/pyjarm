import argparse
from datetime import datetime, timezone

try:
    from jarm.scanner.scanner import Scanner
except ImportError:
    import os
    import sys

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from jarm.scanner.scanner import Scanner


def _scan(target: str, address_family: int = 0):
    if ":" in target:
        parts = target.split(":")
        host = parts[0]
        port = int(parts[1])
    else:
        host = target
        port = 443
    print(f"Target: {host}:{port}")
    results = Scanner.scan(
        dest_host=host, dest_port=port, address_family=address_family
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
    args = parser.parse_args()
    if args.ipv4only and args.ipv6only:
        parser.error("Cannot specify both --ipv4only and --ipv6only at the same time")
    address_family = Scanner.AddressFamily.AF_ANY  # either IPv4 or IPv6 allowed
    if args.ipv4only:
        address_family = Scanner.AddressFamily.AF_INET
    elif args.ipv6only:
        address_family = Scanner.AddressFamily.AF_INET6
    if args.scan is None and args.input is None:
        parser.error("A domain/IP to scan or an input file is required to run")
    elif args.scan is not None:
        results = [_scan(args.scan, address_family=address_family)]
    else:
        targets = []
        results = []
        with open(args.input, "r") as inpt:
            targets = [*inpt.read().splitlines()]
        for target in targets:
            results.append(_scan(target, address_family=address_family))
    if args.output is not None:
        with open(args.output, "w") as out:
            utc_now = datetime.now(timezone.utc).isoformat()
            out.write("Host,Port,JARM,ScanTime\n")
            for res in results:
                out.write(f"{res[1]},{res[2]},{res[0]},{utc_now}\n")

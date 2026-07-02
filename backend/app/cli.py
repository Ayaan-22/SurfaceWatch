import argparse
import json

from app.scanner.headers import analyze_headers
from app.scanner.ports import check_tcp_port
from app.scanner.ssl_checker import check_ssl
from app.scanner.subdomains import passive_seed_discovery


def main() -> None:
    parser = argparse.ArgumentParser(prog="surfacewatch", description="Safe local scanner helpers.")
    subcommands = parser.add_subparsers(dest="command", required=True)
    scan_parser = subcommands.add_parser("scan")
    scan_parser.add_argument("domain")
    ssl_parser = subcommands.add_parser("ssl")
    ssl_parser.add_argument("domain")
    ports_parser = subcommands.add_parser("ports")
    ports_parser.add_argument("domain")
    ports_parser.add_argument("--ports", default="80,443,8080,8443")
    headers_parser = subcommands.add_parser("headers")
    headers_parser.add_argument("--header", action="append", default=[])

    args = parser.parse_args()
    if args.command == "scan":
        print(json.dumps([candidate.__dict__ for candidate in passive_seed_discovery(args.domain)], indent=2))
    elif args.command == "ssl":
        print(json.dumps(check_ssl(args.domain).__dict__, indent=2, default=str))
    elif args.command == "ports":
        ports = [int(item.strip()) for item in args.ports.split(",") if item.strip()]
        print(json.dumps([check_tcp_port(args.domain, port).__dict__ for port in ports], indent=2))
    elif args.command == "headers":
        headers = dict(item.split(":", 1) for item in args.header)
        print(json.dumps(analyze_headers(headers), indent=2))


if __name__ == "__main__":
    main()

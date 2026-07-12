import argparse
import json

from app.scanner.worker import run_scan_worker
from app.scanner.scheduler import run_scan_scheduler
from app.scanner.headers import analyze_headers
from app.scanner.ports import check_tcp_ports
from app.scanner.ssl_checker import check_ssl
from app.scanner.subdomains import discover_subdomains


def main() -> None:
    parser = argparse.ArgumentParser(prog="surfacewatch", description="Safe local scanner helpers.")
    subcommands = parser.add_subparsers(dest="command", required=True)
    scan_parser = subcommands.add_parser("scan")
    scan_parser.add_argument("domain")
    scan_parser.add_argument("--aggressive", action="store_true")
    scan_parser.add_argument("--max-assets", type=int, default=250)
    scan_parser.add_argument("--authorized", action="store_true", help="Confirm you are authorized to assess this target.")
    ssl_parser = subcommands.add_parser("ssl")
    ssl_parser.add_argument("domain")
    ssl_parser.add_argument("--authorized", action="store_true", help="Confirm you are authorized to assess this target.")
    ports_parser = subcommands.add_parser("ports")
    ports_parser.add_argument("domain")
    ports_parser.add_argument("--ports", default="80,443,8080,8443")
    ports_parser.add_argument("--authorized", action="store_true", help="Confirm you are authorized to assess this target.")
    headers_parser = subcommands.add_parser("headers")
    headers_parser.add_argument("--header", action="append", default=[])
    worker_parser = subcommands.add_parser("scan-worker")
    worker_parser.add_argument("--once", action="store_true")
    worker_parser.add_argument("--poll-interval", type=float, default=2.0)
    scheduler_parser = subcommands.add_parser("scheduler")
    scheduler_parser.add_argument("--once", action="store_true")
    scheduler_parser.add_argument("--poll-interval", type=float, default=30.0)

    args = parser.parse_args()
    if args.command in {"scan", "ssl", "ports"} and not args.authorized:
        parser.error("Outbound scanner commands require --authorized confirmation.")
    if args.command == "scan":
        discovery = discover_subdomains(
            args.domain,
            max_candidates=max(1, args.max_assets),
            aggressive_dns=args.aggressive,
        )
        print(
            json.dumps(
                {
                    "metadata": discovery.metadata(),
                    "candidates": [candidate.__dict__ for candidate in discovery.candidates],
                },
                indent=2,
            )
        )
    elif args.command == "ssl":
        print(json.dumps(check_ssl(args.domain).__dict__, indent=2, default=str))
    elif args.command == "ports":
        ports = [int(item.strip()) for item in args.ports.split(",") if item.strip()]
        print(json.dumps([result.__dict__ for result in check_tcp_ports(args.domain, ports)], indent=2))
    elif args.command == "headers":
        headers = dict(item.split(":", 1) for item in args.header)
        print(json.dumps(analyze_headers(headers), indent=2))
    elif args.command == "scan-worker":
        run_scan_worker(poll_interval_seconds=args.poll_interval, once=args.once)
    elif args.command == "scheduler":
        run_scan_scheduler(poll_interval_seconds=args.poll_interval, once=args.once)


if __name__ == "__main__":
    main()

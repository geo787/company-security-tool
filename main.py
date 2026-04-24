import argparse
import logging
import os
import sys
from datetime import datetime

import scanner


# ─── Logging setup ───────────────────────────────────────────────────────────

def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure console + rotating file logging."""
    from logging.handlers import RotatingFileHandler

    os.makedirs("logs", exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-8s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    ch.setLevel(level)

    # File (5 MB max, 3 rotations)
    fh = RotatingFileHandler(
        "logs/scanner.log",
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    fh.setFormatter(fmt)
    fh.setLevel(logging.DEBUG)

    root = logging.getLogger("scanner")
    root.setLevel(logging.DEBUG)
    root.addHandler(ch)
    root.addHandler(fh)
    return root


# ─── Argument parser ─────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security-scanner",
        description="Company Security Port Scanner v2.0 — by Roberta Barba",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -t scanme.nmap.org
  python main.py -t 192.168.1.1 -p 1-1024 --output json
  python main.py -t company.com -p 80,443,8080,3306 --output csv
  python main.py -t app.io -p 1-65535 --threads 500 --timeout 0.3
  python main.py -t target.com --no-banners --verbose

GitHub: https://github.com/geo787/company-security-tool
        """,
    )

    parser.add_argument(
        "-t", "--target",
        required=True,
        metavar="HOST",
        help="Target hostname or IP address",
    )
    parser.add_argument(
        "-p", "--ports",
        default="1-1024",
        metavar="RANGE",
        help="Port range (1-1024), list (80,443,8080), or single port (443). Default: 1-1024",
    )
    parser.add_argument(
        "-o", "--output",
        choices=["txt", "json", "csv"],
        default="txt",
        dest="output_format",
        help="Report format. Default: txt",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=300,
        metavar="N",
        help="Max concurrent threads. Default: 300",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        metavar="SEC",
        help="Connection timeout per port in seconds. Default: 0.5",
    )
    parser.add_argument(
        "--no-banners",
        action="store_true",
        help="Skip banner grabbing (faster scan)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show debug output and progress",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 2.0.0",
    )

    return parser


# ─── Input validation ────────────────────────────────────────────────────────

def validate_args(args: argparse.Namespace, logger: logging.Logger) -> bool:
    try:
        start, end = scanner.parse_ports(args.ports)
    except (ValueError, IndexError):
        logger.error(f"Invalid port specification: '{args.ports}'")
        logger.error("Use formats like: 1-1024  or  80,443,8080  or  443")
        return False

    if not (0 < start <= 65535 and 0 < end <= 65535):
        logger.error("Ports must be between 1 and 65535.")
        return False

    if start > end:
        logger.error(f"Start port ({start}) must be ≤ end port ({end}).")
        return False

    if args.threads < 1 or args.threads > 1000:
        logger.error("Thread count must be between 1 and 1000.")
        return False

    if args.timeout <= 0 or args.timeout > 30:
        logger.error("Timeout must be between 0.01 and 30 seconds.")
        return False

    return True


# ─── Main ────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    logger = setup_logging(verbose=args.verbose)

    # ── Banner ──────────────────────────────────────────────────────────────
    logger.info("=" * 52)
    logger.info("  Company Security Port Scanner v2.0")
    logger.info(f"  Target  : {args.target}")
    logger.info(f"  Ports   : {args.ports}")
    logger.info(f"  Output  : {args.output_format.upper()}")
    logger.info(f"  Threads : {args.threads}  |  Timeout: {args.timeout}s")
    logger.info("=" * 52)

    # ── Validate ─────────────────────────────────────────────────────────────
    if not validate_args(args, logger):
        return 1

    # ── Resolve ──────────────────────────────────────────────────────────────
    ip = scanner.check_website(args.target)
    if not ip:
        return 1

    # ── Scan ─────────────────────────────────────────────────────────────────
    start_port, end_port = scanner.parse_ports(args.ports)
    start_time = datetime.now()

    try:
        open_ports = scanner.scan_ports(
            ip=ip,
            start_port=start_port,
            end_port=end_port,
            max_threads=args.threads,
            timeout=args.timeout,
            grab_banners=not args.no_banners,
        )
    except KeyboardInterrupt:
        logger.warning("\nScan interrupted by user (Ctrl+C).")
        return 130

    elapsed = (datetime.now() - start_time).total_seconds()

    # ── Summary ───────────────────────────────────────────────────────────────
    logger.info("─" * 52)
    logger.info(f"Scan completed in {elapsed:.1f}s")
    logger.info(f"Open ports found: {len(open_ports)}")

    risky = [p for p in open_ports if p.get("risk")]
    if risky:
        logger.warning(f"ATTENTION: {len(risky)} risky port(s) detected!")
        for p in risky:
            logger.warning(f"  Port {p['port']} ({p['service']}): {p['risk']}")
    else:
        logger.info("No high-risk ports detected.")

    # ── Save report ───────────────────────────────────────────────────────────
    report_path = scanner.save_report(
        target=args.target,
        ip=ip,
        open_ports=open_ports,
        output_format=args.output_format,
    )
    logger.info(f"Report → {report_path}")
    logger.info("=" * 52)

    # Exit 1 if risky ports found (useful for CI/CD pipelines)
    return 1 if risky else 0


if __name__ == "__main__":
    sys.exit(main())
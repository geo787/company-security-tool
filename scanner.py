"""
scanner.py — Company Security Tool v2.0
Core scanning engine with multithreading, service detection, banner grabbing.
"""

import socket
import os
import json
import csv
import logging
import concurrent.futures
from datetime import datetime
from typing import Optional

# ─── Service map ────────────────────────────────────────────────────────────

COMMON_SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    111: "RPC", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-submit",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    2222: "SSH-alt", 3000: "Node/Dev", 3306: "MySQL",
    3389: "RDP", 4443: "HTTPS-alt", 5000: "Flask/Dev",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-alt", 8443: "HTTPS-alt", 8888: "Jupyter",
    9200: "Elasticsearch", 27017: "MongoDB", 27018: "MongoDB-shard",
}

# ─── Risk map: ports that are dangerous if exposed ──────────────────────────

RISKY_PORTS = {
    21:    "FTP — credentials sent in plaintext",
    23:    "Telnet — fully unencrypted protocol",
    135:   "MSRPC — Windows exploit surface",
    139:   "NetBIOS — lateral movement risk",
    445:   "SMB — ransomware & EternalBlue target",
    1433:  "MSSQL — database exposed to internet",
    1521:  "Oracle DB — database exposed to internet",
    3306:  "MySQL — database exposed to internet",
    3389:  "RDP — brute-force & BlueKeep target",
    5432:  "PostgreSQL — database exposed to internet",
    5900:  "VNC — remote desktop, often no auth",
    6379:  "Redis — usually no auth by default",
    8888:  "Jupyter — code execution, no auth by default",
    9200:  "Elasticsearch — data exposed, no auth by default",
    27017: "MongoDB — historically exposed with no auth",
}

logger = logging.getLogger("scanner")


# ─── DNS resolution ──────────────────────────────────────────────────────────

def check_website(host: str) -> Optional[str]:
    """Resolve hostname to IP. Returns None on failure."""
    if not host or not host.strip():
        logger.error("No target specified.")
        return None
    try:
        ip = socket.gethostbyname(host.strip())
        logger.info(f"Resolved {host} → {ip}")
        return ip
    except socket.gaierror as e:
        logger.error(f"Cannot resolve '{host}': {e}")
        return None


# ─── Banner grabbing ─────────────────────────────────────────────────────────

def grab_banner(ip: str, port: int, timeout: float = 1.5) -> Optional[str]:
    """
    Attempt to read the service banner for version detection.
    Returns up to 200 chars of banner text, or None.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # HTTP ports: send a minimal request to get a response header
        if port in (80, 8080, 8443, 3000, 5000, 8888):
            sock.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")

        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()

        # Clean up: keep only first line (most informative)
        first_line = banner.splitlines()[0] if banner else ""
        return first_line[:200] if first_line else None

    except Exception:
        return None


# ─── Single port scan ────────────────────────────────────────────────────────

def scan_single_port(
    ip: str,
    port: int,
    timeout: float = 0.5,
    grab_banners: bool = True
) -> Optional[dict]:
    """
    Check one port. Returns a result dict if open, None if closed.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            service = COMMON_SERVICES.get(port, "Unknown")
            risk = RISKY_PORTS.get(port)
            banner = grab_banner(ip, port) if grab_banners else None

            entry = {
                "port":    port,
                "service": service,
                "banner":  banner,
                "risk":    risk,
                "status":  "open",
            }

            risk_label = f"  ⚠  RISK: {risk}" if risk else ""
            banner_label = f"  [{banner}]" if banner else ""
            logger.info(f"[OPEN] {port}/{service}{banner_label}{risk_label}")

            return entry

    except Exception:
        pass
    return None


# ─── Threaded port scan ──────────────────────────────────────────────────────

def scan_ports(
    ip: str,
    start_port: int,
    end_port: int,
    max_threads: int = 300,
    timeout: float = 0.5,
    grab_banners: bool = True
) -> list[dict]:
    """
    Scan a port range using a thread pool.
    Returns sorted list of open port dicts.
    """
    ports = range(start_port, end_port + 1)
    total = len(ports)
    open_ports = []

    logger.info(f"Scanning {total} ports on {ip} "
                f"({max_threads} threads, {timeout}s timeout)")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(scan_single_port, ip, p, timeout, grab_banners): p
            for p in ports
        }
        done = 0
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
            done += 1
            # Progress every 10%
            if done % max(1, total // 10) == 0:
                pct = int(done / total * 100)
                logger.debug(f"Progress: {pct}% ({done}/{total})")

    return sorted(open_ports, key=lambda x: x["port"])


# ─── Port string parser ──────────────────────────────────────────────────────

def parse_ports(port_str: str) -> tuple[int, int]:
    """
    Parse port argument.
      "1-1024"       → (1, 1024)
      "80,443,8080"  → (80, 8080)   scans full range between min and max
      "443"          → (443, 443)
    """
    port_str = port_str.strip()
    if "-" in port_str:
        parts = port_str.split("-")
        return int(parts[0]), int(parts[1])
    if "," in port_str:
        nums = [int(p.strip()) for p in port_str.split(",")]
        return min(nums), max(nums)
    n = int(port_str)
    return n, n


# ─── Report saving ───────────────────────────────────────────────────────────

def save_report(
    target: str,
    ip: str,
    open_ports: list[dict],
    output_format: str = "txt"
) -> str:
    """
    Save scan results to reports/ in the chosen format.
    Returns the path of the saved file.
    """
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    base = f"reports/scan_{ip}_{timestamp}"

    risky = [p for p in open_ports if p.get("risk")]

    if output_format == "json":
        path = f"{base}.json"
        payload = {
            "meta": {
                "target":        target,
                "ip":            ip,
                "timestamp":     timestamp,
                "tool":          "company-security-tool v2.0",
                "total_open":    len(open_ports),
                "risky_count":   len(risky),
            },
            "risky_ports": risky,
            "open_ports":  open_ports,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    elif output_format == "csv":
        path = f"{base}.csv"
        fieldnames = ["port", "service", "banner", "risk", "status"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(open_ports)

    else:  # txt (default)
        path = f"{base}.txt"
        with open(path, "w", encoding="utf-8") as f:
            f.write("=" * 50 + "\n")
            f.write("  COMPANY SECURITY SCAN REPORT\n")
            f.write("=" * 50 + "\n")
            f.write(f"  Target    : {target}\n")
            f.write(f"  IP        : {ip}\n")
            f.write(f"  Timestamp : {timestamp}\n")
            f.write(f"  Open ports: {len(open_ports)}\n")
            if risky:
                f.write(f"  RISKY     : {len(risky)} port(s) require attention!\n")
            f.write("=" * 50 + "\n\n")

            if not open_ports:
                f.write("No open ports found.\n")
            else:
                for p in open_ports:
                    banner_str = f"  [{p['banner']}]" if p.get("banner") else ""
                    f.write(f"  [OPEN] {p['port']:<6} {p['service']:<18}{banner_str}\n")
                    if p.get("risk"):
                        f.write(f"         ⚠  RISK: {p['risk']}\n")

            if risky:
                f.write("\n" + "─" * 50 + "\n")
                f.write("  ACTION REQUIRED — Risky open ports:\n")
                f.write("─" * 50 + "\n")
                for p in risky:
                    f.write(f"  Port {p['port']} ({p['service']}): {p['risk']}\n")

    logger.info(f"Report saved → {path}")
    return path
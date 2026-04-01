import socket
import argparse
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor


def check_website(host):
    try:
        ip = socket.gethostbyname(host)
        print(f"[+] {host} resolves to {ip}")
        return ip

    except socket.error:
        print(f"[-] Could not resolve {host}")
        return None


def scan_port(ip, port):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)

    result = s.connect_ex((ip, port))

    if result == 0:
        status = "OPEN"
    else:
        status = "CLOSED"

    s.close()

    return (port, status)


def scan_ports(ip, start_port, end_port):

    print(f"\nScanning ports {start_port}-{end_port} on {ip}...\n")

    ports = range(start_port, end_port + 1)

    report = []

    with ThreadPoolExecutor(max_workers=100) as executor:

        results = executor.map(
            lambda port: scan_port(ip, port),
            ports
        )

        for port, status in results:

            print(f"{status} Port {port}")

            report.append(
                (port, status)
            )

    save_report(ip, report)


def save_report(ip, report):

    now = datetime.now()

    folder = "reports"

    # creează folderul dacă nu există
    if not os.path.exists(folder):
        os.makedirs(folder)

    filename = f"{folder}/scan_report_{ip}.csv"

    with open(filename, "w") as file:

        file.write("Port,Status\n")

        for port, status in report:

            file.write(
                f"{port},{status}\n"
            )

    print(
        f"\nReport saved as: {filename}"
    )


def main():

    parser = argparse.ArgumentParser(
        description="Network Security Scanner"
    )

    parser.add_argument(
        "target",
        help="Target domain or IP"
    )

    parser.add_argument(
        "--start",
        type=int,
        default=1,
        help="Start port"
    )

    parser.add_argument(
        "--end",
        type=int,
        default=1024,
        help="End port"
    )

    args = parser.parse_args()

    ip = check_website(
        args.target
    )

    if ip:

        scan_ports(
            ip,
            args.start,
            args.end
        )


if __name__ == "__main__":

    main()
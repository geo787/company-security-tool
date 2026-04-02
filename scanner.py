import socket
import os
from datetime import datetime


def check_website(host):
    try:
        ip = socket.gethostbyname(host)
        print(f"[+] {host} resolves to {ip}")
        return ip

    except socket.gaierror:
        print(f"[-] Could not resolve {host}")
        return None


def scan_ports(target_ip, start_port, end_port):
    open_ports = []

    for port in range(start_port, end_port + 1):

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            socket.setdefaulttimeout(0.5)

            result = sock.connect_ex((target_ip, port))

            if result == 0:
                print(f"[OPEN] Port {port}")
                open_ports.append(port)

            sock.close()

        except Exception:
            pass

    return open_ports


def save_report(target_ip, open_ports):

    if not os.path.exists("reports"):
        os.makedirs("reports")

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    filename = f"reports/scan_report_{target_ip}_{timestamp}.txt"

    with open(filename, "w") as file:

        file.write("=== Port Scan Report ===\n")
        file.write(f"Target: {target_ip}\n")
        file.write(f"Scan time: {timestamp}\n\n")

        if open_ports:

            file.write("Open ports:\n")

            for port in open_ports:
                file.write(f"Port {port}\n")

        else:

            file.write("No open ports found.\n")

    print(f"\nReport saved as: {filename}")
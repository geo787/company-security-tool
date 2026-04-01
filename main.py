import socket
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

    return f"{status} Port {port}"

def scan_ports(ip):

    print(f"\nScanning ports on {ip}...\n")

    ports = range(1, 1025)

    report = []

    with ThreadPoolExecutor(max_workers=100) as executor:

        results = executor.map(
            lambda port: scan_port(ip, port),
            ports
        )

        for result in results:
            print(result)
            report.append(result)

    save_report(ip, report)

def save_report(ip, report):

    now = datetime.now()
    filename = f"scan_report_{ip}.txt"

    with open(filename, "w") as file:

        file.write(f"Scan Report for {ip}\n")
        file.write(f"Date: {now}\n\n")

        for line in report:
            file.write(line + "\n")

    print(f"\nReport saved as: {filename}")

if __name__ == "__main__":

    website = input("Enter website: ")
    ip = check_website(website)

    if ip:
        scan_ports(ip)
import socket
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

    return f"{status} Port {port}"

def scan_ports(ip):

    print(f"\nScanning ports on {ip}...\n")

    ports = range(1, 1025)

    report = []

    with ThreadPoolExecutor(max_workers=100) as executor:

        results = executor.map(
            lambda port: scan_port(ip, port),
            ports
        )

        for result in results:
            print(result)
            report.append(result)

    save_report(ip, report)

def save_report(ip, report):

    now = datetime.now()
    filename = f"scan_report_{ip}.txt"

    with open(filename, "w") as file:

        file.write(f"Scan Report for {ip}\n")
        file.write(f"Date: {now}\n\n")

        for line in report:
            file.write(line + "\n")

    print(f"\nReport saved as: {filename}")

if __name__ == "__main__":

    website = input("Enter website: ")
    ip = check_website(website)

    if ip:
        scan_ports(ip)
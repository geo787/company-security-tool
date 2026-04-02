import socket
import threading
from datetime import datetime

# lista globală pentru porturi deschise
open_ports = []

# lock pentru thread safety
lock = threading.Lock()


def check_website(host):
    try:
        ip = socket.gethostbyname(host)
        print(f"[+] {host} resolves to {ip}")
        return ip

    except socket.gaierror:
        print("[-] Could not resolve host.")
        return None


def scan_port(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)

        result = sock.connect_ex((target_ip, port))

        if result == 0:
            with lock:
                print(f"[OPEN] Port {port}")
                open_ports.append(port)

        sock.close()

    except Exception:
        pass


def scan_ports(target_ip, start_port, end_port):
    threads = []

    # reset list
    global open_ports
    open_ports = []

    print(f"Scanning ports {start_port}-{end_port} on {target_ip}...\n")

    for port in range(start_port, end_port + 1):
        thread = threading.Thread(
            target=scan_port,
            args=(target_ip, port)
        )

        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    return open_ports


def save_report(target_ip, open_ports):
    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    filename = f"scan_report_{target_ip}_{now}.txt"

    with open(filename, "w") as file:
        file.write("=== Port Scan Report ===\n")
        file.write(f"Target: {target_ip}\n")
        file.write(f"Scan time: {now}\n\n")

        if open_ports:
            file.write("Open ports:\n")

            for port in open_ports:
                file.write(f"Port {port}\n")

        else:
            file.write("No open ports found.\n")

    print(f"\nReport saved as: {filename}")
from scanner import check_website, scan_ports, save_report


def main():
    print("=== Company Security Port Scanner ===\n")

    try:
        target = input("Enter website: ").strip()

        if not target:
            print("No website entered.")
            return

        target_ip = check_website(target)

        if not target_ip:
            return

        try:
            start_port = int(input("Enter start port: "))
            end_port = int(input("Enter end port: "))

        except ValueError:
            print("Ports must be numbers.")
            return

        if start_port < 0 or end_port > 65535:
            print("Invalid port range.")
            return

        if start_port > end_port:
            print("Start port must be less than end port.")
            return

        print(f"\nScanning ports {start_port}-{end_port} on {target_ip}...\n")

        open_ports = scan_ports(target_ip, start_port, end_port)

        if not open_ports:
            print("\nNo open ports found.")
        else:
            print(f"\nOpen ports found: {len(open_ports)}")

        save_report(target_ip, open_ports)

        print("\nScan completed successfully.")

    except KeyboardInterrupt:
        print("\nScan interrupted by user.")


if __name__ == "__main__":
    main()
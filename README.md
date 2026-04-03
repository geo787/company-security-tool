# 🔐 Company Security Port Scanner

A lightweight and practical Python-based security tool designed to scan TCP ports, identify exposed services, and generate structured security reports.
Built for educational use, cybersecurity practice, and basic network reconnaissance.

## 🚀 Overview

**Company Security Port Scanner** 
Is a command-line tool that helps identify open ports on a target system within a specified range.
It resolves domain names, performs TCP connection checks, and exports scan results into readable report files.

This project demonstrates core networking and security concepts such as:

* TCP/IP communication
* DNS resolution
* Port scanning
* Service exposure detection
* Report generation
* Error handling and input validation


## ⚙️ Features

* Scan custom port ranges (e.g., 1–1024)
* Detect open TCP ports
* Resolve domain names to IP addresses
* Generate TXT and CSV security reports
* Simple and clean CLI interface
* Cross-platform (Windows / Linux / macOS)
* Modular Python code structure


## 🧰 Technologies Used

* Python 3
* socket (network communication)
* datetime (timestamp generation)
* os (file and directory management)
* Git & GitHub (version control)

## 📦 Project Structure

company-security-tool/

main.py
scanner.py
reports/
README.md
.gitignore


▶️ How to Run

### 1. Clone the repository

git clone https://github.com/geo787/company-security-tool.git

cd company-security-tool


### 2. Create a virtual environment

python -m venv venv


### 3. Activate environment

Windows:

venv\Scripts\activate


### 4. Run the scanner

python main.py


## 🧪 Example Usage

Enter website:

scanme.nmap.org

Enter start port:

1

Enter end port:

1024

Output:

[OPEN] Port 22
[OPEN] Port 80

Report saved as:

reports/scan_report_45.33.32.156_YYYY-MM-DD.txt


## 📄 Output Reports

After each scan, the tool automatically generates a report:

TXT report:

reports/scan_report_TARGET_TIMESTAMP.txt

CSV report:

reports/scan_report_TARGET_TIMESTAMP.csv

These reports can be used for:

* security documentation
* vulnerability assessment notes
* network auditing
* cybersecurity exercises

## 🔒 Ethical Use Notice

This tool is intended strictly for:

* educational purposes
* authorized security testing
* cybersecurity learning environments

Do not use this tool to scan systems without permission.


## 🎯 Future Improvements

* Multithreaded scanning
* Service detection (banner grabbing)
* JSON report export
* CLI arguments support (argparse)
* Basic vulnerability detection
* Logging system
* GUI interface

## 👩‍💻 Author

Roberta Barba
Cybersecurity & Computer Science
GitHub: https://github.com/geo787

## ⭐ Why This Project Matters

This project demonstrates practical cybersecurity skills, including:

* network scanning fundamentals
* secure coding practices
* structured reporting
* real-world security tooling concepts

It is designed as a portfolio-ready project for cybersecurity, networking, and IT roles.

# 🔐 Company Security Port Scanner

A practical Python-based security tool designed to scan TCP ports, identify exposed services, and generate structured security reports.

This project is built as a **portfolio-ready cybersecurity tool** demonstrating real-world networking, security, and software engineering skills relevant for startups, IT teams, and security analysts.

# 🚀 Overview

**Company Security Port Scanner** 

Is a command-line security tool that helps identify open ports on a target system within a specified range.

It resolves domain names, performs TCP connection checks, and exports scan results into readable report files.

The tool simulates a real-world security task commonly performed before deploying applications, auditing infrastructure, or performing authorized penetration testing.


# 🏢 Real-World Use Case

A startup deploying a web application wants to verify that only required services are exposed before going live.

This tool allows the team to:

* detect unintended open ports
* verify security configuration
* document network exposure
* support compliance and security checks
* assist in basic vulnerability assessments

Typical environments where this tool can be used:

* startup infrastructure validation
* DevOps deployment checks
* network security audits
* cybersecurity labs and exercises
* educational environments

# 🧠 Architecture

User Input

```
    |
    v
```

Domain Resolver (DNS)

```
    |
    v
```

TCP Port Scanner

```
    |
    v
```

Report Generator

```
    |
    v
```

TXT / CSV Output Files

# ⚙️ Features

* Scan custom port ranges (example: 1–1024)
* Detect open TCP ports
* Resolve domain names to IP addresses
* Generate TXT and CSV security reports
* Simple and clean command-line interface
* Cross-platform (Windows / Linux / macOS)
* Modular Python code structure
* Input validation and error handling

# 🛡️ Skills Demonstrated

## Networking

* TCP/IP communication
* DNS resolution
* Port scanning logic
* Socket programming

## Cybersecurity

* basic reconnaissance techniques
* service exposure detection
* network enumeration
* structured security reporting

## Software Engineering

* modular Python architecture
* error handling
* input validation
* file system operations
* logging and reporting design

# 🧰 Technologies Used

* Python 3
* socket
* datetime
* os
* Git
* GitHub

# 📦 Project Structure

company-security-tool/

```
main.py
scanner.py
reports/
README.md
.gitignore
```

# ▶️ Installation

## 1. Clone repository

```
git clone https://github.com/geo787/company-security-tool.git

cd company-security-tool
```

## 2. Create a virtual environment

```
python -m venv venv
```

## 3. Activate environment

Windows:

```
venv\Scripts\activate
```

Linux / macOS:

```
source venv/bin/activate
```

# ▶️ Run the Scanner

```
python main.py
```

Example input:

Target:

```
scanme.nmap.org
```

Port range:

```
1
1024
```

# 📸 Sample Scan Output

```
Scanning target: scanme.nmap.org

Open ports detected:

[OPEN] Port 22  -> SSH
[OPEN] Port 80  -> HTTP

Scan completed successfully
```

Generated reports:

```
reports/scan_report_45.33.32.156_2026-04-07.txt

reports/scan_report_45.33.32.156_2026-04-07.csv
```

# 📄 Output Reports

After each scan, the tool automatically generates structured reports.

## TXT Report

Used for:

* documentation
* audit logs
* incident notes

## CSV Report

Used for:

* spreadsheet analysis
* security dashboards
* automation workflows

# 🔒 Ethical Use Notice

This tool is intended strictly for:

* educational purposes
* authorized security testing
* cybersecurity learning environments

Do not use this tool to scan systems without permission.

# 🚀 Roadmap

## Version 1.1

* multithreaded scanning
* performance optimization
* faster port detection

## Version 1.2

* service detection (banner grabbing)
* timeout handling improvements
* logging system

## Version 2.0

* vulnerability detection module
* JSON report export
* CLI arguments support (argparse)

## Version 3.0

* web dashboard interface
* REST API integration
* Docker container deployment

# 🧪 Practical Development Plan

This plan transforms the project from a simple script into a real-world cybersecurity tool suitable for job applications and startup environments.

## Phase 1 — Stability and Performance (1–2 weeks)

Goal:

Make the scanner reliable and production-ready.

Tasks:

* implement multithreading
* add timeout control
* improve error handling
* add logging system
* optimize scanning speed

Deliverables:

* faster scans
* stable execution
* professional logs

## Phase 2 — Security Features (2–3 weeks)

Goal:

Transform the tool into a real security utility.

Tasks:

* implement banner grabbing
* detect service versions
* identify common risky ports
* basic vulnerability indicators

Examples:

* open Telnet
* open FTP
* exposed SSH

Deliverables:

* service detection
* security warnings
* enriched reports

## Phase 3 — Automation and CLI (2 weeks)

Goal:

Make the tool usable in scripts and DevOps pipelines.

Tasks:

* add argparse support
* allow command-line parameters
* add configuration file
* enable batch scanning

Example usage:

```
python main.py --target example.com --ports 1-1024
```

Deliverables:

* automation-ready scanner
* DevOps compatibility

## Phase 4 — Deployment and Portfolio Readiness (2–3 weeks)

Goal:

Make the project attractive for recruiters and startups.

Tasks:

* create Docker container
* add requirements.txt
* add architecture diagram image
* create demo screenshots
* add usage documentation

Deliverables:

* deployable security tool
* production-style repository

## Phase 5 — Advanced Version (Optional)

Goal:

Transform the project into a flagship cybersecurity portfolio project.

Possible extensions:

* web interface dashboard
* REST API
* scheduled scans
* email alerts
* vulnerability database integration
* network discovery module

# 📌 Recommended Next Commit Order

1. Add a logging system

2. Implement multithreading

3. Add CLI arguments

4. Add banner grabbing

5. Add Docker support

# 👩‍💻 Author

Roberta Barba

Cybersecurity & Computer Science

GitHub:

[https://github.com/geo787](https://github.com/geo787)

# ⭐ Why This Project Matters

This project demonstrates practical cybersecurity and software engineering capabilities required in real technical environments.

It shows the ability to:

* build functional security tools
* understand networking fundamentals
* automate technical processes
* generate structured reports
* design scalable software components

This repository is intended as a portfolio project for:

* Cybersecurity roles
* Network engineering roles
* DevOps roles
* QA and testing roles
* Startup technical positions

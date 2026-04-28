![Python 3.11](https://img.shields.io/badge/Python-3.11-blue)
![Tests](https://img.shields.io/badge/Tests-22%2F22-success)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)
![License](https://img.shields.io/badge/License-MIT-green)

# Security Port Scanner v2.0

Fast, concurrent TCP port scanner with service detection, risk scoring, REST API, and Docker support.

## Features

- **Multithreaded scanning**: 1-65535 ports in seconds using ThreadPoolExecutor
- **Service detection**: Identifies 28 common services (SSH, HTTP, MySQL, RDP, etc.)
- **Banner grabbing**: Auto-detects service versions
- **Risk scoring**: Flags 15 dangerous ports (Telnet, RDP, SMB, exposed databases)
- **REST API**: FastAPI with Pydantic validation & rate limiting
- **Output formats**: TXT, JSON, CSV with metadata & risk classification

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Scan localhost ports 1-1024
python main.py -t 127.0.0.1 -p 1-1024

# API server (http://localhost:8000/docs)
uvicorn api:app --reload
```

## CLI Examples

```bash
# Scan full range with threading
python main.py -t 192.168.1.1 -p 1-65535 --threads 500 --timeout 0.3

# Export as JSON
python main.py -t example.com -p 80,443,3306 -o json

# Verbose output with no banners (faster)
python main.py -t app.io -p 1-1024 --no-banners -v
```

## API Usage

```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "scanme.nmap.org",
    "start_port": 1,
    "end_port": 1024,
    "threads": 300,
    "timeout": 0.5
  }'
```

**Response:**
```json
{
  "meta": {
    "target": "scanme.nmap.org",
    "ip": "45.33.32.156",
    "timestamp": "2026-04-27T14:30:00",
    "total_open": 2,
    "risky_count": 0
  },
  "open_ports": [
    {"port": 22, "service": "SSH", "banner": "OpenSSH_7.4", "risk": null, "status": "open"},
    {"port": 80, "service": "HTTP", "banner": "Apache/2.4.6", "risk": null, "status": "open"}
  ],
  "risky_ports": []
}
```

## Docker

```bash
# Build and run
docker-compose up --build

# Test
curl http://localhost:8000/api/health
```

## Architecture

```
CLI (main.py)  ─┐
API (api.py)   ┼─→ scanner.py (threading, detection) → reports/
Tests ─────────┘
```

## Ethical Use

This tool is for **authorized security testing only**. Unauthorized port scans violate Computer Fraud and Abuse Act (CFAA). Use only on systems you own or have explicit permission to test.

## Author

**Roberta Barba**
[GitHub](https://github.com/geo787) | [LinkedIn](https://linkedin.com/in/roberta-barba)
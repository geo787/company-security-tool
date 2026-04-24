import pytest # type: ignore
import json
import os
import tempfile
from unittest.mock import patch, MagicMock

from scanner import (
    check_website,
    parse_ports,
    scan_single_port,
    save_report,
    COMMON_SERVICES,
    RISKY_PORTS,
)


# ─── DNS resolution ──────────────────────────────────────────────────────────

class TestCheckWebsite:
    def test_resolves_known_ip(self):
        """scanme.nmap.org always resolves to this IP."""
        ip = check_website("scanme.nmap.org")
        assert ip == "45.33.32.156"

    def test_returns_none_on_invalid_domain(self):
        ip = check_website("this-domain-absolutely-does-not-exist-xyz123.com")
        assert ip is None

    def test_returns_ip_for_raw_ip(self):
        ip = check_website("8.8.8.8")
        assert ip == "8.8.8.8"

    def test_handles_empty_string(self):
        ip = check_website("")
        assert ip is None


# ─── Port parsing ────────────────────────────────────────────────────────────

class TestParsePorts:
    def test_range_format(self):
        assert parse_ports("1-1024") == (1, 1024)

    def test_range_full(self):
        assert parse_ports("1-65535") == (1, 65535)

    def test_single_port(self):
        assert parse_ports("443") == (443, 443)

    def test_list_format(self):
        start, end = parse_ports("80,443,8080")
        assert start == 80
        assert end == 8080

    def test_list_unordered(self):
        start, end = parse_ports("8080,80,443")
        assert start == 80
        assert end == 8080

    def test_invalid_raises(self):
        with pytest.raises((ValueError, IndexError)):
            parse_ports("notaport")


# ─── Port scanning ───────────────────────────────────────────────────────────

class TestScanSinglePort:
    """Uses scanme.nmap.org — requires internet access."""

    def test_open_port_http(self):
        result = scan_single_port("45.33.32.156", 80, grab_banners=False)
        assert result is not None
        assert result["port"] == 80
        assert result["service"] == "HTTP"
        assert result["status"] == "open"

    def test_open_port_ssh(self):
        result = scan_single_port("45.33.32.156", 22, grab_banners=False)
        assert result is not None
        assert result["port"] == 22
        assert result["service"] == "SSH"

    def test_closed_port_returns_none(self):
        result = scan_single_port("45.33.32.156", 9999, grab_banners=False)
        assert result is None

    def test_risky_port_has_risk_label(self):
        """If port 3306 were open, it should flag as risky."""
        # Mock a connection success on MySQL port
        with patch("scanner.socket.socket") as mock_sock:
            instance = MagicMock()
            instance.connect_ex.return_value = 0
            mock_sock.return_value = instance

            result = scan_single_port("1.2.3.4", 3306, grab_banners=False)
            assert result is not None
            assert result["risk"] is not None
            assert "MySQL" in result["risk"]

    def test_result_has_required_keys(self):
        with patch("scanner.socket.socket") as mock_sock:
            instance = MagicMock()
            instance.connect_ex.return_value = 0
            mock_sock.return_value = instance

            result = scan_single_port("1.2.3.4", 80, grab_banners=False)
            assert result is not None
            for key in ("port", "service", "banner", "risk", "status"):
                assert key in result


# ─── Report saving ───────────────────────────────────────────────────────────

class TestSaveReport:
    SAMPLE_PORTS = [
        {"port": 22, "service": "SSH", "banner": "OpenSSH_8.9", "risk": None, "status": "open"},
        {"port": 80, "service": "HTTP", "banner": "nginx/1.24", "risk": None, "status": "open"},
        {"port": 3306, "service": "MySQL", "banner": None,
         "risk": "MySQL — database exposed to internet", "status": "open"},
    ]

    def test_saves_txt(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        path = save_report("example.com", "1.2.3.4", self.SAMPLE_PORTS, "txt")
        assert os.path.exists(path)
        content = open(path).read()
        assert "example.com" in content
        assert "MySQL" in content
        assert "RISK" in content

    def test_saves_json(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        path = save_report("example.com", "1.2.3.4", self.SAMPLE_PORTS, "json")
        assert path.endswith(".json")
        data = json.load(open(path))
        assert data["meta"]["target"] == "example.com"
        assert data["meta"]["total_open"] == 3
        assert data["meta"]["risky_count"] == 1
        assert len(data["open_ports"]) == 3

    def test_saves_csv(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        path = save_report("example.com", "1.2.3.4", self.SAMPLE_PORTS, "csv")
        assert path.endswith(".csv")
        lines = open(path).readlines()
        assert lines[0].startswith("port")   # header
        assert len(lines) == 4               # header + 3 ports

    def test_empty_ports(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        path = save_report("example.com", "1.2.3.4", [], "txt")
        content = open(path).read()
        assert "No open ports found" in content


# ─── Data integrity ───────────────────────────────────────────────────────────

class TestDataMaps:
    def test_all_risky_ports_in_service_map(self):
        """Every risky port should have a known service name."""
        for port in RISKY_PORTS:
            assert port in COMMON_SERVICES, (
                f"Port {port} is in RISKY_PORTS but not in COMMON_SERVICES"
            )

    def test_no_duplicate_ports(self):
        port_list = list(COMMON_SERVICES.keys())
        assert len(port_list) == len(set(port_list))

    def test_port_range_valid(self):
        for port in COMMON_SERVICES:
            assert 1 <= port <= 65535
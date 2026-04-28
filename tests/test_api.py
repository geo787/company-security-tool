"""
Tests for FastAPI port scanner endpoints.
"""

import pytest
from fastapi.testclient import TestClient

from api import app

client = TestClient(app)


def test_health_endpoint():
    """GET /api/health returns 200 with status ok."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["version"] == "2.0.0"


def test_root_endpoint():
    """GET / returns docs link."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "docs" in data


def test_scan_invalid_target():
    """POST /api/scan with invalid hostname returns 400."""
    response = client.post(
        "/api/scan",
        json={
            "target": "invalid.example.not.exists.test.local",
            "start_port": 80,
            "end_port": 80,
        }
    )
    assert response.status_code == 400


def test_scan_invalid_ports():
    """POST /api/scan with port > 65535 returns 422."""
    response = client.post(
        "/api/scan",
        json={
            "target": "127.0.0.1",
            "start_port": 1,
            "end_port": 70000,  # Invalid: > 65535
        }
    )
    assert response.status_code == 422


def test_scan_empty_target():
    """POST /api/scan without target returns 422."""
    response = client.post(
        "/api/scan",
        json={
            "target": "",
            "start_port": 1,
            "end_port": 100,
        }
    )
    assert response.status_code == 422


def test_scan_valid_request():
    """POST /api/scan with valid localhost returns 200 or 400."""
    response = client.post(
        "/api/scan",
        json={
            "target": "127.0.0.1",
            "start_port": 80,
            "end_port": 80,
            "threads": 10,
            "timeout": 0.5,
            "grab_banners": False,
        }
    )
    # Could return 200 (success) or 400 (can't resolve) depending on system
    assert response.status_code in [200, 400]

    if response.status_code == 200:
        data = response.json()
        assert "meta" in data
        assert "open_ports" in data
        assert "risky_ports" in data
        assert "target" in data["meta"]
        assert "ip" in data["meta"]


def test_docs_available():
    """GET /docs returns 200."""
    response = client.get("/docs")
    # Swagger UI available (or redirects)
    assert response.status_code in [200, 307]


def test_scan_port_order():
    """POST /api/scan validates start_port <= end_port."""
    response = client.post(
        "/api/scan",
        json={
            "target": "127.0.0.1",
            "start_port": 100,
            "end_port": 50,  # Invalid: end < start
            "threads": 10,
        }
    )
    assert response.status_code == 422


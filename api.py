"""
FastAPI web interface for port scanner.
Provides REST endpoints for scanning and health checks.
"""

import asyncio
import logging
from typing import Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
import uvicorn

import scanner

# ─── Setup ────────────────────────────────────────────────────────────────

logger = logging.getLogger("scanner")

app = FastAPI(
    title="Security Scanner API",
    description="Port scanner with threading, service detection, and risk scoring",
    version="2.0.0",
)

# Enable CORS for all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Track concurrent scans (rate limiting: max 5 concurrent)
ACTIVE_SCANS: set[str] = set()
MAX_CONCURRENT_SCANS = 5


# ─── Pydantic Models ──────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    """Request model for port scan."""
    target: str = Field(..., description="Target hostname or IP address", min_length=1)
    start_port: int = Field(default=1, description="Start port", ge=1, le=65535)
    end_port: int = Field(default=1024, description="End port", ge=1, le=65535)
    threads: int = Field(default=300, description="Max concurrent threads", ge=1, le=1000)
    timeout: float = Field(default=0.5, description="Connection timeout in seconds", gt=0, le=30)
    grab_banners: bool = Field(default=True, description="Grab service banners")

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        """Validate target is not empty."""
        if not v or not v.strip():
            raise ValueError("target cannot be empty")
        return v.strip()

    @field_validator("end_port")
    @classmethod
    def validate_port_range(cls, v: int, info) -> int:
        """Validate end_port >= start_port."""
        if "start_port" in info.data and v < info.data["start_port"]:
            raise ValueError("end_port must be >= start_port")
        return v


class PortResult(BaseModel):
    """Single port scan result."""
    port: int
    service: str
    banner: Optional[str] = None
    risk: Optional[str] = None
    status: str


class ScanResponse(BaseModel):
    """Complete scan response."""
    meta: dict = Field(..., description="Scan metadata")
    open_ports: list[PortResult]
    risky_ports: list[PortResult]


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str


# ─── Endpoints ────────────────────────────────────────────────────────────

@app.post("/api/scan", response_model=ScanResponse, status_code=200)
async def scan_ports_endpoint(request: ScanRequest) -> dict:
    """
    Scan target for open ports.

    Rate limited to 5 concurrent scans.
    Returns JSON with metadata, open ports, and risky ports.
    """
    # Rate limiting check
    if len(ACTIVE_SCANS) >= MAX_CONCURRENT_SCANS:
        raise HTTPException(
            status_code=429,
            detail=f"Too many concurrent scans. Max: {MAX_CONCURRENT_SCANS}"
        )

    scan_id = f"{request.target}_{datetime.now().timestamp()}"
    ACTIVE_SCANS.add(scan_id)

    try:
        # Resolve hostname to IP
        ip = scanner.check_website(request.target)
        if not ip:
            raise HTTPException(status_code=400, detail=f"Cannot resolve '{request.target}'")

        # Run scan in thread pool (non-blocking)
        loop = asyncio.get_event_loop()
        open_ports = await loop.run_in_executor(
            None,
            scanner.scan_ports,
            ip,
            request.start_port,
            request.end_port,
            request.threads,
            request.timeout,
            request.grab_banners,
        )

        # Prepare response
        risky_ports = [p for p in open_ports if p.get("risk")]
        timestamp = datetime.now().isoformat()

        return {
            "meta": {
                "target": request.target,
                "ip": ip,
                "timestamp": timestamp,
                "total_open": len(open_ports),
                "risky_count": len(risky_ports),
                "scan_range": f"{request.start_port}-{request.end_port}",
                "threads_used": request.threads,
            },
            "open_ports": open_ports,
            "risky_ports": risky_ports,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        ACTIVE_SCANS.discard(scan_id)


@app.get("/api/health", response_model=HealthResponse)
async def health_check() -> dict:
    """Health check endpoint."""
    return {
        "status": "ok",
        "version": "2.0.0",
    }


@app.get("/docs")
async def docs():
    """Auto-generated Swagger UI (built-in to FastAPI)."""
    pass


# ─── Root endpoint ────────────────────────────────────────────────────────

@app.get("/")
async def root() -> dict:
    """API root — redirects to /docs."""
    return {
        "message": "Security Scanner API v2.0",
        "docs": "/docs",
        "health": "/api/health",
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    uvicorn.run(app, host="0.0.0.0", port=8000)

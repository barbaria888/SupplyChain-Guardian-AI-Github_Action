"""
Enterprise FastAPI Application — Guardian Demo Service
------------------------------------------------------
A minimal but production-patterned FastAPI service used as the
target application for the Supply Chain Guardian pipeline.

Intentionally built with:
  - Structured JSON logging
  - A /healthz liveness probe endpoint (required by k8s manifests)
  - A /readyz readiness probe endpoint
  - A /metrics stub (for Prometheus scraping in future iterations)
"""

import logging
import os
import sys
import time
from datetime import datetime, timezone

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# ---------------------------------------------------------------------------
# Structured Logging Setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "msg": "%(message)s"}',
)
logger = logging.getLogger("guardian-service")

# ---------------------------------------------------------------------------
# App Initialization
# ---------------------------------------------------------------------------
APP_VERSION = os.getenv("APP_VERSION", "1.0.0")
APP_ENV = os.getenv("APP_ENV", "production")
START_TIME = time.time()

app = FastAPI(
    title="Guardian Demo Service",
    description=(
        "Target application for the Proactive DevSecOps "
        "Supply Chain Guardian pipeline."
    ),
    version=APP_VERSION,
    docs_url="/docs" if APP_ENV != "production" else None,
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/", tags=["root"])
async def root() -> JSONResponse:
    """Root endpoint — returns service identity."""
    return JSONResponse(
        {
            "service": "guardian-demo-service",
            "version": APP_VERSION,
            "environment": APP_ENV,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


@app.get("/healthz", tags=["probes"])
async def liveness() -> JSONResponse:
    """
    Kubernetes liveness probe.
    Returns 200 if the process is alive and the event loop is responsive.
    """
    return JSONResponse({"status": "ok"})


@app.get("/readyz", tags=["probes"])
async def readiness() -> JSONResponse:
    """
    Kubernetes readiness probe.
    Returns 200 when the service is ready to accept traffic.
    In a real service, this would check DB connections, cache, etc.
    """
    uptime_seconds = round(time.time() - START_TIME, 2)
    return JSONResponse({"status": "ready", "uptime_seconds": uptime_seconds})


@app.get("/metrics", tags=["observability"])
async def metrics() -> JSONResponse:
    """
    Prometheus metrics stub.
    Replace with prometheus_client exposition in production.
    """
    uptime_seconds = round(time.time() - START_TIME, 2)
    return JSONResponse(
        {
            "uptime_seconds": uptime_seconds,
            "version": APP_VERSION,
            "note": "Replace with prometheus_client for production scraping.",
        }
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info("Starting Guardian Demo Service v%s [%s]", APP_VERSION, APP_ENV)
    uvicorn.run(
        "main:app",
        host="0.0.0.0",  # noqa: S104 — required for container networking
        port=8080,
        log_level="info",
    )

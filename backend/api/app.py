"""FastAPI Application Entry Point for Avionics PQC Security Lab.

Provides REST endpoints for simulated avionics nodes, hybrid PQC handshake,
authenticated secure messaging, security attack simulations, and benchmark metrics.
"""

from __future__ import annotations

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.api.routes import (
    avionics_router,
    benchmarks_router,
    health_router,
    protocol_router,
    policy_router,
    security_router,
)

app = FastAPI(
    title="Avionics PQC Security Lab API",
    description=(
        "REST API layer for evaluating hybrid post-quantum cryptography "
        "(X25519 + ML-KEM-1024, Ed25519 + SLH-DSA-shake_128f, HKDF-SHA256, AES-256-GCM) "
        "in simulated avionics communications (FCC, NAV, GCS)."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Configure CORS for local frontend development (Vite, React, etc.)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "*",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers under /api
app.include_router(health_router, prefix="/api")
app.include_router(avionics_router, prefix="/api")
app.include_router(protocol_router, prefix="/api")
app.include_router(policy_router, prefix="/api")
app.include_router(security_router, prefix="/api")
app.include_router(benchmarks_router, prefix="/api")


@app.get("/", tags=["Root"])
def root_endpoint() -> dict[str, str]:
    """Root endpoint welcoming users and pointing to documentation."""
    return {
        "service": "Avionics PQC Security Lab API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/api/health",
    }


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch unhandled runtime errors and return clean JSON response."""
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "InternalServerError",
            "detail": str(exc),
            "path": request.url.path,
        },
    )

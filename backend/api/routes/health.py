"""Health check API route."""

from __future__ import annotations

from fastapi import APIRouter

from backend.api.schemas import HealthResponse

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    """Return API health status and service metadata."""
    return HealthResponse(
        status="healthy",
        service="Avionics PQC Security Lab",
        api_version="1.0",
    )

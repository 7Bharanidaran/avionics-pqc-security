"""API route registrations."""

from __future__ import annotations

from .avionics import router as avionics_router
from .benchmarks import router as benchmarks_router
from .health import router as health_router
from .protocol import router as protocol_router
from .policy import router as policy_router
from .security import router as security_router

__all__ = [
    "avionics_router",
    "benchmarks_router",
    "health_router",
    "protocol_router",
    "policy_router",
    "security_router",
]

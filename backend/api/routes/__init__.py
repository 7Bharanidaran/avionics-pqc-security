"""API route registrations."""

from __future__ import annotations

from .ai import router as ai_router
from .avionics import router as avionics_router
from .benchmarks import router as benchmarks_router
from .crypto_constructions import router as crypto_constructions_router
from .demonstration import router as demonstration_router
from .evaluation import router as evaluation_router
from .experiments import router as experiments_router
from .health import router as health_router
from .protocol import router as protocol_router
from .policy import router as policy_router
from .security import router as security_router

__all__ = [
    "ai_router",
    "avionics_router",
    "benchmarks_router",
    "crypto_constructions_router",
    "demonstration_router",
    "evaluation_router",
    "experiments_router",
    "health_router",
    "protocol_router",
    "policy_router",
    "security_router",
]




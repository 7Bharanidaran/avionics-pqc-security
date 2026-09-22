"""Phase 14 Practical Research Demonstration API Routes.

Exposes REST endpoints for:
1. Demonstration scenario catalog (GET /api/demonstration/scenarios)
2. Interactive demonstration execution (POST /api/demonstration/run)
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.demonstration.engine import DEMONSTRATION_ENGINE
from backend.demonstration.scenarios import (
    DEMO_SCENARIOS,
    get_demonstration_scenario,
    list_demonstration_scenarios,
)

logger = logging.getLogger("DemonstrationAPI")
router = APIRouter(prefix="/demonstration", tags=["Phase 14 Demonstration"])


class RunDemonstrationRequest(BaseModel):
    scenario_id: str = Field(default="DEMO_01_NORMAL", description="Scenario ID (e.g., DEMO_01_NORMAL through DEMO_08_REPLAY)")


@router.get("/scenarios")
def get_demonstration_scenarios() -> dict[str, Any]:
    """List all 8 standardized research demonstration scenarios."""
    return {
        "status": "SUCCESS",
        "total_scenarios": len(DEMO_SCENARIOS),
        "scenarios": list_demonstration_scenarios(),
    }


@router.post("/run")
def execute_demonstration_scenario(req: RunDemonstrationRequest) -> dict[str, Any]:
    """Execute an interactive demonstration scenario with real cryptographic pipeline and safety verification."""
    try:
        result = DEMONSTRATION_ENGINE.run_scenario(req.scenario_id)
        return {
            "status": "SUCCESS",
            "result": result.to_dict(),
        }
    except ValueError as ex:
        raise HTTPException(status_code=400, detail=str(ex))
    except Exception as ex:
        logger.exception("Failed to execute demonstration scenario %s: %s", req.scenario_id, ex)
        raise HTTPException(status_code=500, detail=f"Demonstration execution error: {str(ex)}")

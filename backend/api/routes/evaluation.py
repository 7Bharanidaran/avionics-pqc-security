"""Phase 13 Research Evaluation API Routes.

Exposes REST endpoints for:
1. Standardized scenario catalog (GET /api/evaluation/scenarios)
2. Running evaluation experiments (POST /api/evaluation/run)
3. Retrieving detailed scenario metrics (GET /api/evaluation/results)
4. Baseline comparative results (GET /api/evaluation/comparison)
5. 5-Way ablation & safety invariant validation (POST /api/evaluation/ablation)
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from backend.evaluation.ablation import run_ablation_study, run_safety_ablation
from backend.evaluation.baselines import (
    AI_ADAPTIVE,
    BASELINE_RULE,
    BASELINE_STATIC,
    EvaluationHarness,
    SystemConfiguration,
)
from backend.evaluation.metrics import compute_scenario_metrics
from backend.evaluation.runner import run_full_evaluation
from backend.evaluation.scenarios import EVAL_SCENARIOS, get_scenario, list_scenarios

logger = logging.getLogger("EvaluationAPI")
router = APIRouter(prefix="/evaluation", tags=["Phase 13 Research Evaluation"])

DATA_DIR = Path("data/evaluation")


class RunEvaluationRequest(BaseModel):
    scenario_id: str | None = Field(default=None, description="Optional specific scenario ID (e.g., S01_NORMAL)")
    system_config: str = Field(default="AI_ADAPTIVE", description="BASELINE_STATIC, BASELINE_RULE, or AI_ADAPTIVE")
    dwell_k: int = Field(default=3, ge=1, le=10, description="Hysteresis hold steps on downgrades")


@router.get("/scenarios")
def get_evaluation_scenarios() -> dict[str, Any]:
    """List all 12 standardized evaluation scenarios and their descriptions."""
    return {
        "status": "SUCCESS",
        "total_scenarios": len(EVAL_SCENARIOS),
        "scenarios": list_scenarios(),
    }


@router.post("/run")
def execute_evaluation(req: RunEvaluationRequest) -> dict[str, Any]:
    """Execute evaluation for all scenarios or a specific scenario."""
    harness = EvaluationHarness()

    try:
        cfg = SystemConfiguration(req.system_config)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid system_config '{req.system_config}'. Supported: {[c.value for c in SystemConfiguration]}",
        )

    if req.scenario_id:
        try:
            scenario = get_scenario(req.scenario_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        res = harness.run_scenario(scenario, cfg, dwell_k=req.dwell_k)
        metrics = compute_scenario_metrics(res, scenario)
        return {
            "status": "SUCCESS",
            "scenario_result": res.to_dict(),
            "comprehensive_metrics": metrics.to_dict(),
        }

    # Run full master evaluation
    logger.info("Executing full Phase 13 evaluation via API...")
    full_res = run_full_evaluation()
    return full_res


@router.get("/results")
def get_evaluation_results(scenario_id: str | None = Query(default=None)) -> dict[str, Any]:
    """Retrieve exported evaluation results from data/evaluation/scenario_results.json."""
    json_path = DATA_DIR / "scenario_results.json"
    if not json_path.exists():
        # Generate on demand
        run_full_evaluation()

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if scenario_id:
            if scenario_id not in data:
                raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found in results.")
            return {"status": "SUCCESS", "scenario": data[scenario_id]}
        return {"status": "SUCCESS", "total_scenarios": len(data), "scenarios": data}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to read evaluation results: {exc}")


@router.get("/comparison")
def get_baseline_comparison() -> dict[str, Any]:
    """Retrieve 3-way baseline comparison from data/evaluation/baseline_comparison.json."""
    json_path = DATA_DIR / "baseline_comparison.json"
    if not json_path.exists():
        run_full_evaluation()

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to read baseline comparison: {exc}")


@router.post("/ablation")
def execute_ablation() -> dict[str, Any]:
    """Execute 5-way ablation study and targeted safety invariant verification."""
    logger.info("Executing ablation experiments via API...")
    ablation_res = run_ablation_study()
    safety_ablation_res = run_safety_ablation()

    return {
        "status": "SUCCESS",
        "ablation_configurations": ablation_res,
        "safety_ablation": safety_ablation_res,
    }

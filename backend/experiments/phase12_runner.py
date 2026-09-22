"""Phase 12 Master Experiment Runner & Artifact Exporter.

Executes:
1. All 10 Digital Twin Operational Scenarios (SCN-001 through SCN-010)
2. Three-Way Comparative Evaluation (Mode A vs Mode B vs Mode C)
3. Adversarial Robustness & Safety Boundary Verification
4. Full structured export to data/phase12/ (JSON & CSV)

Usage:
    python -m backend.experiments.phase12_runner
"""

from __future__ import annotations

import csv
import json
import logging
import os
import platform
import sys
import time
from pathlib import Path
from typing import Any

from backend.experiments.closed_loop import (
    ClosedLoopEngine,
    SCENARIO_GENERATORS,
    run_adversarial_robustness_evaluation,
    run_comparative_evaluation,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("Phase12Runner")

OUTPUT_DIR = Path("data/phase12")


def export_phase12_artifacts() -> dict[str, Any]:
    """Execute all Phase 12 experiments and save JSON/CSV artifacts to data/phase12/."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    start_time = time.perf_counter()

    logger.info("Starting Phase 12 Closed-Loop Adaptive Intelligence Evaluation...")

    engine = ClosedLoopEngine()

    # 1. Run all 10 digital twin scenarios
    scenario_results: dict[str, Any] = {}
    all_telemetry_rows: list[dict[str, Any]] = []

    for scn_id in SCENARIO_GENERATORS.keys():
        logger.info("Executing Scenario %s...", scn_id)
        res = engine.run_scenario(scenario_id=scn_id, mode="MODE_C_AI_ASSISTED")
        scenario_results[scn_id] = res.to_dict()

        # Flatten timeline rows for CSV export
        for step in res.timeline:
            row = step.to_dict()
            row["scenario_id"] = scn_id
            row["scenario_name"] = res.summary.scenario_name
            all_telemetry_rows.append(row)

    # Export closed loop scenarios JSON
    scenarios_json_path = OUTPUT_DIR / "closed_loop_scenarios.json"
    with open(scenarios_json_path, "w", encoding="utf-8") as f:
        json.dump(scenario_results, f, indent=2)
    logger.info("Exported %s", scenarios_json_path)

    # Export digital twin telemetry CSV
    csv_path = OUTPUT_DIR / "digital_twin_telemetry.csv"
    if all_telemetry_rows:
        fieldnames = list(all_telemetry_rows[0].keys())
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_telemetry_rows)
    logger.info("Exported %d telemetry rows to %s", len(all_telemetry_rows), csv_path)

    # 2. Run Comparative Evaluation (Mode A vs Mode B vs Mode C)
    logger.info("Running Three-Way Comparative Evaluation across all modes...")
    comparative_results = run_comparative_evaluation()
    comp_json_path = OUTPUT_DIR / "comparative_evaluation.json"
    with open(comp_json_path, "w", encoding="utf-8") as f:
        json.dump(comparative_results, f, indent=2)
    logger.info("Exported %s", comp_json_path)

    # 3. Run Adversarial Robustness & Safety Boundary Verification
    logger.info("Running Adversarial Robustness & Safety Invariant Verifications...")
    adv_results = run_adversarial_robustness_evaluation()
    adv_json_path = OUTPUT_DIR / "adversarial_robustness.json"
    with open(adv_json_path, "w", encoding="utf-8") as f:
        json.dump(adv_results, f, indent=2)
    logger.info("Exported %s", adv_json_path)

    # 4. Export Metadata
    elapsed_sec = time.perf_counter() - start_time
    metadata = {
        "phase": "PHASE_12",
        "title": "Closed-Loop Adaptive Cryptographic Intelligence & Research Validation",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "execution_duration_sec": round(elapsed_sec, 2),
        "total_scenarios_evaluated": len(SCENARIO_GENERATORS),
        "total_steps_executed": len(all_telemetry_rows),
        "platform": platform.platform(),
        "python_version": sys.version,
        "scenarios_evaluated": list(SCENARIO_GENERATORS.keys()),
        "modes_evaluated": ["MODE_A_STATIC", "MODE_B_DETERMINISTIC", "MODE_C_AI_ASSISTED"],
        "artifacts_generated": [
            "closed_loop_scenarios.json",
            "digital_twin_telemetry.csv",
            "comparative_evaluation.json",
            "adversarial_robustness.json",
            "experiment_metadata.json",
        ],
    }

    meta_json_path = OUTPUT_DIR / "experiment_metadata.json"
    with open(meta_json_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    logger.info("Exported %s", meta_json_path)

    logger.info("Phase 12 Experiment Suite completed in %.2f seconds.", elapsed_sec)
    return {
        "metadata": metadata,
        "comparative_evaluation": comparative_results,
        "adversarial_robustness": adv_results,
    }


if __name__ == "__main__":
    export_phase12_artifacts()

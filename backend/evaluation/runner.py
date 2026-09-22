"""Phase 13 Master Evaluation Runner & Artifact Exporter.

Executes:
1. All 12 Standardized Operational Scenarios (S01 through S12) across 3 Baselines
2. Comprehensive Security, Adaptation, Performance, and AI Metrics Calculation
3. 5-Way Ablation Study and Safety Invariant Validation
4. Data Export to data/evaluation/ (JSON & CSV)
5. Automated Research Plot Generation in data/evaluation/plots/

Usage:
    python -m backend.evaluation.runner
"""

from __future__ import annotations

import csv
import json
import logging
import time
from pathlib import Path
from typing import Any

from backend.evaluation.ablation import run_ablation_study, run_safety_ablation
from backend.evaluation.baselines import (
    AI_ADAPTIVE,
    BASELINE_RULE,
    BASELINE_STATIC,
    EvaluationHarness,
    ScenarioEvaluationResult,
    SystemConfiguration,
)
from backend.evaluation.metrics import (
    compute_comparative_metrics,
    compute_scenario_metrics,
)
from backend.evaluation.plots import generate_evaluation_plots
from backend.evaluation.scenarios import EVAL_SCENARIOS, get_scenario

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("Phase13Runner")

OUTPUT_DIR = Path("data/evaluation")
PLOTS_DIR = OUTPUT_DIR / "plots"


class EvaluationRunner:
    """Master orchestrator for Phase 13 research evaluation."""

    def __init__(self, output_dir: Path = OUTPUT_DIR) -> None:
        self.output_dir = output_dir
        self.plots_dir = output_dir / "plots"
        self.harness = EvaluationHarness()

    def run_all(self) -> dict[str, Any]:
        """Execute complete evaluation suite, export data, and generate plots."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.plots_dir.mkdir(parents=True, exist_ok=True)

        start_time = time.perf_counter()
        logger.info("Starting Phase 13 Research Evaluation Suite...")

        scenarios = [get_scenario(scn_id) for scn_id in EVAL_SCENARIOS.keys()]

        # 1. Run Baseline Evaluations across all 12 scenarios
        static_results: list[ScenarioEvaluationResult] = []
        rule_results: list[ScenarioEvaluationResult] = []
        ai_results: list[ScenarioEvaluationResult] = []

        scenario_json_dict: dict[str, Any] = {}
        all_step_csv_rows: list[dict[str, Any]] = []

        for scn in scenarios:
            logger.info("Executing Scenario %s across all 3 baselines...", scn.scenario_id)

            res_static = self.harness.run_scenario(scn, BASELINE_STATIC)
            res_rule = self.harness.run_scenario(scn, BASELINE_RULE)
            res_ai = self.harness.run_scenario(scn, AI_ADAPTIVE)

            static_results.append(res_static)
            rule_results.append(res_rule)
            ai_results.append(res_ai)

            # Scenario metrics for AI_ADAPTIVE
            comp_metrics = compute_scenario_metrics(
                res_ai,
                scn,
                static_baseline_energy=res_static.total_energy_uj,
                static_baseline_cpu_time=sum(s.measured_total_latency_ms for s in res_static.timeline),
            )

            scenario_json_dict[scn.scenario_id] = {
                "scenario_metadata": scn.to_dict(),
                "metrics": comp_metrics.to_dict(),
                "static_baseline": res_static.to_dict(),
                "rule_baseline": res_rule.to_dict(),
                "ai_adaptive": res_ai.to_dict(),
            }

            # Flatten timeline for CSV
            for s in res_ai.timeline:
                row = s.to_dict()
                row["scenario_id"] = scn.scenario_id
                row["scenario_name"] = scn.name
                all_step_csv_rows.append(row)

        # 2. Export scenario results
        scn_json_path = self.output_dir / "scenario_results.json"
        with open(scn_json_path, "w", encoding="utf-8") as f:
            json.dump(scenario_json_dict, f, indent=2)
        logger.info("Exported %s", scn_json_path)

        scn_csv_path = self.output_dir / "scenario_results.csv"
        if all_step_csv_rows:
            with open(scn_csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=list(all_step_csv_rows[0].keys()))
                writer.writeheader()
                writer.writerows(all_step_csv_rows)
        logger.info("Exported %s (%d rows)", scn_csv_path, len(all_step_csv_rows))

        # 3. Comparative Baseline Evaluation
        logger.info("Computing 3-Way Baseline Comparison...")
        comparative_summary = compute_comparative_metrics(static_results, rule_results, ai_results)

        comp_json_path = self.output_dir / "baseline_comparison.json"
        with open(comp_json_path, "w", encoding="utf-8") as f:
            json.dump(comparative_summary, f, indent=2)
        logger.info("Exported %s", comp_json_path)

        comp_csv_path = self.output_dir / "baseline_comparison.csv"
        if "comparisons" in comparative_summary and comparative_summary["comparisons"]:
            with open(comp_csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=list(comparative_summary["comparisons"][0].keys()))
                writer.writeheader()
                writer.writerows(comparative_summary["comparisons"])
        logger.info("Exported %s", comp_csv_path)

        # 4. Ablation Study
        logger.info("Running 5-Way Ablation Study...")
        ablation_summary = run_ablation_study()
        safety_ablation_summary = run_safety_ablation()

        ab_json_path = self.output_dir / "ablation_results.json"
        with open(ab_json_path, "w", encoding="utf-8") as f:
            json.dump({
                "ablation_configurations": ablation_summary,
                "safety_ablation": safety_ablation_summary,
            }, f, indent=2)
        logger.info("Exported %s", ab_json_path)

        ab_csv_path = self.output_dir / "ablation_results.csv"
        if ablation_summary:
            with open(ab_csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=list(ablation_summary[0].keys()))
                writer.writeheader()
                writer.writerows(ablation_summary)
        logger.info("Exported %s", ab_csv_path)

        # 5. Transition Results
        trans_dict = {
            "total_transitions_ai_adaptive": sum(r.total_transitions for r in ai_results),
            "total_transitions_rule_based": sum(r.total_transitions for r in rule_results),
            "total_transitions_static": sum(r.total_transitions for r in static_results),
            "scenario_transitions": [
                {
                    "scenario_id": r.scenario_id,
                    "ai_adaptive_transitions": r.total_transitions,
                    "rule_based_transitions": rule_results[i].total_transitions,
                    "downgrades_held": r.downgrades_held_count,
                    "downgrades_executed": r.downgrades_executed_count,
                }
                for i, r in enumerate(ai_results)
            ]
        }
        trans_json_path = self.output_dir / "transition_results.json"
        with open(trans_json_path, "w", encoding="utf-8") as f:
            json.dump(trans_dict, f, indent=2)
        logger.info("Exported %s", trans_json_path)

        # 6. Automated Plots
        logger.info("Generating Research Plots in %s...", self.plots_dir)
        plots_generated = generate_evaluation_plots(
            comparisons=comparative_summary["comparisons"],
            ablation_results=ablation_summary,
            scenario_results=scenario_json_dict,
            output_dir=self.plots_dir,
        )
        logger.info("Generated %d plots.", len(plots_generated))

        elapsed_sec = time.perf_counter() - start_time
        logger.info("Phase 13 Evaluation completed in %.2f seconds.", elapsed_sec)

        return {
            "status": "SUCCESS",
            "execution_duration_sec": round(elapsed_sec, 2),
            "total_scenarios": len(scenarios),
            "total_steps": len(all_step_csv_rows),
            "artifacts_generated": [
                str(scn_json_path),
                str(scn_csv_path),
                str(comp_json_path),
                str(comp_csv_path),
                str(ab_json_path),
                str(ab_csv_path),
                str(trans_json_path),
            ] + plots_generated,
            "comparative_summary": comparative_summary,
            "ablation_summary": ablation_summary,
            "safety_ablation_summary": safety_ablation_summary,
        }


def run_full_evaluation() -> dict[str, Any]:
    """Helper function to execute the evaluation runner."""
    runner = EvaluationRunner()
    return runner.run_all()


if __name__ == "__main__":
    run_full_evaluation()

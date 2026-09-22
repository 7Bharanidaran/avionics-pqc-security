"""Comprehensive Metrics Evaluation Suite for Phase 13.

Calculates:
1. Security Metrics (Violations, Downgrade Blocks, Safety Overrides)
2. Adaptation Metrics (Transitions, Dwell Time, Anti-Oscillation, Latency to Respond)
3. Performance Metrics (Handshake, Encap, Sign, Total Latency, Energy Conservation)
4. AI Metrics (Accuracy, Precision, Recall, Macro F1, MAE, RMSE, R2, Confidence)
"""

from __future__ import annotations

import math
import statistics
from dataclasses import asdict, dataclass, field
from typing import Any

from backend.evaluation.baselines import ScenarioEvaluationResult
from backend.evaluation.scenarios import EvalScenario


@dataclass
class SecurityMetrics:
    """Security and safety invariant metrics."""

    total_steps: int
    safety_violations: int
    safety_violation_rate_pct: float
    downgrade_attempts: int
    downgrades_blocked: int
    downgrade_block_success_rate_pct: float
    safety_overrides_triggered: int
    authentication_failures: int
    replay_rejections: int
    invalid_messages_rejected: int
    mean_security_margin_bits: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AdaptationMetrics:
    """Dynamic agility, stability, and anti-oscillation metrics."""

    total_transitions: int
    escalations_count: int
    downgrades_held_count: int
    downgrades_executed_count: int
    time_spent_in_constructions_pct: dict[str, float]
    transition_rate_per_step: float
    unnecessary_transitions_count: int
    anti_oscillation_damping_efficiency_pct: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PerformanceMetrics:
    """Timing, computational latency, and energy metrics."""

    total_execution_time_ms: float
    mean_step_latency_ms: float
    p95_step_latency_ms: float
    min_step_latency_ms: float
    max_step_latency_ms: float
    mean_ai_inference_time_ms: float
    mean_policy_decision_time_ms: float
    mean_handshake_latency_ms: float
    total_energy_uj: float
    energy_savings_pct_vs_static: float
    cpu_savings_pct_vs_static: float
    deadline_violations: int
    deadline_compliance_rate_pct: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AIMetrics:
    """Statistical predictive accuracy and confidence metrics."""

    has_ground_truth: bool
    accuracy: float
    macro_precision: float
    macro_recall: float
    macro_f1: float
    threat_score_mae: float
    threat_score_rmse: float
    threat_score_r2: float
    mean_confidence: float
    low_confidence_step_count: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ComprehensiveMetrics:
    """Unified metrics bundle for a scenario or comparative evaluation."""

    scenario_id: str
    scenario_name: str
    system_config: str
    security: SecurityMetrics
    adaptation: AdaptationMetrics
    performance: PerformanceMetrics
    ai: AIMetrics

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "system_config": self.system_config,
            "security": self.security.to_dict(),
            "adaptation": self.adaptation.to_dict(),
            "performance": self.performance.to_dict(),
            "ai": self.ai.to_dict(),
        }


def compute_scenario_metrics(
    result: ScenarioEvaluationResult,
    scenario: EvalScenario,
    static_baseline_energy: float | None = None,
    static_baseline_cpu_time: float | None = None,
) -> ComprehensiveMetrics:
    """Compute detailed multidimensional metrics for an executed scenario result."""
    total_steps = len(result.timeline)

    # 1. Security Metrics
    sec_violations = result.security_violations
    sec_violation_rate = (sec_violations / total_steps * 100.0) if total_steps > 0 else 0.0

    # Count downgrade attempts (where telemetry indicates lower threat than required)
    downgrade_attempts = sum(1 for step in scenario.steps if step.is_attack_step or step.criticality in ("CRITICAL", "SAFETY_CRITICAL"))
    downgrades_blocked = result.downgrades_blocked_count
    block_rate = (downgrades_blocked / max(1, downgrade_attempts) * 100.0) if downgrade_attempts > 0 else 100.0

    auth_fails = sum(step.telemetry.auth_failure_count for step in scenario.steps)
    replays = sum(step.telemetry.replay_attempt_count for step in scenario.steps)
    integ_fails = sum(step.telemetry.integrity_failure_count for step in scenario.steps)

    sec_margins = [s.security_margin_bits for s in result.timeline]
    mean_sec_margin = statistics.mean(sec_margins) if sec_margins else 128.0

    sec_metrics = SecurityMetrics(
        total_steps=total_steps,
        safety_violations=sec_violations,
        safety_violation_rate_pct=round(sec_violation_rate, 2),
        downgrade_attempts=downgrade_attempts,
        downgrades_blocked=downgrades_blocked,
        downgrade_block_success_rate_pct=round(min(100.0, block_rate), 2),
        safety_overrides_triggered=result.safety_overrides_count,
        authentication_failures=auth_fails,
        replay_rejections=replays,
        invalid_messages_rejected=integ_fails,
        mean_security_margin_bits=round(mean_sec_margin, 1),
    )

    # 2. Adaptation Metrics
    dist_pct: dict[str, float] = {}
    for prof, cnt in result.construction_distribution.items():
        dist_pct[prof] = round((cnt / total_steps * 100.0), 2) if total_steps > 0 else 0.0

    trans_rate = (result.total_transitions / total_steps) if total_steps > 0 else 0.0

    # Unnecessary transitions: transitions during nominal steps with no threat change
    unnecessary = 0
    for i in range(1, len(result.timeline)):
        s_prev = result.timeline[i - 1]
        s_curr = result.timeline[i]
        if not scenario.steps[i].is_attack_step and not scenario.steps[i - 1].is_attack_step:
            if s_curr.selected_construction != s_prev.selected_construction:
                unnecessary += 1

    # Damping efficiency: how many downgrades were held vs executed
    held = result.downgrades_held_count
    exec_down = result.downgrades_executed_count
    damping_eff = (held / max(1, held + exec_down) * 100.0) if (held + exec_down) > 0 else 100.0

    adapt_metrics = AdaptationMetrics(
        total_transitions=result.total_transitions,
        escalations_count=result.escalations_count,
        downgrades_held_count=result.downgrades_held_count,
        downgrades_executed_count=result.downgrades_executed_count,
        time_spent_in_constructions_pct=dist_pct,
        transition_rate_per_step=round(trans_rate, 4),
        unnecessary_transitions_count=unnecessary,
        anti_oscillation_damping_efficiency_pct=round(damping_eff, 2),
    )

    # 3. Performance Metrics
    latencies = [s.measured_total_latency_ms for s in result.timeline]
    mean_lat = statistics.mean(latencies) if latencies else 0.0
    sorted_lat = sorted(latencies)
    p95_idx = min(len(sorted_lat) - 1, int(len(sorted_lat) * 0.95))
    p95_lat = sorted_lat[p95_idx] if sorted_lat else 0.0
    min_lat = min(latencies) if latencies else 0.0
    max_lat = max(latencies) if latencies else 0.0

    ai_inf_times = [s.ai_inference_time_ms for s in result.timeline if s.ai_inference_time_ms > 0]
    mean_ai_inf = statistics.mean(ai_inf_times) if ai_inf_times else 0.0

    policy_times = [s.policy_decision_time_ms for s in result.timeline]
    mean_pol = statistics.mean(policy_times) if policy_times else 0.0

    handshake_times = [s.measured_handshake_latency_ms for s in result.timeline]
    mean_hs = statistics.mean(handshake_times) if handshake_times else 0.0

    base_energy = static_baseline_energy or result.total_energy_uj
    energy_savings = max(0.0, 100.0 * (1.0 - result.total_energy_uj / max(1e-4, base_energy)))

    base_cpu = static_baseline_cpu_time or sum(latencies)
    cpu_savings = max(0.0, 100.0 * (1.0 - sum(latencies) / max(1e-4, base_cpu)))

    deadline_compliance = ((total_steps - result.deadline_violations) / max(1, total_steps) * 100.0)

    perf_metrics = PerformanceMetrics(
        total_execution_time_ms=result.total_execution_time_ms,
        mean_step_latency_ms=round(mean_lat, 4),
        p95_step_latency_ms=round(p95_lat, 4),
        min_step_latency_ms=round(min_lat, 4),
        max_step_latency_ms=round(max_lat, 4),
        mean_ai_inference_time_ms=round(mean_ai_inf, 4),
        mean_policy_decision_time_ms=round(mean_pol, 4),
        mean_handshake_latency_ms=round(mean_hs, 4),
        total_energy_uj=round(result.total_energy_uj, 2),
        energy_savings_pct_vs_static=round(energy_savings, 2),
        cpu_savings_pct_vs_static=round(cpu_savings, 2),
        deadline_violations=result.deadline_violations,
        deadline_compliance_rate_pct=round(deadline_compliance, 2),
    )

    # 4. AI Metrics
    ai_steps = [s for s in result.timeline if s.ai_threat_level is not None]
    if ai_steps:
        y_true_cls = [step.ground_truth_threat_level for step in scenario.steps]
        y_pred_cls = [s.ai_threat_level for s in ai_steps]
        y_true_reg = [step.ground_truth_threat_score for step in scenario.steps]
        y_pred_reg = [s.ai_threat_score or 0.0 for s in ai_steps]

        # Classification metrics
        classes = ["NORMAL", "ELEVATED", "HIGH", "CRITICAL"]
        correct = sum(1 for yt, yp in zip(y_true_cls, y_pred_cls) if yt == yp)
        acc = correct / len(y_true_cls) if y_true_cls else 0.0

        precisions = []
        recalls = []
        f1s = []
        for c in classes:
            tp = sum(1 for yt, yp in zip(y_true_cls, y_pred_cls) if yt == c and yp == c)
            fp = sum(1 for yt, yp in zip(y_true_cls, y_pred_cls) if yt != c and yp == c)
            fn = sum(1 for yt, yp in zip(y_true_cls, y_pred_cls) if yt == c and yp != c)
            prec = tp / (tp + fp) if (tp + fp) > 0 else 1.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 1.0
            f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
            precisions.append(prec)
            recalls.append(rec)
            f1s.append(f1)

        macro_p = statistics.mean(precisions)
        macro_r = statistics.mean(recalls)
        macro_f1 = statistics.mean(f1s)

        # Regression metrics
        mae = statistics.mean(abs(yt - yp) for yt, yp in zip(y_true_reg, y_pred_reg))
        rmse = math.sqrt(statistics.mean((yt - yp) ** 2 for yt, yp in zip(y_true_reg, y_pred_reg)))

        mean_yt = statistics.mean(y_true_reg)
        ss_tot = sum((yt - mean_yt) ** 2 for yt in y_true_reg)
        ss_res = sum((yt - yp) ** 2 for yt, yp in zip(y_true_reg, y_pred_reg))
        r2 = 1.0 - (ss_res / max(1e-6, ss_tot)) if ss_tot > 0 else 1.0

        confs = [s.ai_confidence for s in ai_steps if s.ai_confidence is not None]
        mean_conf = statistics.mean(confs) if confs else 0.0
        low_conf_cnt = sum(1 for c in confs if c < 0.50)

        ai_metrics = AIMetrics(
            has_ground_truth=True,
            accuracy=round(acc, 4),
            macro_precision=round(macro_p, 4),
            macro_recall=round(macro_r, 4),
            macro_f1=round(macro_f1, 4),
            threat_score_mae=round(mae, 4),
            threat_score_rmse=round(rmse, 4),
            threat_score_r2=round(max(0.0, r2), 4),
            mean_confidence=round(mean_conf, 4),
            low_confidence_step_count=low_conf_cnt,
        )
    else:
        ai_metrics = AIMetrics(
            has_ground_truth=False,
            accuracy=0.0,
            macro_precision=0.0,
            macro_recall=0.0,
            macro_f1=0.0,
            threat_score_mae=0.0,
            threat_score_rmse=0.0,
            threat_score_r2=0.0,
            mean_confidence=0.0,
            low_confidence_step_count=0,
        )

    return ComprehensiveMetrics(
        scenario_id=scenario.scenario_id,
        scenario_name=scenario.name,
        system_config=result.system_config,
        security=sec_metrics,
        adaptation=adapt_metrics,
        performance=perf_metrics,
        ai=ai_metrics,
    )


def compute_comparative_metrics(
    static_results: list[ScenarioEvaluationResult],
    rule_results: list[ScenarioEvaluationResult],
    ai_results: list[ScenarioEvaluationResult],
) -> dict[str, Any]:
    """Aggregate comparative summary across all 12 scenarios for the 3 system configurations."""
    configs = [
        ("BASELINE_STATIC", "Mode A: Static Heavy Post-Quantum Baseline (Fixed ADAPTIVE-CRITICAL)", static_results),
        ("BASELINE_RULE", "Mode B: Deterministic Rule-Based Adaptive Policy (Phase 9B Instantaneous)", rule_results),
        ("AI_ADAPTIVE", "Mode C: Closed-Loop AI-Assisted Adaptive Intelligence with Safety Constraints", ai_results),
    ]

    static_energy = sum(sum(s.energy_cost_uj for s in res.timeline) for res in static_results)
    static_cpu = sum(sum(s.measured_total_latency_ms for s in res.timeline) for res in static_results)

    comparisons = []
    for cfg_id, desc, res_list in configs:
        all_steps = [s for r in res_list for s in r.timeline]
        total_energy = sum(s.energy_cost_uj for s in all_steps)
        total_cpu = sum(s.measured_total_latency_ms for s in all_steps)
        latencies = [s.measured_total_latency_ms for s in all_steps]
        mean_lat = statistics.mean(latencies) if latencies else 0.0
        sorted_lat = sorted(latencies)
        p95_lat = sorted_lat[min(len(sorted_lat) - 1, int(len(sorted_lat) * 0.95))] if sorted_lat else 0.0

        total_transitions = sum(r.total_transitions for r in res_list)
        total_safety_overrides = sum(r.safety_overrides_count for r in res_list)
        total_downgrades_blocked = sum(r.downgrades_blocked_count for r in res_list)
        total_sec_violations = sum(r.security_violations for r in res_list)
        total_deadline_violations = sum(r.deadline_violations for r in res_list)

        energy_sav = max(0.0, 100.0 * (1.0 - total_energy / max(1e-4, static_energy)))
        cpu_sav = max(0.0, 100.0 * (1.0 - total_cpu / max(1e-4, static_cpu)))

        comparisons.append({
            "config_id": cfg_id,
            "description": desc,
            "total_scenarios": len(res_list),
            "total_steps": len(all_steps),
            "total_cpu_time_ms": round(total_cpu, 2),
            "mean_latency_ms": round(mean_lat, 4),
            "p95_latency_ms": round(p95_lat, 4),
            "total_energy_uj": round(total_energy, 2),
            "energy_savings_pct_vs_static": round(energy_sav, 2),
            "cpu_savings_pct_vs_static": round(cpu_sav, 2),
            "total_transitions": total_transitions,
            "safety_overrides_count": total_safety_overrides,
            "downgrades_blocked_count": total_downgrades_blocked,
            "security_violations": total_sec_violations,
            "deadline_violations": total_deadline_violations,
            "security_coverage_pct": 100.0 if total_sec_violations == 0 else max(0.0, 100.0 - (total_sec_violations / len(all_steps) * 100.0)),
        })

    return {
        "status": "SUCCESS",
        "total_scenarios_evaluated": len(static_results),
        "total_steps_evaluated": sum(len(r.timeline) for r in ai_results),
        "comparisons": comparisons,
    }

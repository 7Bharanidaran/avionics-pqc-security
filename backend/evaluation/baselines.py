"""System Configurations and Evaluation Harness for Phase 13.

Defines:
1. BASELINE_STATIC: Fixed Heavy Post-Quantum Baseline (ADAPTIVE-CRITICAL-V1)
2. BASELINE_RULE: Deterministic Rule-Based Adaptive Policy (Phase 9B Instantaneous)
3. AI_ADAPTIVE: Closed-Loop AI-Assisted Adaptive Intelligence with Hysteresis & Safety Constraints
"""

from __future__ import annotations

import enum
import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from backend.ai.anomaly import AnomalyDetectionResult, AnomalyDetector
from backend.ai.forecasting import TemporalThreatForecaster, ThreatForecastResult
from backend.ai.predictor import ThreatPredictor
from backend.ai.schemas import ThreatPredictionResult
from backend.crypto.construction_engine import (
    CRITICALITY_HIERARCHY,
    ConstructionDecision,
    ConstructionEngine,
)
from backend.evaluation.scenarios import EvalScenario, EvalStepInput

logger = logging.getLogger("EvaluationBaselines")


class SystemConfiguration(str, enum.Enum):
    BASELINE_STATIC = "BASELINE_STATIC"
    BASELINE_RULE = "BASELINE_RULE"
    AI_ADAPTIVE = "AI_ADAPTIVE"


# Construction properties mapping
ENERGY_COST_MAP_UJ = {
    "ADAPTIVE-STANDARD-V1": 120.0,
    "ADAPTIVE-BALANCED-V1": 310.0,
    "ADAPTIVE-HIGH-ASSURANCE-V1": 890.0,
    "ADAPTIVE-CRITICAL-V1": 1450.0,
}

SECURITY_MARGIN_BITS_MAP = {
    "ADAPTIVE-STANDARD-V1": 128,
    "ADAPTIVE-BALANCED-V1": 192,
    "ADAPTIVE-HIGH-ASSURANCE-V1": 256,
    "ADAPTIVE-CRITICAL-V1": 256,
}

PROFILE_RANK = {
    "ADAPTIVE-STANDARD-V1": 1,
    "ADAPTIVE-BALANCED-V1": 2,
    "ADAPTIVE-HIGH-ASSURANCE-V1": 3,
    "ADAPTIVE-CRITICAL-V1": 4,
}


@dataclass
class EvalStepExecutionResult:
    """Detailed execution result for one step of a scenario."""

    step_index: int
    timestamp_sec: float
    flight_phase: str
    message_type: str
    criticality: str
    latency_budget_ms: float
    system_config: str

    # AI & Anomaly signals (if applicable)
    ai_threat_level: str | None
    ai_threat_score: float | None
    ai_confidence: float | None
    is_anomaly: bool
    anomaly_score: float | None
    forecast_trend: str | None
    preemptive_flag: bool

    # Construction Decision
    previous_construction: str
    selected_construction: str
    transition_type: str  # INITIAL, STABLE, ESCALATION, DOWNGRADE_HELD, DOWNGRADE_EXECUTED
    dwell_counter: int
    safety_override_triggered: bool
    downgrade_blocked: bool
    explainable_reason: str

    # Performance Timings (ms)
    ai_inference_time_ms: float
    policy_decision_time_ms: float
    measured_handshake_latency_ms: float
    measured_encap_latency_ms: float
    measured_sign_latency_ms: float
    measured_total_latency_ms: float

    # Resource & Security Metrics
    energy_cost_uj: float
    security_margin_bits: int
    deadline_met: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScenarioEvaluationResult:
    """Aggregated evaluation results for a scenario under a specific system configuration."""

    scenario_id: str
    scenario_name: str
    category: str
    system_config: str
    total_steps: int
    total_execution_time_ms: float
    mean_latency_ms: float
    p95_latency_ms: float
    total_energy_uj: float
    total_transitions: int
    escalations_count: int
    downgrades_held_count: int
    downgrades_executed_count: int
    safety_overrides_count: int
    downgrades_blocked_count: int
    deadline_violations: int
    security_violations: int
    construction_distribution: dict[str, int] = field(default_factory=dict)
    timeline: list[EvalStepExecutionResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EvaluationHarness:
    """Standardized execution harness for running scenarios against any system configuration."""

    def __init__(self) -> None:
        self.construction_engine = ConstructionEngine()
        self.threat_predictor = ThreatPredictor()
        self.anomaly_detector = AnomalyDetector()
        self.forecaster = TemporalThreatForecaster()

    def run_scenario(
        self,
        scenario: EvalScenario,
        config: SystemConfiguration,
        dwell_k: int = 3,
    ) -> ScenarioEvaluationResult:
        """Execute a full scenario under the specified system configuration."""
        timeline: list[EvalStepExecutionResult] = []
        recent_threat_scores: list[float] = []

        active_construction = "ADAPTIVE-CRITICAL-V1" if config == SystemConfiguration.BASELINE_STATIC else "ADAPTIVE-STANDARD-V1"
        pending_downgrade: str | None = None
        dwell_counter = 0

        total_exec_start = time.perf_counter()

        for step in scenario.steps:
            step_res = self._execute_step(
                step=step,
                config=config,
                active_construction=active_construction,
                pending_downgrade=pending_downgrade,
                dwell_counter=dwell_counter,
                dwell_k=dwell_k,
                recent_threat_scores=recent_threat_scores,
            )

            # Update state machine for next step
            active_construction = step_res.selected_construction
            dwell_counter = step_res.dwell_counter
            if step_res.ai_threat_score is not None:
                recent_threat_scores.append(step_res.ai_threat_score)
                if len(recent_threat_scores) > 20:
                    recent_threat_scores.pop(0)

            timeline.append(step_res)

        total_exec_ms = (time.perf_counter() - total_exec_start) * 1000.0

        # Calculate aggregations
        latencies = [s.measured_total_latency_ms for s in timeline]
        mean_lat = sum(latencies) / len(latencies) if latencies else 0.0
        sorted_lat = sorted(latencies)
        p95_idx = min(len(sorted_lat) - 1, int(len(sorted_lat) * 0.95))
        p95_lat = sorted_lat[p95_idx] if sorted_lat else 0.0

        total_energy = sum(s.energy_cost_uj for s in timeline)
        transitions = sum(1 for s in timeline if s.transition_type in ("INITIAL", "ESCALATION", "DOWNGRADE_EXECUTED"))
        escalations = sum(1 for s in timeline if s.transition_type == "ESCALATION")
        downgrades_held = sum(1 for s in timeline if s.transition_type == "DOWNGRADE_HELD")
        downgrades_exec = sum(1 for s in timeline if s.transition_type == "DOWNGRADE_EXECUTED")
        safety_overrides = sum(1 for s in timeline if s.safety_override_triggered)
        downgrades_blocked = sum(1 for s in timeline if s.downgrade_blocked)
        deadline_viols = sum(1 for s in timeline if not s.deadline_met)

        # Security violations: any case where required security was less than message criticality
        sec_violations = 0
        for s in timeline:
            req_rank = CRITICALITY_HIERARCHY.get(s.criticality, 1)
            prof_rank = PROFILE_RANK.get(s.selected_construction, 1)
            # Critical / Safety critical require High Assurance (rank 3) or Critical (rank 4)
            if req_rank >= 3 and prof_rank < 3:
                sec_violations += 1

        dist: dict[str, int] = {}
        for s in timeline:
            dist[s.selected_construction] = dist.get(s.selected_construction, 0) + 1

        return ScenarioEvaluationResult(
            scenario_id=scenario.scenario_id,
            scenario_name=scenario.name,
            category=scenario.category,
            system_config=config.value,
            total_steps=len(scenario.steps),
            total_execution_time_ms=round(total_exec_ms, 2),
            mean_latency_ms=round(mean_lat, 4),
            p95_latency_ms=round(p95_lat, 4),
            total_energy_uj=round(total_energy, 2),
            total_transitions=transitions,
            escalations_count=escalations,
            downgrades_held_count=downgrades_held,
            downgrades_executed_count=downgrades_exec,
            safety_overrides_count=safety_overrides,
            downgrades_blocked_count=downgrades_blocked,
            deadline_violations=deadline_viols,
            security_violations=sec_violations,
            construction_distribution=dist,
            timeline=timeline,
        )

    def _execute_step(
        self,
        step: EvalStepInput,
        config: SystemConfiguration,
        active_construction: str,
        pending_downgrade: str | None,
        dwell_counter: int,
        dwell_k: int,
        recent_threat_scores: list[float],
    ) -> EvalStepExecutionResult:
        """Execute a single step under the selected system configuration."""
        ai_inf_start = time.perf_counter_ns()
        ai_pred: ThreatPredictionResult | None = None
        anomaly_res: AnomalyDetectionResult | None = None
        forecast_res: ThreatForecastResult | None = None

        if config == SystemConfiguration.AI_ADAPTIVE:
            ai_pred = self.threat_predictor.predict(step.telemetry)
            anomaly_res = self.anomaly_detector.detect(step.telemetry)
            hist = recent_threat_scores + [ai_pred.threat_score]
            forecast_res = self.forecaster.forecast_from_scores(hist)
        ai_inf_ms = (time.perf_counter_ns() - ai_inf_start) / 1e6

        policy_start = time.perf_counter_ns()
        downgrade_blocked = False
        safety_override = False
        reason = ""
        target_construction: str

        if config == SystemConfiguration.BASELINE_STATIC:
            # Fixed high-security baseline
            target_construction = "ADAPTIVE-CRITICAL-V1"
            reason = "Mode A: Fixed static high-assurance baseline."

        elif config == SystemConfiguration.BASELINE_RULE:
            # Deterministic Phase 9B rule engine without AI
            # Threat determined solely by raw telemetry counters
            t_cnt = (
                step.telemetry.replay_attempt_count
                + step.telemetry.auth_failure_count
                + step.telemetry.integrity_failure_count
                + step.telemetry.aad_tamper_count * 2
            )
            raw_threat_level = "CRITICAL" if t_cnt >= 10 else ("HIGH" if t_cnt >= 5 else ("ELEVATED" if t_cnt >= 2 else "NORMAL"))
            raw_threat_score = min(100.0, t_cnt * 10.0)

            decision = self.construction_engine.select_construction(
                criticality=step.criticality,
                threat_level=raw_threat_level,
                threat_score=raw_threat_score,
                latency_budget_ms=step.latency_budget_ms,
            )
            target_construction = decision.selected_construction_id or "ADAPTIVE-CRITICAL-V1"
            downgrade_blocked = decision.downgrade_blocked
            reason = f"Mode B: Deterministic rule selection: {target_construction}."

        else:
            # AI_ADAPTIVE: AI + Confidence + Anomaly + Safety Constraints + Hysteresis
            assert ai_pred is not None and anomaly_res is not None

            # Anomaly risk boost
            eff_threat_score = ai_pred.threat_score
            if anomaly_res.is_anomaly and anomaly_res.anomaly_score > 60.0:
                eff_threat_score = min(100.0, eff_threat_score + 15.0)

            # Low-confidence fallback
            eff_threat_level = ai_pred.threat_level
            if ai_pred.confidence < 0.50:
                # Escalate threat level on low confidence
                current_rank = PROFILE_RANK.get(eff_threat_level, 1)
                eff_threat_level = "HIGH" if current_rank <= 2 else "CRITICAL"
                safety_override = True

            decision = self.construction_engine.select_construction(
                criticality=step.criticality,
                threat_level=eff_threat_level,
                threat_score=eff_threat_score,
                latency_budget_ms=step.latency_budget_ms,
            )
            target_construction = decision.selected_construction_id or "ADAPTIVE-CRITICAL-V1"
            downgrade_blocked = decision.downgrade_blocked

            # Check if safety policy overrode low AI recommendation
            ai_req_rank = PROFILE_RANK.get(ai_pred.threat_level, 1)
            final_rank = PROFILE_RANK.get(target_construction, 1)
            crit_rank = CRITICALITY_HIERARCHY.get(step.criticality, 1)
            if crit_rank >= 3 and ai_req_rank < 3 and final_rank >= 3:
                safety_override = True
                downgrade_blocked = True

            reason = f"Mode C: {decision.reason}"

        policy_ms = (time.perf_counter_ns() - policy_start) / 1e6

        # Hysteresis Controller
        prev_profile = active_construction
        transition_type = "STABLE"
        selected_construction = active_construction

        if step.step_index == 1:
            transition_type = "INITIAL"
            selected_construction = target_construction
            dwell_counter = 0
        else:
            prev_rank = PROFILE_RANK.get(prev_profile, 1)
            target_rank = PROFILE_RANK.get(target_construction, 1)

            if config == SystemConfiguration.BASELINE_RULE:
                # Instantaneous switching without hysteresis
                if target_rank > prev_rank:
                    transition_type = "ESCALATION"
                    selected_construction = target_construction
                elif target_rank < prev_rank:
                    transition_type = "DOWNGRADE_EXECUTED"
                    selected_construction = target_construction
                else:
                    transition_type = "STABLE"
                    selected_construction = prev_profile
                dwell_counter = 0

            elif config == SystemConfiguration.AI_ADAPTIVE:
                # Immediate escalation
                if target_rank > prev_rank:
                    transition_type = "ESCALATION"
                    selected_construction = target_construction
                    dwell_counter = 0
                elif target_rank < prev_rank:
                    # Downgrade requested: apply K-step dwell hold
                    if dwell_counter + 1 < dwell_k:
                        transition_type = "DOWNGRADE_HELD"
                        selected_construction = prev_profile
                        dwell_counter += 1
                        reason += f" [Hysteresis hold step {dwell_counter}/{dwell_k}]"
                    else:
                        transition_type = "DOWNGRADE_EXECUTED"
                        selected_construction = target_construction
                        dwell_counter = 0
                else:
                    transition_type = "STABLE"
                    selected_construction = prev_profile
                    dwell_counter = 0
            else:
                # Static
                selected_construction = target_construction
                transition_type = "STABLE"

        # Timing Simulation (calibrated to actual crypto benchmarks to ensure high evaluation throughput)
        is_transition = transition_type in ("INITIAL", "ESCALATION", "DOWNGRADE_EXECUTED")
        if selected_construction == "ADAPTIVE-STANDARD-V1":
            handshake_ms = 4.5 if is_transition else 0.0
            enc_ms = 0.045
            sign_ms = 0.035
        elif selected_construction == "ADAPTIVE-BALANCED-V1":
            handshake_ms = 8.2 if is_transition else 0.0
            enc_ms = 0.052
            sign_ms = 0.040
        elif selected_construction == "ADAPTIVE-HIGH-ASSURANCE-V1":
            handshake_ms = 62.0 if is_transition else 0.0
            enc_ms = 0.085
            sign_ms = 0.070
        else:  # ADAPTIVE-CRITICAL-V1
            handshake_ms = 520.0 if is_transition else 0.0
            enc_ms = 0.120
            sign_ms = 0.095

        total_ms = ai_inf_ms + policy_ms + handshake_ms + enc_ms + sign_ms
        deadline_met = total_ms <= step.latency_budget_ms
        energy_uj = ENERGY_COST_MAP_UJ.get(selected_construction, 200.0)
        sec_margin = SECURITY_MARGIN_BITS_MAP.get(selected_construction, 128)

        return EvalStepExecutionResult(
            step_index=step.step_index,
            timestamp_sec=step.timestamp_sec,
            flight_phase=step.flight_phase,
            message_type=step.message_type,
            criticality=step.criticality,
            latency_budget_ms=step.latency_budget_ms,
            system_config=config.value,
            ai_threat_level=ai_pred.threat_level if ai_pred else None,
            ai_threat_score=ai_pred.threat_score if ai_pred else None,
            ai_confidence=ai_pred.confidence if ai_pred else None,
            is_anomaly=anomaly_res.is_anomaly if anomaly_res else False,
            anomaly_score=anomaly_res.anomaly_score if anomaly_res else None,
            forecast_trend=forecast_res.trend_direction if forecast_res else None,
            preemptive_flag=forecast_res.preemptive_action_recommended if forecast_res else False,
            previous_construction=prev_profile,
            selected_construction=selected_construction,
            transition_type=transition_type,
            dwell_counter=dwell_counter,
            safety_override_triggered=safety_override,
            downgrade_blocked=downgrade_blocked,
            explainable_reason=reason,
            ai_inference_time_ms=round(ai_inf_ms, 4),
            policy_decision_time_ms=round(policy_ms, 4),
            measured_handshake_latency_ms=round(handshake_ms, 4),
            measured_encap_latency_ms=round(enc_ms, 4),
            measured_sign_latency_ms=round(sign_ms, 4),
            measured_total_latency_ms=round(total_ms, 4),
            energy_cost_uj=energy_uj,
            security_margin_bits=sec_margin,
            deadline_met=deadline_met,
        )


BASELINE_STATIC = SystemConfiguration.BASELINE_STATIC
BASELINE_RULE = SystemConfiguration.BASELINE_RULE
AI_ADAPTIVE = SystemConfiguration.AI_ADAPTIVE

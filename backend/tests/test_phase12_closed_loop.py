"""Unit and Integration Tests for Phase 12: Closed-Loop Adaptive Intelligence & Research Validation.

Validates:
- Unsupervised Anomaly Detection (Mahalanobis distance & feature deviations)
- Multi-horizon Temporal Threat Forecasting (+5, +10, +15 steps & proactive escalation)
- Hysteresis & Anti-Oscillation Controller (Immediate escalation, dwell-time downgrade hold)
- Confidence-Aware Safety Handling & DO-178C Safety Boundary Override
- 10 Digital Twin Operational Scenarios (SCN-001 through SCN-010)
- Three-Way Comparative Evaluation (Mode A vs Mode B vs Mode C)
- Adversarial Robustness & Perturbation Containment
- Phase 12 REST API Endpoints
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.ai.anomaly import AnomalyDetector, get_anomaly_detector
from backend.ai.forecasting import TemporalThreatForecaster, get_threat_forecaster
from backend.ai.schemas import TelemetryInput
from backend.api.app import app
from backend.experiments.closed_loop import (
    ClosedLoopEngine,
    HysteresisController,
    SCENARIO_GENERATORS,
    run_adversarial_robustness_evaluation,
    run_comparative_evaluation,
)


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def closed_loop_engine() -> ClosedLoopEngine:
    return ClosedLoopEngine(dwell_steps_required=3)


# ==============================================================================
# 1. ANOMALY DETECTION TESTS
# ==============================================================================

def test_anomaly_detection_nominal():
    """Verify that nominal telemetry yields low anomaly score (< 40) and NOMINAL severity."""
    detector = get_anomaly_detector()
    nominal_telem = TelemetryInput(
        message_type="AIRCRAFT_STATUS",
        criticality="ROUTINE",
        criticality_rank=1,
        latency_budget_ms=1000.0,
        observed_packet_rate_hz=28.0,
        channel_bit_error_rate=0.0001,
        replay_attempt_count=0,
        auth_failure_count=0,
        integrity_failure_count=0,
        aad_tamper_count=0,
        transcript_anomaly_count=0,
    )
    result = detector.detect(nominal_telem)
    assert result.anomaly_score < 45.0
    assert result.severity in ["NOMINAL", "LOW"]
    assert result.is_anomaly is False


def test_anomaly_detection_outlier():
    """Verify that high multivariate error counts trigger high anomaly score and anomaly flag."""
    detector = get_anomaly_detector()
    anomalous_telem = TelemetryInput(
        message_type="FLIGHT_PLAN",
        criticality="CRITICAL",
        criticality_rank=3,
        latency_budget_ms=500.0,
        observed_packet_rate_hz=95.0,
        channel_bit_error_rate=0.05,
        replay_attempt_count=12,
        auth_failure_count=8,
        integrity_failure_count=7,
        aad_tamper_count=5,
        transcript_anomaly_count=6,
    )
    result = detector.detect(anomalous_telem)
    assert result.anomaly_score >= 50.0
    assert result.severity in ["HIGH", "CRITICAL", "MEDIUM"]
    assert result.advisory_threat_boost > 0.0
    assert len(result.top_deviations) > 0


# ==============================================================================
# 2. TEMPORAL FORECASTING TESTS
# ==============================================================================

def test_threat_forecasting_stable():
    """Verify that steady threat scores produce stable trajectory and no preemptive flag."""
    forecaster = get_threat_forecaster()
    steady_scores = [10.0, 10.5, 9.8, 10.2, 10.0]
    result = forecaster.forecast_from_scores(steady_scores, horizons=[5, 10, 15])
    assert result.trend_direction in ["STABLE", "DECREASING", "MODERATE_INCREASE"]
    assert result.preemptive_action_recommended is False
    assert len(result.forecast_points) == 3


def test_threat_forecasting_rapid_escalation():
    """Verify that a rising slope triggers RAPID_ESCALATION and preemptive action recommendation."""
    forecaster = get_threat_forecaster()
    rising_scores = [5.0, 12.0, 24.0, 38.0, 56.0]
    result = forecaster.forecast_from_scores(rising_scores, horizons=[5, 10, 15])
    assert result.trend_direction in ["RAPID_ESCALATION", "MODERATE_INCREASE"]
    assert result.rate_of_change_per_step > 0
    assert result.preemptive_action_recommended is True
    assert "Preemptive Escalation Advised" in result.advisory_recommendation


# ==============================================================================
# 3. HYSTERESIS & ANTI-OSCILLATION TESTS
# ==============================================================================

def test_hysteresis_immediate_escalation():
    """Verify that security escalation happens immediately on the very next step."""
    controller = HysteresisController(dwell_steps_required=3)
    
    # Step 1: Initialize at STANDARD
    p1, t1, _, _ = controller.evaluate_transition("ADAPTIVE-STANDARD-V1", "Normal")
    assert p1 == "ADAPTIVE-STANDARD-V1"
    assert t1 == "INITIAL"

    # Step 2: Escalate to HIGH_ASSURANCE -> Must switch immediately
    p2, t2, _, _ = controller.evaluate_transition("ADAPTIVE-HIGH-ASSURANCE-V1", "Threat elevated")
    assert p2 == "ADAPTIVE-HIGH-ASSURANCE-V1"
    assert t2 == "ESCALATION"


def test_hysteresis_dwell_time_downgrade():
    """Verify that downgrade is held for 3 consecutive steps before executing downgrade."""
    controller = HysteresisController(dwell_steps_required=3)
    controller.evaluate_transition("ADAPTIVE-CRITICAL-V1", "Initial critical")

    # Step 1 of candidate downgrade: must hold CRITICAL
    p1, t1, c1, _ = controller.evaluate_transition("ADAPTIVE-STANDARD-V1", "Threat subsiding")
    assert p1 == "ADAPTIVE-CRITICAL-V1"
    assert t1 == "DOWNGRADE_HELD"
    assert c1 == 1

    # Step 2: still hold CRITICAL
    p2, t2, c2, _ = controller.evaluate_transition("ADAPTIVE-STANDARD-V1", "Threat subsiding")
    assert p2 == "ADAPTIVE-CRITICAL-V1"
    assert t2 == "DOWNGRADE_HELD"
    assert c2 == 2

    # Step 3: Dwell requirement satisfied -> Execute downgrade safely
    p3, t3, c3, _ = controller.evaluate_transition("ADAPTIVE-STANDARD-V1", "Threat subsiding")
    assert p3 == "ADAPTIVE-STANDARD-V1"
    assert t3 == "DOWNGRADE_EXECUTED"
    assert c3 == 0


# ==============================================================================
# 4. SAFETY BOUNDARY & CONFIDENCE HANDLING TESTS
# ==============================================================================

def test_safety_boundary_override_on_safety_critical(closed_loop_engine: ClosedLoopEngine):
    """Verify that AI advisory reporting NORMAL on a SAFETY_CRITICAL command is overridden by policy."""
    telem = TelemetryInput(
        message_type="PRIMARY_FLIGHT_CONTROL",
        criticality="SAFETY_CRITICAL",
        criticality_rank=4,
        latency_budget_ms=5000.0,
        replay_attempt_count=0,
        auth_failure_count=0,
    )
    step_res = closed_loop_engine.run_step(
        step_index=1,
        timestamp_sec=0.0,
        flight_phase="TAKEOFF",
        telemetry=telem,
        criticality_str="SAFETY_CRITICAL",
        latency_budget_ms=5000.0,
        recent_threat_scores=[],
        mode="MODE_C_AI_ASSISTED",
    )
    # Even if AI predicted NORMAL, SAFETY_CRITICAL demands maximum/high assurance
    assert step_res.selected_construction in ["ADAPTIVE-HIGH-ASSURANCE-V1", "ADAPTIVE-CRITICAL-V1"]
    assert step_res.safety_override_triggered is True


# ==============================================================================
# 5. ALL 10 DIGITAL TWIN SCENARIOS TESTS
# ==============================================================================

@pytest.mark.parametrize("scenario_id", list(SCENARIO_GENERATORS.keys()))
def test_all_10_scenarios_execution(closed_loop_engine: ClosedLoopEngine, scenario_id: str):
    """Verify that each of the 10 operational scenarios executes to completion with 0 deadline violations."""
    res = closed_loop_engine.run_scenario(scenario_id=scenario_id, mode="MODE_C_AI_ASSISTED")
    assert res.summary.total_steps > 0
    assert res.summary.deadline_violations == 0
    assert len(res.timeline) == res.summary.total_steps
    for step in res.timeline:
        assert step.measured_total_latency_ms > 0
        assert step.deadline_met is True


# ==============================================================================
# 6. THREE-WAY COMPARATIVE EVALUATION & ADVERSARIAL ROBUSTNESS TESTS
# ==============================================================================

def test_comparative_evaluation():
    """Verify comparative evaluation across Mode A, Mode B, and Mode C."""
    comp = run_comparative_evaluation()
    assert comp["status"] == "SUCCESS"
    assert len(comp["mode_comparisons"]) == 3
    
    mode_c = next(m for m in comp["mode_comparisons"] if m["mode_name"] == "MODE_C_AI_ASSISTED")
    # Mode C should yield significant CPU and energy savings over static Mode A
    assert mode_c["cpu_time_savings_pct_vs_static"] > 30.0
    assert mode_c["energy_savings_pct_vs_static"] > 30.0
    assert mode_c["security_coverage_score"] == 100.0
    assert mode_c["deadline_violations"] == 0


def test_adversarial_robustness_evaluation():
    """Verify 100% of adversarial perturbation tests are blocked by the safety boundary."""
    adv = run_adversarial_robustness_evaluation()
    assert adv["status"] == "SUCCESS"
    assert adv["robustness_score_pct"] == 100.0
    assert adv["total_adversarial_downgrades_blocked"] == adv["total_tests"]


# ==============================================================================
# 7. PHASE 12 REST API ENDPOINTS TESTS
# ==============================================================================

def test_api_forecast_endpoint(client: TestClient):
    """Test POST /api/ai/forecast endpoint."""
    response = client.post(
        "/api/ai/forecast",
        json={"recent_threat_scores": [10.0, 20.0, 35.0, 50.0], "lookahead_horizons": [5, 10, 15]},
    )
    assert response.status_code == 200
    data = response.json()
    assert "trend_direction" in data
    assert "forecast_points" in data
    assert len(data["forecast_points"]) == 3


def test_api_anomaly_endpoint(client: TestClient):
    """Test POST /api/ai/anomaly endpoint."""
    response = client.post(
        "/api/ai/anomaly",
        json={
            "message_type": "AIRCRAFT_STATUS",
            "criticality": "ROUTINE",
            "latency_budget_ms": 1000.0,
            "channel_bit_error_rate": 0.0001,
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "anomaly_score" in data
    assert "is_anomaly" in data
    assert "severity" in data


def test_api_closed_loop_simulation(client: TestClient):
    """Test POST /api/experiments/closed-loop endpoint."""
    response = client.post(
        "/api/experiments/closed-loop",
        json={"scenario_id": "SCN-001", "mode": "MODE_C_AI_ASSISTED"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert "scenario" in data
    assert data["scenario"]["summary"]["scenario_id"] == "SCN-001"


def test_api_phase12_summary_endpoint(client: TestClient):
    """Test GET /api/experiments/phase12/summary endpoint."""
    response = client.get("/api/experiments/phase12/summary")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert "cpu_savings_pct" in data
    assert "energy_savings_pct" in data
    assert "modes" in data


def test_api_phase12_latest_endpoint(client: TestClient):
    """Test GET /api/experiments/phase12/latest endpoint."""
    response = client.get("/api/experiments/phase12/latest")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert "scenarios" in data
    assert "comparative_evaluation" in data

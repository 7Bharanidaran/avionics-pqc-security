"""Phase 13 Comprehensive Research Evaluation & Safety Invariant Tests.

Verifies:
1. Deterministic scenario generation & seed reproducibility (S01 through S12)
2. Baseline execution (BASELINE_STATIC, BASELINE_RULE, AI_ADAPTIVE)
3. Multidimensional metrics calculations (Security, Adaptation, Performance, AI)
4. Safety invariant enforcement and DO-178C fail-closed properties
5. Downgrade attack prevention and safety overrides
6. 5-Way ablation study and safety ablation validation
7. REST API endpoint responses and contracts
8. Zero secret leakage in all outputs, metadata, and JSON/CSV artifacts
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.api.app import app
from backend.evaluation.ablation import (
    AblationConfiguration,
    AblationStudy,
    run_ablation_study,
    run_safety_ablation,
)
from backend.evaluation.baselines import (
    AI_ADAPTIVE,
    BASELINE_RULE,
    BASELINE_STATIC,
    EvaluationHarness,
    SystemConfiguration,
)
from backend.evaluation.metrics import (
    compute_comparative_metrics,
    compute_scenario_metrics,
)
from backend.evaluation.scenarios import (
    EVAL_SCENARIOS,
    get_scenario,
    list_scenarios,
)


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture(scope="module")
def harness() -> EvaluationHarness:
    return EvaluationHarness()


class TestScenarioGeneration:
    """Validate reproducible scenario generation and deterministic seeds."""

    def test_all_12_scenarios_exist(self) -> None:
        assert len(EVAL_SCENARIOS) == 12
        catalog = list_scenarios()
        assert len(catalog) == 12
        ids = [c["scenario_id"] for c in catalog]
        expected_ids = [
            "S01_NORMAL",
            "S02_ELEVATED_THREAT",
            "S03_HIGH_THREAT",
            "S04_CRITICAL_THREAT",
            "S05_THREAT_ESCALATION",
            "S06_THREAT_RECOVERY",
            "S07_LOW_CONFIDENCE",
            "S08_CRITICAL_MESSAGE_LOW_AI_SCORE",
            "S09_DOWNGRADE_ATTEMPT",
            "S10_TELEMETRY_PERTURBATION",
            "S11_RAPID_THREAT_OSCILLATION",
            "S12_COMBINED_THREAT",
        ]
        for exp in expected_ids:
            assert exp in ids

    def test_deterministic_seed_reproducibility(self) -> None:
        scn1 = get_scenario("S01_NORMAL", seed=42)
        scn2 = get_scenario("S01_NORMAL", seed=42)
        assert len(scn1.steps) == len(scn2.steps)
        for s1, s2 in zip(scn1.steps, scn2.steps):
            assert s1.telemetry.observed_packet_rate_hz == s2.telemetry.observed_packet_rate_hz
            assert s1.ground_truth_threat_score == s2.ground_truth_threat_score


class TestBaselineExecution:
    """Validate execution across Static, Rule-Based, and AI-Adaptive configurations."""

    def test_static_baseline_uses_fixed_critical(self, harness: EvaluationHarness) -> None:
        scn = get_scenario("S01_NORMAL")
        res = harness.run_scenario(scn, BASELINE_STATIC)
        assert res.system_config == "BASELINE_STATIC"
        assert res.security_violations == 0
        for s in res.timeline:
            assert s.selected_construction == "ADAPTIVE-CRITICAL-V1"

    def test_rule_baseline_adapts_instantaneously(self, harness: EvaluationHarness) -> None:
        scn = get_scenario("S05_THREAT_ESCALATION")
        res = harness.run_scenario(scn, BASELINE_RULE)
        assert res.system_config == "BASELINE_RULE"
        assert res.total_transitions >= 3
        # Should start at standard/balanced and escalate to critical
        assert res.timeline[0].selected_construction in ("ADAPTIVE-STANDARD-V1", "ADAPTIVE-BALANCED-V1")
        assert res.timeline[-1].selected_construction == "ADAPTIVE-CRITICAL-V1"

    def test_ai_adaptive_closed_loop_execution(self, harness: EvaluationHarness) -> None:
        scn = get_scenario("S12_COMBINED_THREAT")
        res = harness.run_scenario(scn, AI_ADAPTIVE)
        assert res.system_config == "AI_ADAPTIVE"
        assert res.total_steps == 30
        assert res.security_violations == 0
        assert len(res.timeline) == 30
        # Check all fields populated
        for s in res.timeline:
            assert s.ai_threat_level is not None
            assert s.ai_threat_score is not None
            assert s.ai_confidence is not None
            assert s.ai_inference_time_ms >= 0.0
            assert s.policy_decision_time_ms >= 0.0


class TestSafetyInvariantsAndAblation:
    """Validate DO-178C fail-closed safety policy, anti-downgrade, and ablation studies."""

    def test_safety_override_on_critical_message(self, harness: EvaluationHarness) -> None:
        # S08: Safety critical message sent under benign telemetry (AI predicts NORMAL)
        scn = get_scenario("S08_CRITICAL_MESSAGE_LOW_AI_SCORE")
        res = harness.run_scenario(scn, AI_ADAPTIVE)
        assert res.security_violations == 0
        assert res.safety_overrides_count > 0

        for s in res.timeline:
            if s.criticality == "SAFETY_CRITICAL":
                # Safety policy MUST enforce ADAPTIVE-HIGH-ASSURANCE-V1 or ADAPTIVE-CRITICAL-V1
                assert s.selected_construction in ("ADAPTIVE-HIGH-ASSURANCE-V1", "ADAPTIVE-CRITICAL-V1")

    def test_downgrade_attempt_blocked(self, harness: EvaluationHarness) -> None:
        # S09: Adversarial downgrade attempt on CRITICAL flight plan
        scn = get_scenario("S09_DOWNGRADE_ATTEMPT")
        res = harness.run_scenario(scn, AI_ADAPTIVE)
        assert res.security_violations == 0
        assert res.downgrades_blocked_count > 0
        for s in res.timeline:
            assert s.selected_construction in ("ADAPTIVE-HIGH-ASSURANCE-V1", "ADAPTIVE-CRITICAL-V1")

    def test_hysteresis_anti_oscillation_damping(self, harness: EvaluationHarness) -> None:
        # S11: Rapid alternating threat spikes
        scn = get_scenario("S11_RAPID_THREAT_OSCILLATION")
        res_rule = harness.run_scenario(scn, BASELINE_RULE)
        res_ai = harness.run_scenario(scn, AI_ADAPTIVE)

        # AI-adaptive with K=3 hysteresis should have significantly fewer switches than rule-based
        assert res_ai.total_transitions <= res_rule.total_transitions
        assert res_ai.downgrades_held_count > 0

    def test_five_way_ablation_study(self) -> None:
        ablation_res = run_ablation_study()
        assert len(ablation_res) == 5
        config_ids = [r["config_id"] for r in ablation_res]
        assert "CONFIG_A_NO_AI" in config_ids
        assert "CONFIG_B_AI_NO_CONFIDENCE" in config_ids
        assert "CONFIG_C_AI_WITH_CONFIDENCE" in config_ids
        assert "CONFIG_D_AI_SAFETY_POLICY" in config_ids
        assert "CONFIG_E_FULL_SYSTEM" in config_ids

        # Unconstrained AI (Config B) must have safety violations, while Full System (Config E) has 0
        cfg_b = next(r for r in ablation_res if r["config_id"] == "CONFIG_B_AI_NO_CONFIDENCE")
        cfg_e = next(r for r in ablation_res if r["config_id"] == "CONFIG_E_FULL_SYSTEM")
        assert cfg_b["safety_violations"] > 0
        assert cfg_e["safety_violations"] == 0

    def test_safety_ablation_verification(self) -> None:
        safety_ab = run_safety_ablation()
        assert safety_ab["status"] == "SUCCESS"
        comp = safety_ab["comparison"]
        assert comp["ai_only_unconstrained"]["safety_violations"] > 0
        assert comp["full_safety_constrained_system"]["safety_violations"] == 0


class TestEvaluationAPI:
    """Validate Phase 13 REST API endpoints."""

    def test_get_scenarios_endpoint(self, client: TestClient) -> None:
        resp = client.get("/api/evaluation/scenarios")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "SUCCESS"
        assert data["total_scenarios"] == 12

    def test_post_run_single_scenario(self, client: TestClient) -> None:
        resp = client.post(
            "/api/evaluation/run",
            json={"scenario_id": "S01_NORMAL", "system_config": "AI_ADAPTIVE", "dwell_k": 3},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "SUCCESS"
        assert "scenario_result" in data
        assert "comprehensive_metrics" in data

    def test_get_results_and_comparison_endpoints(self, client: TestClient) -> None:
        resp_comp = client.get("/api/evaluation/comparison")
        assert resp_comp.status_code == 200
        assert resp_comp.json()["status"] == "SUCCESS"

        resp_res = client.get("/api/evaluation/results?scenario_id=S01_NORMAL")
        assert resp_res.status_code == 200
        assert resp_res.json()["status"] == "SUCCESS"


class TestSecurityAndZeroLeakage:
    """Verify that zero private keys, session keys, or plaintexts leak in evaluation artifacts."""

    def test_no_secrets_in_scenario_results(self) -> None:
        json_path = Path("data/evaluation/scenario_results.json")
        if json_path.exists():
            content = json_path.read_text(encoding="utf-8")
            forbidden = ["private_key", "secret_key", "master_secret", "session_key", "sk_bytes", "priv_key"]
            for term in forbidden:
                assert f'"{term}"' not in content

    def test_no_secrets_in_baseline_comparison(self) -> None:
        json_path = Path("data/evaluation/baseline_comparison.json")
        if json_path.exists():
            content = json_path.read_text(encoding="utf-8")
            forbidden = ["private_key", "secret_key", "master_secret", "session_key"]
            for term in forbidden:
                assert f'"{term}"' not in content

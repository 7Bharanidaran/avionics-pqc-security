"""Tests for Phase 9B safety-constrained adaptive selection."""
from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from backend.api.app import app
from backend.policy import BenchmarkProvider, Criticality, DecisionStatus, PolicyEngine, PolicyRequest, ThreatLevel
from backend.policy.profiles import UNAPPROVED_CLASSICAL_ONLY

client = TestClient(app)


def request(criticality=Criticality.ROUTINE, threat=ThreatLevel.NORMAL, budget=5000.0):
    return PolicyRequest("FLIGHT_CONTROL", criticality, threat, budget)


def test_normal_routine_selection():
    decision = PolicyEngine().evaluate(request())
    assert decision.status is DecisionStatus.PROFILE_SELECTED
    assert decision.selected_profile == "STANDARD_HYBRID"


def test_elevated_important_selection():
    decision = PolicyEngine().evaluate(request(Criticality.IMPORTANT, ThreatLevel.ELEVATED))
    assert decision.status is DecisionStatus.PROFILE_SELECTED
    assert decision.selected_profile == "HIGH_ASSURANCE_HYBRID"


def test_high_critical_selection():
    decision = PolicyEngine().evaluate(request(Criticality.CRITICAL, ThreatLevel.HIGH))
    assert decision.status is DecisionStatus.PROFILE_SELECTED
    assert decision.assurance_level.value == "MAXIMUM"


def test_critical_safety_critical_selection():
    decision = PolicyEngine().evaluate(request(Criticality.SAFETY_CRITICAL, ThreatLevel.CRITICAL))
    assert decision.status is DecisionStatus.PROFILE_SELECTED
    assert decision.selected_profile == "HIGH_ASSURANCE_HYBRID"


def test_latency_requirement_satisfied():
    decision = PolicyEngine().evaluate(request(budget=5000.0))
    assert next(item for item in decision.constraints if item.name == "Latency requirement").passed


def test_latency_requirement_conflict_never_downgrades():
    decision = PolicyEngine().evaluate(request(Criticality.SAFETY_CRITICAL, ThreatLevel.CRITICAL, 100.0))
    assert decision.status is DecisionStatus.CONSTRAINT_CONFLICT
    assert decision.downgrade_blocked is True
    assert "Security downgrade is prohibited" in decision.reason


def test_safety_critical_downgrade_blocked():
    decision = PolicyEngine().evaluate(request(Criticality.SAFETY_CRITICAL, ThreatLevel.NORMAL, 100.0))
    assert decision.downgrade_blocked is True
    assert decision.selected_profile == "HIGH_ASSURANCE_HYBRID"


def test_high_threat_downgrade_blocked():
    decision = PolicyEngine().evaluate(request(Criticality.ROUTINE, ThreatLevel.HIGH, 100.0))
    assert decision.status is DecisionStatus.CONSTRAINT_CONFLICT
    assert decision.selected_profile == "HIGH_ASSURANCE_HYBRID"


def test_classical_only_unapproved_profile_rejected():
    decision = PolicyEngine(profiles=(UNAPPROVED_CLASSICAL_ONLY,)).evaluate(request())
    assert decision.status is DecisionStatus.NO_FEASIBLE_PROFILE
    assert decision.selected_profile is None


def test_invalid_latency_is_invalid_request():
    decision = PolicyEngine().evaluate(request(budget=0))
    assert decision.status is DecisionStatus.INVALID_REQUEST


def test_benchmark_provider_reads_latest_measurement():
    latency = BenchmarkProvider().handshake_latency_ms()
    assert latency > 0
    assert latency == 2318.9934


def test_missing_benchmark_data_is_safe(tmp_path: Path):
    decision = PolicyEngine(BenchmarkProvider(tmp_path / "missing.json")).evaluate(request())
    assert decision.status is DecisionStatus.NO_FEASIBLE_PROFILE
    assert decision.downgrade_blocked is True


def test_score_and_explanation_are_deterministic():
    engine = PolicyEngine()
    first, second = engine.evaluate(request()), engine.evaluate(request())
    assert first.score == second.score
    assert first.reason == second.reason


def test_policy_api_validation_and_response_schema():
    response = client.post("/api/policy/evaluate", json={"message_type": "FLIGHT_CONTROL", "criticality": "SAFETY_CRITICAL", "threat_level": "CRITICAL", "latency_budget_ms": 100})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "CONSTRAINT_CONFLICT"
    assert data["downgrade_blocked"] is True
    assert isinstance(data["constraints"], list)
    invalid = client.post("/api/policy/evaluate", json={"message_type": "X", "criticality": "INVALID", "threat_level": "NORMAL", "latency_budget_ms": 1})
    assert invalid.status_code == 422


def test_policy_profiles_rules_and_metrics_api():
    profiles = client.get("/api/policy/profiles")
    assert profiles.status_code == 200
    assert {p["profile_id"] for p in profiles.json()} == {"STANDARD_HYBRID", "HIGH_ASSURANCE_HYBRID"}
    rules = client.get("/api/policy/rules")
    assert rules.status_code == 200
    assert rules.json()["criticality_minimum_assurance"]["SAFETY_CRITICAL"] == "MAXIMUM"
    assert client.get("/api/policy/metrics").json()["scope"] == "CURRENT SESSION"

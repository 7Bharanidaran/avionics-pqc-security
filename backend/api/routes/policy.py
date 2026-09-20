"""API routes for deterministic safety-constrained profile selection."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from backend.api.schemas import (PolicyConstraintResponse, PolicyDecisionResponse, PolicyEvaluateRequest,
                                 PolicyMetricsResponse, PolicyProfileResponse, PolicyRulesResponse)
from backend.policy import APPROVED_PROFILES, Criticality, PolicyEngine, PolicyRequest, ThreatLevel
from backend.policy.benchmark_provider import BenchmarkDataError
from backend.policy.engine import CRITICALITY_MINIMUM, THREAT_MINIMUM

router = APIRouter(prefix="/policy", tags=["Adaptive Policy"])
engine = PolicyEngine()
_metrics = {"total": 0, "selected": 0, "conflicts": 0, "blocked": 0, "time_ms": 0.0}


def serialize_decision(decision) -> PolicyDecisionResponse:
    return PolicyDecisionResponse(
        status=decision.status.value, selected_profile=decision.selected_profile,
        assurance_level=decision.assurance_level.value if decision.assurance_level else None,
        estimated_latency_ms=decision.estimated_latency_ms, latency_budget_ms=decision.latency_budget_ms,
        criticality=decision.criticality.value if decision.criticality else None,
        threat_level=decision.threat_level.value if decision.threat_level else None, score=decision.score,
        reason=decision.reason, constraints=[PolicyConstraintResponse(name=item.name, passed=item.passed, detail=item.detail) for item in decision.constraints],
        downgrade_allowed=decision.downgrade_allowed, downgrade_blocked=decision.downgrade_blocked,
        decision_time_ms=decision.decision_time_ms, benchmark_source=decision.benchmark_source,
    )


@router.post("/evaluate", response_model=PolicyDecisionResponse)
def evaluate_policy(request: PolicyEvaluateRequest) -> PolicyDecisionResponse:
    try:
        domain_request = PolicyRequest(request.message_type, Criticality(request.criticality), ThreatLevel(request.threat_level), request.latency_budget_ms)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid policy input: {exc}") from exc
    decision = engine.evaluate(domain_request)
    _metrics["total"] += 1
    _metrics["time_ms"] += decision.decision_time_ms
    if decision.status.value == "PROFILE_SELECTED": _metrics["selected"] += 1
    if decision.status.value == "CONSTRAINT_CONFLICT": _metrics["conflicts"] += 1
    if decision.downgrade_blocked: _metrics["blocked"] += 1
    return serialize_decision(decision)


@router.get("/profiles", response_model=list[PolicyProfileResponse])
def get_profiles() -> list[PolicyProfileResponse]:
    try:
        measured_latency = engine.benchmark_provider.handshake_latency_ms()
    except BenchmarkDataError:
        measured_latency = None
    return [PolicyProfileResponse(profile_id=p.profile_id, assurance_level=p.assurance_level.value, key_agreement=p.key_agreement,
        kem=p.kem, authentication=p.authentication, aead=p.aead, allowed_criticality=[item.value for item in p.allowed_criticality],
        maximum_threat=p.maximum_threat.value, downgrade_allowed=p.downgrade_allowed, measured_latency_ms=measured_latency) for p in APPROVED_PROFILES]


@router.get("/rules", response_model=PolicyRulesResponse)
def get_rules() -> PolicyRulesResponse:
    return PolicyRulesResponse(
        criticality_minimum_assurance={key.value: value.value for key, value in CRITICALITY_MINIMUM.items()},
        threat_minimum_assurance={key.value: value.value for key, value in THREAT_MINIMUM.items()},
        scoring_weights={"security": engine.weights.security, "threat": engine.weights.threat, "latency": engine.weights.latency, "resource": engine.weights.resource},
        safety_rules=["SAFETY_CRITICAL messages require MAXIMUM assurance.", "CRITICAL messages cannot use a classical-only profile.", "HIGH and CRITICAL threat states cannot reduce assurance.", "Security requirements take priority over latency optimization.", "Only approved profiles may be selected.", "A latency conflict never triggers an unsafe downgrade."],
    )


@router.get("/metrics", response_model=PolicyMetricsResponse)
def get_metrics() -> PolicyMetricsResponse:
    total = _metrics["total"]
    return PolicyMetricsResponse(scope="CURRENT SESSION", total_evaluations=total, successful_selections=_metrics["selected"],
        constraint_conflicts=_metrics["conflicts"], blocked_downgrades=_metrics["blocked"], average_decision_time_ms=round(_metrics["time_ms"] / total, 4) if total else 0.0)

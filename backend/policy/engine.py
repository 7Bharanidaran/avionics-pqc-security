"""Deterministic, safety-first operational profile selection engine."""
from __future__ import annotations

import time
from dataclasses import dataclass

from .benchmark_provider import BenchmarkDataError, BenchmarkProvider
from .models import (ASSURANCE_RANK, THREAT_RANK, AssuranceLevel, ConstraintCheck, Criticality,
                     CryptoProfile, DecisionStatus, PolicyDecision, PolicyRequest, ThreatLevel)
from .profiles import APPROVED_PROFILES


CRITICALITY_MINIMUM = {Criticality.ROUTINE: AssuranceLevel.STANDARD, Criticality.IMPORTANT: AssuranceLevel.HIGH,
                       Criticality.CRITICAL: AssuranceLevel.HIGH, Criticality.SAFETY_CRITICAL: AssuranceLevel.MAXIMUM}
THREAT_MINIMUM = {ThreatLevel.NORMAL: AssuranceLevel.STANDARD, ThreatLevel.ELEVATED: AssuranceLevel.STANDARD,
                  ThreatLevel.HIGH: AssuranceLevel.HIGH, ThreatLevel.CRITICAL: AssuranceLevel.MAXIMUM}

@dataclass(frozen=True)
class ScoringWeights:
    security: float = 0.45
    threat: float = 0.25
    latency: float = 0.20
    resource: float = 0.10


class PolicyEngine:
    def __init__(self, benchmark_provider: BenchmarkProvider | None = None, profiles: tuple[CryptoProfile, ...] = APPROVED_PROFILES,
                 weights: ScoringWeights = ScoringWeights()) -> None:
        self.benchmark_provider, self.profiles, self.weights = benchmark_provider or BenchmarkProvider(), profiles, weights

    @staticmethod
    def required_assurance(request: PolicyRequest) -> AssuranceLevel:
        criticality_requirement = CRITICALITY_MINIMUM[request.criticality]
        threat_requirement = THREAT_MINIMUM[request.threat_level]
        return max(criticality_requirement, threat_requirement, key=lambda level: ASSURANCE_RANK[level])

    def evaluate(self, request: PolicyRequest) -> PolicyDecision:
        started = time.perf_counter_ns()
        if request.latency_budget_ms <= 0:
            return self._invalid(request, "Latency budget must be greater than zero.", started)
        try:
            latency = self.benchmark_provider.handshake_latency_ms()
        except BenchmarkDataError as exc:
            return self._benchmark_failure(request, str(exc), started)
        required = self.required_assurance(request)
        checks: list[ConstraintCheck] = []
        feasible: list[CryptoProfile] = []
        for profile in self.profiles:
            approved = profile.approved
            assurance_ok = ASSURANCE_RANK[profile.assurance_level] >= ASSURANCE_RANK[required]
            threat_ok = THREAT_RANK[request.threat_level] <= THREAT_RANK[profile.maximum_threat]
            criticality_ok = request.criticality in profile.allowed_criticality
            if approved and assurance_ok and threat_ok and criticality_ok:
                feasible.append(profile)
        checks.extend((
            ConstraintCheck("Approved profile", bool(feasible), "Only approved executable hybrid profiles are eligible."),
            ConstraintCheck("Security requirement", bool(feasible), f"Minimum assurance is {required.value}."),
            ConstraintCheck("Threat requirement", bool(feasible), f"Threat state is {request.threat_level.value}."),
            ConstraintCheck("Criticality requirement", bool(feasible), f"Message criticality is {request.criticality.value}."),
        ))
        if not feasible:
            checks.append(ConstraintCheck("Latency requirement", latency <= request.latency_budget_ms, f"Measured hybrid handshake latency is {latency:.4f} ms."))
            return self._decision(DecisionStatus.NO_FEASIBLE_PROFILE, None, request, latency, None,
                f"No approved profile satisfies {request.criticality.value} criticality, {request.threat_level.value} threat, and {required.value} minimum assurance.", checks, True, started)
        latency_ok = latency <= request.latency_budget_ms
        checks.append(ConstraintCheck("Latency requirement", latency_ok, f"Measured hybrid handshake latency is {latency:.4f} ms; budget is {request.latency_budget_ms:.4f} ms."))
        if not latency_ok:
            profile = max(feasible, key=lambda item: ASSURANCE_RANK[item.assurance_level])
            return self._decision(DecisionStatus.CONSTRAINT_CONFLICT, profile, request, latency, None,
                f"{required.value} assurance requires {profile.profile_id}, but measured hybrid handshake latency {latency:.4f} ms exceeds the {request.latency_budget_ms:.4f} ms budget. Security downgrade is prohibited.", checks, True, started)
        scored = [(self._score(profile, required, request.threat_level, latency, request.latency_budget_ms), profile) for profile in feasible]
        score, profile = max(scored, key=lambda item: (item[0], item[1].profile_id))
        return self._decision(DecisionStatus.PROFILE_SELECTED, profile, request, latency, score,
            f"Selected {profile.profile_id}: {request.criticality.value} criticality and {request.threat_level.value} threat require at least {required.value} assurance; measured latency {latency:.4f} ms is within budget.", checks, False, started)

    def _score(self, profile: CryptoProfile, required: AssuranceLevel, threat: ThreatLevel, latency: float, budget: float) -> float:
        # Suitability rewards meeting the requirement precisely; surplus assurance is not
        # treated as inherently better when it provides no additional required protection.
        security = max(0.0, 100.0 - 35.0 * (ASSURANCE_RANK[profile.assurance_level] - ASSURANCE_RANK[required]))
        threat_fit = max(0.0, 100.0 - 25.0 * (THREAT_RANK[profile.maximum_threat] - THREAT_RANK[threat]))
        latency_fit = max(0.0, min(100.0, 100.0 * budget / latency))
        value = self.weights.security * security + self.weights.threat * threat_fit + self.weights.latency * latency_fit + self.weights.resource * profile.resource_score
        return round(value, 4)

    def _invalid(self, request: PolicyRequest, reason: str, started: int) -> PolicyDecision:
        return self._decision(DecisionStatus.INVALID_REQUEST, None, request, None, None, reason, (), False, started)

    def _benchmark_failure(self, request: PolicyRequest, reason: str, started: int) -> PolicyDecision:
        return self._decision(DecisionStatus.NO_FEASIBLE_PROFILE, None, request, None, None, reason, (ConstraintCheck("Benchmark availability", False, reason),), True, started)

    def _decision(self, status: DecisionStatus, profile: CryptoProfile | None, request: PolicyRequest, latency: float | None, score: float | None,
                  reason: str, constraints: tuple[ConstraintCheck, ...] | list[ConstraintCheck], downgrade_blocked: bool, started: int) -> PolicyDecision:
        return PolicyDecision(status=status, selected_profile=profile.profile_id if profile else None,
            assurance_level=profile.assurance_level if profile else None, estimated_latency_ms=latency,
            latency_budget_ms=request.latency_budget_ms, criticality=request.criticality, threat_level=request.threat_level,
            score=score, reason=reason, constraints=tuple(constraints), downgrade_allowed=False,
            downgrade_blocked=downgrade_blocked, decision_time_ms=round((time.perf_counter_ns() - started) / 1_000_000, 4),
            benchmark_source=str(self.benchmark_provider.benchmark_file))

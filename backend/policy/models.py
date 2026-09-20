"""Typed policy models for safety-constrained profile selection."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Criticality(str, Enum):
    ROUTINE = "ROUTINE"
    IMPORTANT = "IMPORTANT"
    CRITICAL = "CRITICAL"
    SAFETY_CRITICAL = "SAFETY_CRITICAL"


class ThreatLevel(str, Enum):
    NORMAL = "NORMAL"
    ELEVATED = "ELEVATED"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AssuranceLevel(str, Enum):
    STANDARD = "STANDARD"
    HIGH = "HIGH"
    MAXIMUM = "MAXIMUM"


class DecisionStatus(str, Enum):
    PROFILE_SELECTED = "PROFILE_SELECTED"
    CONSTRAINT_CONFLICT = "CONSTRAINT_CONFLICT"
    INVALID_REQUEST = "INVALID_REQUEST"
    NO_FEASIBLE_PROFILE = "NO_FEASIBLE_PROFILE"


@dataclass(frozen=True)
class PolicyRequest:
    message_type: str
    criticality: Criticality
    threat_level: ThreatLevel
    latency_budget_ms: float


@dataclass(frozen=True)
class CryptoProfile:
    profile_id: str
    assurance_level: AssuranceLevel
    key_agreement: str
    kem: str
    authentication: str
    aead: str
    allowed_criticality: tuple[Criticality, ...]
    maximum_threat: ThreatLevel
    approved: bool = True
    downgrade_allowed: bool = False
    resource_score: float = 50.0


@dataclass(frozen=True)
class ConstraintCheck:
    name: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class PolicyDecision:
    status: DecisionStatus
    selected_profile: str | None
    assurance_level: AssuranceLevel | None
    estimated_latency_ms: float | None
    latency_budget_ms: float
    criticality: Criticality | None
    threat_level: ThreatLevel | None
    score: float | None
    reason: str
    constraints: tuple[ConstraintCheck, ...] = field(default_factory=tuple)
    downgrade_allowed: bool = False
    downgrade_blocked: bool = False
    decision_time_ms: float = 0.0
    benchmark_source: str = ""


ASSURANCE_RANK = {AssuranceLevel.STANDARD: 1, AssuranceLevel.HIGH: 2, AssuranceLevel.MAXIMUM: 3}
THREAT_RANK = {ThreatLevel.NORMAL: 1, ThreatLevel.ELEVATED: 2, ThreatLevel.HIGH: 3, ThreatLevel.CRITICAL: 4}

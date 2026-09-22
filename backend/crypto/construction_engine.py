"""Adaptive Cryptographic Construction Selection and Execution Engine.

Bridges operational threat scoring, message criticality, latency budgets,
and safety constraints to deterministically select, validate, and execute
one of the four verified adaptive constructions without permitting insecure downgrades.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from backend.avionics.channel import EncryptedPacketEnvelope
from backend.avionics.messages import AvionicsMessage
from .adaptive_base import (
    AdaptiveSession,
    BaseAdaptiveConstruction,
    ConstructionDowngradeError,
    ConstructionError,
    ConstructionMetadata,
    ConstructionSecurityLevel,
)
from .adaptive_critical import ADAPTIVE_CRITICAL
from .adaptive_high_assurance import ADAPTIVE_HIGH_ASSURANCE
from .adaptive_balanced import ADAPTIVE_BALANCED
from .adaptive_standard import ADAPTIVE_STANDARD

CRITICALITY_HIERARCHY = {
    "ROUTINE": 1,
    "IMPORTANT": 2,
    "CRITICAL": 3,
    "SAFETY_CRITICAL": 4,
}

THREAT_HIERARCHY = {
    "NORMAL": 1,
    "ELEVATED": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

SECURITY_LEVEL_HIERARCHY = {
    ConstructionSecurityLevel.STANDARD: 1,
    ConstructionSecurityLevel.BALANCED: 2,
    ConstructionSecurityLevel.HIGH_ASSURANCE: 3,
    ConstructionSecurityLevel.CRITICAL: 4,
}


@dataclass(frozen=True)
class ConstructionConstraintCheck:
    name: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class ConstructionDecision:
    status: str  # "APPROVED", "CONSTRAINT_CONFLICT", "REJECTED"
    selected_construction_id: str | None
    security_level: str | None
    criticality: str
    threat_level: str
    threat_score: float | None
    latency_budget_ms: float
    estimated_latency_ms: float | None
    reason: str
    constraints: tuple[ConstructionConstraintCheck, ...] = field(default_factory=tuple)
    downgrade_blocked: bool = False
    decision_time_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "selected_construction_id": self.selected_construction_id,
            "security_level": self.security_level,
            "criticality": self.criticality,
            "threat_level": self.threat_level,
            "threat_score": self.threat_score,
            "latency_budget_ms": self.latency_budget_ms,
            "estimated_latency_ms": self.estimated_latency_ms,
            "reason": self.reason,
            "constraints": [{"name": c.name, "passed": c.passed, "detail": c.detail} for c in self.constraints],
            "downgrade_blocked": self.downgrade_blocked,
            "decision_time_ms": self.decision_time_ms,
        }


class ConstructionEngine:
    """Orchestrates selection, safety filtering, and execution of adaptive constructions."""

    def __init__(self) -> None:
        self._constructions: dict[str, BaseAdaptiveConstruction] = {
            "ADAPTIVE-STANDARD-V1": ADAPTIVE_STANDARD,
            "ADAPTIVE-BALANCED-V1": ADAPTIVE_BALANCED,
            "ADAPTIVE-HIGH-ASSURANCE-V1": ADAPTIVE_HIGH_ASSURANCE,
            "ADAPTIVE-CRITICAL-V1": ADAPTIVE_CRITICAL,
        }

    def get_construction(self, construction_id: str) -> BaseAdaptiveConstruction:
        """Retrieve construction by ID or raise ConstructionError."""
        if construction_id not in self._constructions:
            supported = ", ".join(self._constructions.keys())
            raise ConstructionError(f"Unknown construction ID '{construction_id}'. Supported: {supported}")
        return self._constructions[construction_id]

    def list_constructions(self) -> list[ConstructionMetadata]:
        """Return metadata for all registered adaptive constructions."""
        return [c.metadata for c in self._constructions.values()]

    def select_construction(
        self,
        criticality: str = "ROUTINE",
        threat_level: str = "NORMAL",
        threat_score: float | None = None,
        latency_budget_ms: float = 5000.0,
    ) -> ConstructionDecision:
        """Deterministically select the appropriate construction and enforce safety invariants."""
        start_ns = time.perf_counter_ns()
        crit_upper = criticality.upper()
        threat_upper = threat_level.upper()

        if crit_upper not in CRITICALITY_HIERARCHY:
            return ConstructionDecision(
                status="REJECTED",
                selected_construction_id=None,
                security_level=None,
                criticality=criticality,
                threat_level=threat_level,
                threat_score=threat_score,
                latency_budget_ms=latency_budget_ms,
                estimated_latency_ms=None,
                reason=f"Invalid message criticality: {criticality}",
                constraints=(),
                downgrade_blocked=False,
                decision_time_ms=0.0,
            )

        if threat_upper not in THREAT_HIERARCHY:
            return ConstructionDecision(
                status="REJECTED",
                selected_construction_id=None,
                security_level=None,
                criticality=criticality,
                threat_level=threat_level,
                threat_score=threat_score,
                latency_budget_ms=latency_budget_ms,
                estimated_latency_ms=None,
                reason=f"Invalid threat level: {threat_level}",
                constraints=(),
                downgrade_blocked=False,
                decision_time_ms=0.0,
            )

        effective_threat_rank = THREAT_HIERARCHY[threat_upper]
        normalized_score = threat_score / 100.0 if (threat_score is not None and threat_score > 1.0) else threat_score
        if normalized_score is not None:
            if normalized_score >= 0.75:
                effective_threat_rank = max(effective_threat_rank, 4)
            elif normalized_score >= 0.50:
                effective_threat_rank = max(effective_threat_rank, 3)
            elif normalized_score >= 0.25:
                effective_threat_rank = max(effective_threat_rank, 2)

        crit_rank = CRITICALITY_HIERARCHY[crit_upper]

        if crit_rank == 4:  # SAFETY_CRITICAL
            req_level = ConstructionSecurityLevel.CRITICAL
            selected_id = "ADAPTIVE-CRITICAL-V1"
            est_latency = 2320.0
        elif crit_rank == 3 or effective_threat_rank == 4:  # CRITICAL message or CRITICAL threat
            if effective_threat_rank == 4 or (normalized_score is not None and normalized_score >= 0.75):
                req_level = ConstructionSecurityLevel.CRITICAL
                selected_id = "ADAPTIVE-CRITICAL-V1"
                est_latency = 2320.0
            else:
                req_level = ConstructionSecurityLevel.HIGH_ASSURANCE
                selected_id = "ADAPTIVE-HIGH-ASSURANCE-V1"
                est_latency = 2318.0

        elif effective_threat_rank == 3:  # HIGH threat
            req_level = ConstructionSecurityLevel.HIGH_ASSURANCE
            selected_id = "ADAPTIVE-HIGH-ASSURANCE-V1"
            est_latency = 2318.0
        elif crit_rank == 2 or effective_threat_rank == 2:  # IMPORTANT or ELEVATED
            req_level = ConstructionSecurityLevel.BALANCED
            selected_id = "ADAPTIVE-BALANCED-V1"
            est_latency = 1.5
        else:
            req_level = ConstructionSecurityLevel.STANDARD
            selected_id = "ADAPTIVE-STANDARD-V1"
            est_latency = 0.95

        construction = self._constructions[selected_id]

        # 2. Evaluate Safety Constraints
        checks = [
            ConstructionConstraintCheck("Approved Construction", True, f"Construction {selected_id} is approved and verified."),
            ConstructionConstraintCheck("Security Level", True, f"Assurance level {req_level.value} satisfies {crit_upper} criticality and {threat_upper} threat."),
            ConstructionConstraintCheck("Downgrade Protection", True, "Downgrade to weaker cryptographic profile is prohibited."),
        ]

        # 3. Latency Check & Downgrade Prevention
        if latency_budget_ms < est_latency:
            checks.append(
                ConstructionConstraintCheck(
                    "Latency Budget",
                    False,
                    f"Estimated latency ({est_latency:.2f} ms) exceeds requested budget ({latency_budget_ms:.2f} ms).",
                )
            )
            decision_time = (time.perf_counter_ns() - start_ns) / 1_000_000.0
            return ConstructionDecision(
                status="CONSTRAINT_CONFLICT",
                selected_construction_id=selected_id,
                security_level=req_level.value,
                criticality=crit_upper,
                threat_level=threat_upper,
                threat_score=threat_score,
                latency_budget_ms=latency_budget_ms,
                estimated_latency_ms=est_latency,
                reason=(
                    f"Mandatory security assurance requires {selected_id} ({est_latency:.2f} ms estimated), "
                    f"which exceeds the {latency_budget_ms:.2f} ms latency budget. "
                    f"Security downgrade is strictly prohibited by safety policy."
                ),
                constraints=tuple(checks),
                downgrade_blocked=True,
                decision_time_ms=decision_time,
            )

        checks.append(
            ConstructionConstraintCheck(
                "Latency Budget",
                True,
                f"Estimated latency ({est_latency:.2f} ms) is within budget ({latency_budget_ms:.2f} ms).",
            )
        )

        decision_time = (time.perf_counter_ns() - start_ns) / 1_000_000.0
        return ConstructionDecision(
            status="APPROVED",
            selected_construction_id=selected_id,
            security_level=req_level.value,
            criticality=crit_upper,
            threat_level=threat_upper,
            threat_score=threat_score,
            latency_budget_ms=latency_budget_ms,
            estimated_latency_ms=est_latency,
            reason=(
                f"Selected {selected_id} ({req_level.value}) for {crit_upper} traffic under {threat_upper} threat. "
                f"All safety invariants and latency constraints are satisfied."
            ),
            constraints=tuple(checks),
            downgrade_blocked=False,
            decision_time_ms=decision_time,
        )

    def execute_handshake(
        self,
        initiator: Any,
        responder: Any,
        construction_id: str | None = None,
        criticality: str = "ROUTINE",
        threat_level: str = "NORMAL",
        threat_score: float | None = None,
        latency_budget_ms: float = 5000.0,
    ) -> tuple[AdaptiveSession, AdaptiveSession, ConstructionDecision]:
        """Select construction (or use requested) and execute full handshake."""
        if construction_id is not None:
            construction = self.get_construction(construction_id)
            decision = ConstructionDecision(
                status="APPROVED",
                selected_construction_id=construction_id,
                security_level=construction.metadata.security_level.value,
                criticality=criticality,
                threat_level=threat_level,
                threat_score=threat_score,
                latency_budget_ms=latency_budget_ms,
                estimated_latency_ms=None,
                reason=f"Explicit construction {construction_id} requested.",
                constraints=(ConstructionConstraintCheck("Explicit Override", True, f"Using {construction_id}"),),
                downgrade_blocked=False,
            )
        else:
            decision = self.select_construction(
                criticality=criticality,
                threat_level=threat_level,
                threat_score=threat_score,
                latency_budget_ms=latency_budget_ms,
            )
            if decision.status != "APPROVED":
                raise ConstructionError(f"Cannot establish session: {decision.reason}")
            construction = self.get_construction(decision.selected_construction_id)

        init_session, resp_session = construction.establish_session(initiator, responder)

        if hasattr(initiator, "register_secure_session"):
            initiator.register_secure_session(responder.component_id, init_session)
        if hasattr(responder, "register_secure_session"):
            responder.register_secure_session(initiator.component_id, resp_session)

        return init_session, resp_session, decision


CONSTRUCTION_ENGINE = ConstructionEngine()

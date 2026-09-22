"""Experimental Evaluation and Dataset Generation Package for Avionics PQC Security Lab."""

from __future__ import annotations

from .security_evaluator import (
    ConstructionAttackResult,
    evaluate_construction_against_attacks,
    run_full_security_matrix,
)
from .threat_scenarios import (
    ThreatDatasetRecord,
    generate_threat_dataset,
)

__all__ = [
    "ConstructionAttackResult",
    "evaluate_construction_against_attacks",
    "run_full_security_matrix",
    "ThreatDatasetRecord",
    "generate_threat_dataset",
]


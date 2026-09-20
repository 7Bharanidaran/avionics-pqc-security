"""Avionics Post-Quantum Security Attack Simulation Package.

Provides controlled security simulations and validation reports.
"""

from __future__ import annotations

from .attack_simulation import (
    AttackResult,
    AttackStatus,
    run_all_attack_simulations,
    run_baseline_test,
    simulate_aad_tampering,
    simulate_auth_tag_tampering,
    simulate_ciphertext_tampering,
    simulate_ed25519_forgery,
    simulate_replay_attack,
    simulate_slhdsa_forgery,
    simulate_transcript_modification,
    simulate_wrong_receiver_attack,
    simulate_wrong_session_attack,
)
from .security_report import (
    SecurityReport,
    generate_security_report,
)

__all__ = [
    "AttackResult",
    "AttackStatus",
    "SecurityReport",
    "generate_security_report",
    "run_all_attack_simulations",
    "run_baseline_test",
    "simulate_ciphertext_tampering",
    "simulate_auth_tag_tampering",
    "simulate_aad_tampering",
    "simulate_ed25519_forgery",
    "simulate_slhdsa_forgery",
    "simulate_transcript_modification",
    "simulate_wrong_session_attack",
    "simulate_wrong_receiver_attack",
    "simulate_replay_attack",
]

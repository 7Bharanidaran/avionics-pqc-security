"""Security attack simulation API routes."""

from __future__ import annotations

from typing import Any, Callable
from fastapi import APIRouter, HTTPException

from backend.api.schemas import (
    AttackItem,
    AttacksListResponse,
    SimulateAttackRequest,
    SimulateAttackResponse,
)
from backend.security import (
    AttackResult,
    generate_security_report,
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

router = APIRouter(prefix="/security", tags=["Security"])

_ATTACK_RUNNERS: dict[str, Callable[[], AttackResult]] = {
    "baseline": run_baseline_test,
    "atk-00": run_baseline_test,
    "ciphertext_tampering": simulate_ciphertext_tampering,
    "atk-01": simulate_ciphertext_tampering,
    "tag_tampering": simulate_auth_tag_tampering,
    "gcm_tag_tampering": simulate_auth_tag_tampering,
    "atk-02": simulate_auth_tag_tampering,
    "aad_tampering": simulate_aad_tampering,
    "atk-03": simulate_aad_tampering,
    "ed25519_forgery": simulate_ed25519_forgery,
    "atk-04": simulate_ed25519_forgery,
    "slhdsa_forgery": simulate_slhdsa_forgery,
    "atk-05": simulate_slhdsa_forgery,
    "transcript_modification": simulate_transcript_modification,
    "atk-06": simulate_transcript_modification,
    "wrong_session": simulate_wrong_session_attack,
    "atk-07": simulate_wrong_session_attack,
    "wrong_receiver": simulate_wrong_receiver_attack,
    "atk-08": simulate_wrong_receiver_attack,
    "replay": simulate_replay_attack,
    "replay_attack": simulate_replay_attack,
    "atk-09": simulate_replay_attack,
}


def result_to_attack_item(result: AttackResult) -> AttackItem:
    """Convert an AttackResult domain model to an AttackItem schema."""
    return AttackItem(
        attack_id=result.attack_id,
        attack_name=result.attack_name,
        description=result.description,
        target=result.target,
        expected_behavior=result.expected_behavior,
        actual_behavior=result.actual_behavior,
        detected=result.detected,
        status=result.status.value,
        timestamp=result.timestamp,
    )


@router.get("/attacks", response_model=AttacksListResponse)
def get_security_attacks() -> AttacksListResponse:
    """Execute all security attack simulations and return an aggregated report."""
    report = generate_security_report()

    attack_items = [result_to_attack_item(r) for r in report.results]

    return AttacksListResponse(
        overall_status=report.overall_status,
        baseline_passed=report.baseline_passed,
        total_attacks=report.total_attacks,
        attacks_detected=report.attacks_detected,
        attacks_not_detected=report.attacks_not_detected,
        attacks=attack_items,
    )


@router.post("/simulate", response_model=SimulateAttackResponse)
def simulate_attack(request: SimulateAttackRequest) -> SimulateAttackResponse:
    """Trigger a single security attack simulation by name."""
    norm_key = request.attack.strip().lower()
    runner = _ATTACK_RUNNERS.get(norm_key)

    if runner is None:
        valid_keys = [
            "ciphertext_tampering",
            "tag_tampering",
            "aad_tampering",
            "ed25519_forgery",
            "slhdsa_forgery",
            "transcript_modification",
            "wrong_session",
            "wrong_receiver",
            "replay",
            "baseline",
        ]
        raise HTTPException(
            status_code=400,
            detail=f"Unknown attack identifier '{request.attack}'. Valid options: {valid_keys}",
        )

    result = runner()

    return SimulateAttackResponse(
        attack=request.attack,
        attack_id=result.attack_id,
        attack_name=result.attack_name,
        detected=result.detected,
        status=result.status.value,
        expected_behavior=result.expected_behavior,
        actual_behavior=result.actual_behavior,
        description=result.description,
    )

"""Demonstration Scenarios Catalog for Practical Research Showcase (Phase 14).

Defines 8 standardized demonstration scenarios spanning nominal operations,
threat escalation, maximum PQC assurance, safety policy overrides, and active adversarial attacks.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from backend.ai.schemas import TelemetryInput


@dataclass(frozen=True)
class DemonstrationScenarioDef:
    """Metadata and telemetry definition for a live demonstration scenario."""

    scenario_id: str
    name: str
    category: str
    description: str
    target_construction: str
    message_type: str
    criticality: str
    telemetry: TelemetryInput
    attack_type: str | None = None  # None, "DOWNGRADE", "CIPHERTEXT_TAMPER", "AAD_TAMPER", "REPLAY"
    expected_outcome: str = "ACCEPTED"
    key_takeaway: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "target_construction": self.target_construction,
            "message_type": self.message_type,
            "criticality": self.criticality,
            "telemetry": self.telemetry.model_dump(),
            "attack_type": self.attack_type,
            "expected_outcome": self.expected_outcome,
            "key_takeaway": self.key_takeaway,
        }


# 8 Standardized Demonstration Scenarios
DEMO_SCENARIOS: dict[str, DemonstrationScenarioDef] = {
    "DEMO_01_NORMAL": DemonstrationScenarioDef(
        scenario_id="DEMO_01_NORMAL",
        name="Demo 1: Nominal Avionics Operations",
        category="Baseline",
        description="Routine navigation telemetry exchange under clean RF conditions with zero security anomalies.",
        target_construction="ADAPTIVE-STANDARD-V1",
        message_type="NAVIGATION_UPDATE",
        criticality="ROUTINE",
        telemetry=TelemetryInput(
            message_type="NAVIGATION_UPDATE",
            criticality="ROUTINE",
            criticality_rank=1,
            latency_budget_ms=5000.0,
            observed_packet_rate_hz=20.0,
            channel_bit_error_rate=0.0001,
            replay_attempt_count=0,
            auth_failure_count=0,
            integrity_failure_count=0,
            aad_tamper_count=0,
            transcript_anomaly_count=0,
            routing_error_count=0,
            prior_security_events_window=0,
            anomaly_score_raw=0.04,
            flight_phase="CRUISE",
            snr_db=34.5,
            packet_loss_pct=0.2,
        ),
        attack_type=None,
        expected_outcome="ACCEPTED",
        key_takeaway="Standard post-quantum hybrid (X25519 + ML-KEM-768) provides optimal performance (sub-millisecond latency) during nominal cruise.",
    ),
    "DEMO_02_ELEVATED": DemonstrationScenarioDef(
        scenario_id="DEMO_02_ELEVATED",
        name="Demo 2: Threat Escalation & Dynamic Adaptation",
        category="Escalation",
        description="RF jamming anomalies and intermittent authentication errors trigger dynamic escalation to high-assurance dual authentication.",
        target_construction="ADAPTIVE-HIGH-ASSURANCE-V1",
        message_type="FLIGHT_MODE",
        criticality="IMPORTANT",
        telemetry=TelemetryInput(
            message_type="FLIGHT_MODE",
            criticality="IMPORTANT",
            criticality_rank=2,
            latency_budget_ms=5000.0,
            observed_packet_rate_hz=42.0,
            channel_bit_error_rate=0.012,
            replay_attempt_count=1,
            auth_failure_count=3,
            integrity_failure_count=1,
            aad_tamper_count=0,
            transcript_anomaly_count=1,
            routing_error_count=0,
            prior_security_events_window=4,
            anomaly_score_raw=52.5,
            flight_phase="CLIMB",
            snr_db=16.2,
            packet_loss_pct=8.5,
        ),
        attack_type=None,
        expected_outcome="CONSTRUCTION_ESCALATED",
        key_takeaway="System autonomously escalates to ADAPTIVE-HIGH-ASSURANCE-V1 (ML-KEM-1024 + SLH-DSA), activating dual quantum-resistant signatures.",
    ),
    "DEMO_03_CRITICAL": DemonstrationScenarioDef(
        scenario_id="DEMO_03_CRITICAL",
        name="Demo 3: Critical Threat & Maximum PQC Assurance",
        category="High Assurance",
        description="Active quantum harvesting / store-now-decrypt-later alert triggers maximum security profile with SHA-512 transcript binding.",
        target_construction="ADAPTIVE-CRITICAL-V1",
        message_type="ALTITUDE",
        criticality="SAFETY_CRITICAL",
        telemetry=TelemetryInput(
            message_type="ALTITUDE",
            criticality="SAFETY_CRITICAL",
            criticality_rank=4,
            latency_budget_ms=5000.0,
            observed_packet_rate_hz=65.0,
            channel_bit_error_rate=0.035,
            replay_attempt_count=5,
            auth_failure_count=8,
            integrity_failure_count=4,
            aad_tamper_count=3,
            transcript_anomaly_count=4,
            routing_error_count=2,
            prior_security_events_window=14,
            anomaly_score_raw=91.4,
            flight_phase="DESCENT",
            snr_db=9.5,
            packet_loss_pct=22.0,
        ),
        attack_type=None,
        expected_outcome="MAXIMUM_ASSURANCE_VERIFIED",
        key_takeaway="ADAPTIVE-CRITICAL-V1 activates strict dual post-quantum signatures (SLH-DSA + Ed25519) and 256-bit quantum security margin.",
    ),
    "DEMO_04_SAFETY_CONFLICT": DemonstrationScenarioDef(
        scenario_id="DEMO_04_SAFETY_CONFLICT",
        name="Demo 4: AI / Safety Conflict (DO-178C Safety Override)",
        category="Safety Invariant",
        description="AI threat model perceives low RF threat and recommends low assurance, but safety-critical flight envelope command strictly mandates Level 4 protection.",
        target_construction="ADAPTIVE-CRITICAL-V1",
        message_type="ALTITUDE",
        criticality="SAFETY_CRITICAL",
        telemetry=TelemetryInput(
            message_type="ALTITUDE",
            criticality="SAFETY_CRITICAL",
            criticality_rank=4,
            latency_budget_ms=5000.0,
            observed_packet_rate_hz=20.0,
            channel_bit_error_rate=0.0001,
            replay_attempt_count=0,
            auth_failure_count=0,
            integrity_failure_count=0,
            aad_tamper_count=0,
            transcript_anomaly_count=0,
            routing_error_count=0,
            prior_security_events_window=0,
            anomaly_score_raw=0.02,
            flight_phase="CRUISE",
            snr_db=36.0,
            packet_loss_pct=0.1,
        ),
        attack_type=None,
        expected_outcome="SAFETY_OVERRIDE_ENFORCED",
        key_takeaway="AI is strictly ADVISORY. Deterministic DO-178C safety policy is AUTHORITATIVE and overrides AI suggestion to protect flight-critical traffic.",
    ),
    "DEMO_05_DOWNGRADE_ATTACK": DemonstrationScenarioDef(
        scenario_id="DEMO_05_DOWNGRADE_ATTACK",
        name="Demo 5: Adversarial Downgrade Attack Defense",
        category="Adversarial Attack",
        description="Adversary attempts to manipulate negotiation or latency budget to force session downgrade from HIGH_ASSURANCE to STANDARD.",
        target_construction="ADAPTIVE-HIGH-ASSURANCE-V1",
        message_type="FLIGHT_MODE",
        criticality="CRITICAL",
        telemetry=TelemetryInput(
            message_type="FLIGHT_MODE",
            criticality="CRITICAL",
            criticality_rank=3,
            latency_budget_ms=5000.0,
            observed_packet_rate_hz=25.0,
            channel_bit_error_rate=0.005,
            replay_attempt_count=0,
            auth_failure_count=1,
            integrity_failure_count=0,
            aad_tamper_count=0,
            transcript_anomaly_count=0,
            routing_error_count=0,
            prior_security_events_window=1,
            anomaly_score_raw=15.0,
            flight_phase="CRUISE",
            snr_db=22.0,
            packet_loss_pct=4.0,
        ),
        attack_type="DOWNGRADE",
        expected_outcome="DOWNGRADE_BLOCKED",
        key_takeaway="Construction engine detects illegal security level regression and enforces fail-closed downgrade protection.",
    ),
    "DEMO_06_CIPHERTEXT_TAMPERING": DemonstrationScenarioDef(
        scenario_id="DEMO_06_CIPHERTEXT_TAMPERING",
        name="Demo 6: In-Transit Ciphertext Tampering Detection",
        category="Adversarial Attack",
        description="Adversary intercepts encrypted avionics envelope and flips bit patterns in the AES-256-GCM ciphertext payload.",
        target_construction="ADAPTIVE-HIGH-ASSURANCE-V1",
        message_type="HEADING",
        criticality="IMPORTANT",
        telemetry=TelemetryInput(
            message_type="HEADING",
            criticality="IMPORTANT",
            criticality_rank=2,
            latency_budget_ms=5000.0,
            observed_packet_rate_hz=20.0,
            channel_bit_error_rate=0.0002,
            replay_attempt_count=0,
            auth_failure_count=0,
            integrity_failure_count=0,
            aad_tamper_count=0,
            transcript_anomaly_count=0,
            routing_error_count=0,
            prior_security_events_window=0,
            anomaly_score_raw=1.2,
            flight_phase="CRUISE",
            snr_db=28.0,
            packet_loss_pct=0.8,
        ),
        attack_type="CIPHERTEXT_TAMPER",
        expected_outcome="MESSAGE_REJECTED",
        key_takeaway="AES-256-GCM authentication tag verification fails instantaneously; corrupted message is discarded with zero state mutation.",
    ),
    "DEMO_07_AAD_TAMPERING": DemonstrationScenarioDef(
        scenario_id="DEMO_07_AAD_TAMPERING",
        name="Demo 7: Additional Authenticated Data (AAD) Tampering",
        category="Adversarial Attack",
        description="Adversary tampers with unencrypted envelope routing headers (sender ID) while leaving ciphertext payload untouched.",
        target_construction="ADAPTIVE-BALANCED-V1",
        message_type="AIRCRAFT_STATUS",
        criticality="IMPORTANT",
        telemetry=TelemetryInput(
            message_type="AIRCRAFT_STATUS",
            criticality="IMPORTANT",
            criticality_rank=2,
            latency_budget_ms=5000.0,
            observed_packet_rate_hz=20.0,
            channel_bit_error_rate=0.0003,
            replay_attempt_count=0,
            auth_failure_count=0,
            integrity_failure_count=0,
            aad_tamper_count=0,
            transcript_anomaly_count=0,
            routing_error_count=0,
            prior_security_events_window=0,
            anomaly_score_raw=2.1,
            flight_phase="CRUISE",
            snr_db=27.0,
            packet_loss_pct=1.2,
        ),
        attack_type="AAD_TAMPER",
        expected_outcome="MESSAGE_REJECTED",
        key_takeaway="Cryptographic AAD binding binds message ID, sender ID, receiver ID, and construction ID into the AEAD tag.",
    ),
    "DEMO_08_REPLAY": DemonstrationScenarioDef(
        scenario_id="DEMO_08_REPLAY",
        name="Demo 8: Nonce-Based Replay Attack Defense",
        category="Adversarial Attack",
        description="Adversary captures a legitimate signed and encrypted flight packet and replays the exact envelope across the avionics databus.",
        target_construction="ADAPTIVE-STANDARD-V1",
        message_type="NAVIGATION_UPDATE",
        criticality="ROUTINE",
        telemetry=TelemetryInput(
            message_type="NAVIGATION_UPDATE",
            criticality="ROUTINE",
            criticality_rank=1,
            latency_budget_ms=5000.0,
            observed_packet_rate_hz=20.0,
            channel_bit_error_rate=0.0001,
            replay_attempt_count=0,
            auth_failure_count=0,
            integrity_failure_count=0,
            aad_tamper_count=0,
            transcript_anomaly_count=0,
            routing_error_count=0,
            prior_security_events_window=0,
            anomaly_score_raw=0.5,
            flight_phase="CRUISE",
            snr_db=32.0,
            packet_loss_pct=0.4,
        ),
        attack_type="REPLAY",
        expected_outcome="REPLAY_DETECTED_REJECTED",
        key_takeaway="Session maintains a deterministic sliding window / seen-nonces cache; replayed envelopes are rejected fail-closed.",
    ),
}


def list_demonstration_scenarios() -> list[dict[str, Any]]:
    """Return list of all demonstration scenarios."""
    return [s.to_dict() for s in DEMO_SCENARIOS.values()]


def get_demonstration_scenario(scenario_id: str) -> DemonstrationScenarioDef:
    """Retrieve specific demonstration scenario or raise ValueError."""
    if scenario_id not in DEMO_SCENARIOS:
        raise ValueError(f"Unknown demonstration scenario '{scenario_id}'. Available: {list(DEMO_SCENARIOS.keys())}")
    return DEMO_SCENARIOS[scenario_id]

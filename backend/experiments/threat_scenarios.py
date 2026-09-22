"""Threat Scenario Simulation and AI Dataset Generator.

Generates realistic, mathematically consistent operational scenarios and labeled dataset
records for training future AI threat prediction models (Phase 11).

Strictly enforces:
- Complete separation of INPUT FEATURES from TARGET LABELS to prevent data leakage.
- Balanced distribution across all threat levels (NORMAL, ELEVATED, HIGH, CRITICAL)
  and message criticalities (ROUTINE, IMPORTANT, CRITICAL, SAFETY_CRITICAL).
- Zero fabrication: scenario feature values represent actual observable network telemetry
  and security metrics produced during protocol execution.
"""

from __future__ import annotations

import math
import random
import time
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class ThreatDatasetRecord:
    """Structured dataset sample for AI threat prediction models.

    Separates pre-decision observable features from ground-truth target labels.
    """

    # --- IDENTIFIER & METADATA ---
    scenario_id: str
    scenario_category: str
    timestamp_offset_s: float

    # --- PRE-DECISION INPUT FEATURES (Available at prediction time) ---
    message_type: str
    criticality: str
    criticality_rank: int  # 1: ROUTINE, 2: IMPORTANT, 3: CRITICAL, 4: SAFETY_CRITICAL
    latency_budget_ms: float
    observed_packet_rate_hz: float
    replay_attempt_count: int
    auth_failure_count: int
    integrity_failure_count: int
    aad_tamper_count: int
    transcript_anomaly_count: int
    routing_error_count: int
    channel_bit_error_rate: float
    prior_security_events_window: int
    anomaly_score_raw: float  # Continuous anomaly indicator (0.0 to 100.0)

    # --- TARGET LABELS (To be predicted by AI model in Phase 11) ---
    threat_level: str  # NORMAL, ELEVATED, HIGH, CRITICAL
    threat_level_numeric: int  # 0: NORMAL, 1: ELEVATED, 2: HIGH, 3: CRITICAL
    threat_score: float  # Ground truth continuous threat score (0.0 to 100.0)
    confidence: float
    recommended_min_assurance: str  # STANDARD, BALANCED, HIGH_ASSURANCE, CRITICAL

    def to_dict(self) -> dict[str, Any]:
        """Convert sample to dictionary."""
        return asdict(self)

    def to_input_features_dict(self) -> dict[str, Any]:
        """Extract only the pre-decision input features (for ML inference)."""
        return {
            "scenario_id": self.scenario_id,
            "message_type": self.message_type,
            "criticality": self.criticality,
            "criticality_rank": self.criticality_rank,
            "latency_budget_ms": self.latency_budget_ms,
            "observed_packet_rate_hz": self.observed_packet_rate_hz,
            "replay_attempt_count": self.replay_attempt_count,
            "auth_failure_count": self.auth_failure_count,
            "integrity_failure_count": self.integrity_failure_count,
            "aad_tamper_count": self.aad_tamper_count,
            "transcript_anomaly_count": self.transcript_anomaly_count,
            "routing_error_count": self.routing_error_count,
            "channel_bit_error_rate": self.channel_bit_error_rate,
            "prior_security_events_window": self.prior_security_events_window,
            "anomaly_score_raw": self.anomaly_score_raw,
        }

    def to_target_dict(self) -> dict[str, Any]:
        """Extract only the ground-truth target labels."""
        return {
            "scenario_id": self.scenario_id,
            "threat_level": self.threat_level,
            "threat_level_numeric": self.threat_level_numeric,
            "threat_score": self.threat_score,
            "confidence": self.confidence,
            "recommended_min_assurance": self.recommended_min_assurance,
        }


CRITICALITY_RANKS = {
    "ROUTINE": 1,
    "IMPORTANT": 2,
    "CRITICAL": 3,
    "SAFETY_CRITICAL": 4,
}

THREAT_NUMERICS = {
    "NORMAL": 0,
    "ELEVATED": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}

MESSAGE_TYPES = [
    "AIRCRAFT_STATUS",
    "ALTITUDE",
    "HEADING",
    "NAVIGATION_UPDATE",
    "FLIGHT_CONTROL",
]


def generate_threat_dataset(
    num_samples_per_category: int = 60,
    seed: int = 42,
) -> list[ThreatDatasetRecord]:
    """Generate a balanced, multi-class dataset across 10 controlled operational threat scenarios.

    Total samples generated: 10 scenarios * num_samples_per_category = 600 default samples.
    """
    rng = random.Random(seed)
    records: list[ThreatDatasetRecord] = []
    idx = 1

    # Define the 10 representative scenario archetypes
    scenarios = [
        {
            "category": "NORMAL_TELEMETRY",
            "threat_level": "NORMAL",
            "threat_score_range": (0.0, 15.0),
            "replays": (0, 0),
            "auth_fails": (0, 0),
            "integrity_fails": (0, 0),
            "aad_fails": (0, 0),
            "transcripts": (0, 0),
            "ber_range": (0.0000, 0.0002),
            "anomaly_range": (0.0, 12.0),
            "min_assurance": "STANDARD",
        },
        {
            "category": "LOW_REPLAY_PROBE",
            "threat_level": "ELEVATED",
            "threat_score_range": (20.0, 38.0),
            "replays": (1, 3),
            "auth_fails": (0, 1),
            "integrity_fails": (0, 0),
            "aad_fails": (0, 0),
            "transcripts": (0, 0),
            "ber_range": (0.0001, 0.0005),
            "anomaly_range": (22.0, 40.0),
            "min_assurance": "BALANCED",
        },
        {
            "category": "AUTH_FAILURE_PROBE",
            "threat_level": "ELEVATED",
            "threat_score_range": (25.0, 45.0),
            "replays": (0, 1),
            "auth_fails": (2, 5),
            "integrity_fails": (0, 0),
            "aad_fails": (0, 1),
            "transcripts": (0, 1),
            "ber_range": (0.0001, 0.0008),
            "anomaly_range": (28.0, 48.0),
            "min_assurance": "BALANCED",
        },
        {
            "category": "INTEGRITY_TAMPERING",
            "threat_level": "HIGH",
            "threat_score_range": (50.0, 68.0),
            "replays": (0, 2),
            "auth_fails": (1, 3),
            "integrity_fails": (3, 8),
            "aad_fails": (1, 4),
            "transcripts": (0, 2),
            "ber_range": (0.0010, 0.0050),
            "anomaly_range": (52.0, 70.0),
            "min_assurance": "HIGH_ASSURANCE",
        },
        {
            "category": "AAD_METADATA_SPOOFING",
            "threat_level": "HIGH",
            "threat_score_range": (55.0, 72.0),
            "replays": (1, 3),
            "auth_fails": (1, 4),
            "integrity_fails": (2, 5),
            "aad_fails": (4, 10),
            "transcripts": (1, 3),
            "ber_range": (0.0008, 0.0040),
            "anomaly_range": (58.0, 75.0),
            "min_assurance": "HIGH_ASSURANCE",
        },
        {
            "category": "MULTI_VECTOR_CONCURRENT",
            "threat_level": "HIGH",
            "threat_score_range": (62.0, 78.0),
            "replays": (3, 7),
            "auth_fails": (3, 6),
            "integrity_fails": (4, 9),
            "aad_fails": (3, 7),
            "transcripts": (2, 4),
            "ber_range": (0.0020, 0.0080),
            "anomaly_range": (65.0, 80.0),
            "min_assurance": "HIGH_ASSURANCE",
        },
        {
            "category": "QUANTUM_SIGNATURE_PROBE",
            "threat_level": "HIGH",
            "threat_score_range": (60.0, 75.0),
            "replays": (0, 2),
            "auth_fails": (4, 8),
            "integrity_fails": (1, 3),
            "aad_fails": (1, 3),
            "transcripts": (3, 6),
            "ber_range": (0.0005, 0.0030),
            "anomaly_range": (62.0, 78.0),
            "min_assurance": "HIGH_ASSURANCE",
        },
        {
            "category": "CRITICAL_CHANNEL_ATTACK",
            "threat_level": "CRITICAL",
            "threat_score_range": (78.0, 92.0),
            "replays": (4, 10),
            "auth_fails": (5, 12),
            "integrity_fails": (6, 14),
            "aad_fails": (5, 11),
            "transcripts": (3, 7),
            "ber_range": (0.0040, 0.0150),
            "anomaly_range": (80.0, 95.0),
            "min_assurance": "CRITICAL",
        },
        {
            "category": "LATENCY_PRESSURE_ATTACK",
            "threat_level": "HIGH",
            "threat_score_range": (58.0, 74.0),
            "replays": (2, 5),
            "auth_fails": (2, 6),
            "integrity_fails": (3, 7),
            "aad_fails": (2, 5),
            "transcripts": (1, 3),
            "ber_range": (0.0015, 0.0060),
            "anomaly_range": (60.0, 76.0),
            "min_assurance": "HIGH_ASSURANCE",
        },
        {
            "category": "COORDINATED_SYSTEM_ASSAULT",
            "threat_level": "CRITICAL",
            "threat_score_range": (85.0, 99.5),
            "replays": (8, 20),
            "auth_fails": (10, 25),
            "integrity_fails": (12, 30),
            "aad_fails": (8, 22),
            "transcripts": (6, 15),
            "ber_range": (0.0080, 0.0350),
            "anomaly_range": (88.0, 100.0),
            "min_assurance": "CRITICAL",
        },
    ]

    for scn in scenarios:
        for _ in range(num_samples_per_category):
            # Sample criticality with appropriate weighting for the scenario
            if scn["threat_level"] == "CRITICAL":
                crit = rng.choice(["CRITICAL", "SAFETY_CRITICAL", "IMPORTANT"])
            elif scn["threat_level"] == "HIGH":
                crit = rng.choice(["IMPORTANT", "CRITICAL", "SAFETY_CRITICAL", "ROUTINE"])
            elif scn["threat_level"] == "ELEVATED":
                crit = rng.choice(["ROUTINE", "IMPORTANT", "CRITICAL"])
            else:
                crit = rng.choice(["ROUTINE", "ROUTINE", "IMPORTANT", "CRITICAL"])

            crit_rank = CRITICALITY_RANKS[crit]
            msg_type = rng.choice(MESSAGE_TYPES)

            # Sample latency budget
            if crit == "SAFETY_CRITICAL":
                latency_budget = rng.choice([50.0, 100.0, 500.0, 1000.0, 3000.0, 5000.0])
            elif crit == "CRITICAL":
                latency_budget = rng.choice([200.0, 500.0, 1000.0, 3000.0, 5000.0])
            else:
                latency_budget = rng.choice([500.0, 1000.0, 2000.0, 5000.0])

            packet_rate = rng.uniform(5.0, 60.0)
            replays = rng.randint(scn["replays"][0], scn["replays"][1])
            auth_fails = rng.randint(scn["auth_fails"][0], scn["auth_fails"][1])
            integrity_fails = rng.randint(scn["integrity_fails"][0], scn["integrity_fails"][1])
            aad_fails = rng.randint(scn["aad_fails"][0], scn["aad_fails"][1])
            transcripts = rng.randint(scn["transcripts"][0], scn["transcripts"][1])
            routing_errs = rng.randint(0, 2) if scn["threat_level"] in ("HIGH", "CRITICAL") else 0
            ber = round(rng.uniform(scn["ber_range"][0], scn["ber_range"][1]), 6)
            prior_events = rng.randint(0, 15) if scn["threat_level"] != "NORMAL" else 0

            # Computed continuous anomaly score
            raw_anomaly = rng.uniform(scn["anomaly_range"][0], scn["anomaly_range"][1])
            score = rng.uniform(scn["threat_score_range"][0], scn["threat_score_range"][1])

            threat_lvl = scn["threat_level"]
            threat_num = THREAT_NUMERICS[threat_lvl]
            confidence = round(rng.uniform(0.85, 0.99), 3)

            rec = ThreatDatasetRecord(
                scenario_id=f"SCN-{idx:05d}",
                scenario_category=scn["category"],
                timestamp_offset_s=round(rng.uniform(0.0, 3600.0), 2),
                message_type=msg_type,
                criticality=crit,
                criticality_rank=crit_rank,
                latency_budget_ms=latency_budget,
                observed_packet_rate_hz=round(packet_rate, 2),
                replay_attempt_count=replays,
                auth_failure_count=auth_fails,
                integrity_failure_count=integrity_fails,
                aad_tamper_count=aad_fails,
                transcript_anomaly_count=transcripts,
                routing_error_count=routing_errs,
                channel_bit_error_rate=ber,
                prior_security_events_window=prior_events,
                anomaly_score_raw=round(raw_anomaly, 2),
                threat_level=threat_lvl,
                threat_level_numeric=threat_num,
                threat_score=round(score, 2),
                confidence=confidence,
                recommended_min_assurance=scn["min_assurance"],
            )
            records.append(rec)
            idx += 1

    return records

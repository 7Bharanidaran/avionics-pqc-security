"""Standardized Evaluation Scenarios (S01 through S12).

Provides 12 reproducible, deterministically seeded operational scenarios for
evaluating static, rule-based, and AI-adaptive cryptographic architectures.
"""

from __future__ import annotations

import math
import random
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from backend.ai.schemas import TelemetryInput


@dataclass(frozen=True)
class EvalStepInput:
    """Input telemetry and context for a single evaluation step."""

    step_index: int
    timestamp_sec: float
    flight_phase: str
    message_type: str
    criticality: str
    latency_budget_ms: float
    telemetry: TelemetryInput
    ground_truth_threat_level: str
    ground_truth_threat_score: float
    is_attack_step: bool
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_index": self.step_index,
            "timestamp_sec": self.timestamp_sec,
            "flight_phase": self.flight_phase,
            "message_type": self.message_type,
            "criticality": self.criticality,
            "latency_budget_ms": self.latency_budget_ms,
            "telemetry": self.telemetry.model_dump(),
            "ground_truth_threat_level": self.ground_truth_threat_level,
            "ground_truth_threat_score": self.ground_truth_threat_score,
            "is_attack_step": self.is_attack_step,
            "description": self.description,
        }


@dataclass
class EvalScenario:
    """Complete evaluation scenario definition with deterministic step sequence."""

    scenario_id: str
    name: str
    category: str
    description: str
    primary_stress_target: str
    seed: int
    total_steps: int
    steps: list[EvalStepInput] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "primary_stress_target": self.primary_stress_target,
            "seed": self.seed,
            "total_steps": self.total_steps,
            "steps": [s.to_dict() for s in self.steps],
        }


# ==============================================================================
# SCENARIO GENERATORS (S01 - S12)
# ==============================================================================

def _gen_s01_normal(seed: int = 1001) -> EvalScenario:
    """S01_NORMAL: Routine steady cruise flight with nominal benign link."""
    rng = random.Random(seed)
    steps: list[EvalStepInput] = []
    num_steps = 20
    phases = ["GROUND_OPS", "CLIMB", "CRUISE", "CRUISE", "DESCENT", "APPROACH"]

    for i in range(num_steps):
        phase_idx = min(len(phases) - 1, int(i / (num_steps / len(phases))))
        phase = phases[phase_idx]
        t = i * 2.0
        msg_type = "AIRCRAFT_STATUS" if phase == "CRUISE" else "FLIGHT_PLAN"
        crit = "ROUTINE" if phase == "CRUISE" else "IMPORTANT"

        telem = TelemetryInput(
            message_type=msg_type,
            criticality=crit,
            criticality_rank=1 if crit == "ROUTINE" else 2,
            latency_budget_ms=5000.0,
            observed_packet_rate_hz=20.0 + rng.uniform(-1.5, 1.5),
            channel_bit_error_rate=0.0001 + rng.uniform(0.0, 0.00005),
            replay_attempt_count=0,
            auth_failure_count=0,
            integrity_failure_count=0,
            aad_tamper_count=0,
            transcript_anomaly_count=0,
            prior_security_events_window=0,
        )
        steps.append(
            EvalStepInput(
                step_index=i + 1,
                timestamp_sec=t,
                flight_phase=phase,
                message_type=msg_type,
                criticality=crit,
                latency_budget_ms=5000.0,
                telemetry=telem,
                ground_truth_threat_level="NORMAL",
                ground_truth_threat_score=8.5 + rng.uniform(-1.0, 2.0),
                is_attack_step=False,
                description=f"Nominal flight step {i+1} during {phase}",
            )
        )

    return EvalScenario(
        scenario_id="S01_NORMAL",
        name="S01: Normal Cruise Operation",
        category="NOMINAL",
        description="Nominal flight profile with pristine channel telemetry and routine messaging.",
        primary_stress_target="Verifies baseline energy efficiency and 0 false escalations.",
        seed=seed,
        total_steps=num_steps,
        steps=steps,
    )


def _gen_s02_elevated_threat(seed: int = 1002) -> EvalScenario:
    """S02_ELEVATED_THREAT: Mild channel noise, low-level authentication drops."""
    rng = random.Random(seed)
    steps: list[EvalStepInput] = []
    num_steps = 20

    for i in range(num_steps):
        t = i * 2.0
        is_elevated = (6 <= i <= 15)
        auth_fails = rng.randint(1, 3) if is_elevated else 0
        replays = rng.randint(1, 2) if is_elevated else 0

        telem = TelemetryInput(
            message_type="NAVIGATION_UPDATE",
            criticality="IMPORTANT",
            criticality_rank=2,
            latency_budget_ms=5000.0,
            observed_packet_rate_hz=30.0 + rng.uniform(2.0, 8.0),
            channel_bit_error_rate=0.0025 if is_elevated else 0.0003,
            replay_attempt_count=replays,
            auth_failure_count=auth_fails,
            integrity_failure_count=0,
            aad_tamper_count=0,
            transcript_anomaly_count=0,
            prior_security_events_window=replays + auth_fails,
        )
        gt_level = "ELEVATED" if is_elevated else "NORMAL"
        gt_score = 35.0 + rng.uniform(2.0, 8.0) if is_elevated else 12.0

        steps.append(
            EvalStepInput(
                step_index=i + 1,
                timestamp_sec=t,
                flight_phase="CRUISE",
                message_type="NAVIGATION_UPDATE",
                criticality="IMPORTANT",
                latency_budget_ms=5000.0,
                telemetry=telem,
                ground_truth_threat_level=gt_level,
                ground_truth_threat_score=gt_score,
                is_attack_step=is_elevated,
                description=f"Step {i+1}: {'Elevated noise and auth drops' if is_elevated else 'Nominal baseline'}",
            )
        )

    return EvalScenario(
        scenario_id="S02_ELEVATED_THREAT",
        name="S02: Elevated Threat & Noise",
        category="THREAT",
        description="Transient RF interference and low-level auth failures elevating threat score.",
        primary_stress_target="Evaluates smooth elevation to BALANCED construction without jitter.",
        seed=seed,
        total_steps=num_steps,
        steps=steps,
    )


def _gen_s03_high_threat(seed: int = 1003) -> EvalScenario:
    """S03_HIGH_THREAT: Severe replay burst and packet tampering."""
    rng = random.Random(seed)
    steps: list[EvalStepInput] = []
    num_steps = 20

    for i in range(num_steps):
        t = i * 2.0
        is_attack = (5 <= i <= 14)
        replays = rng.randint(8, 16) if is_attack else 0
        auth_fails = rng.randint(4, 9) if is_attack else 0
        integ_fails = rng.randint(2, 5) if is_attack else 0

        telem = TelemetryInput(
            message_type="FLIGHT_CONTROL",
            criticality="CRITICAL" if is_attack else "IMPORTANT",
            criticality_rank=3 if is_attack else 2,
            latency_budget_ms=5000.0,
            observed_packet_rate_hz=55.0 if is_attack else 25.0,
            channel_bit_error_rate=0.012 if is_attack else 0.0004,
            replay_attempt_count=replays,
            auth_failure_count=auth_fails,
            integrity_failure_count=integ_fails,
            aad_tamper_count=1 if is_attack else 0,
            transcript_anomaly_count=0,
            prior_security_events_window=replays + auth_fails + integ_fails,
        )
        gt_level = "HIGH" if is_attack else "NORMAL"
        gt_score = 72.0 + rng.uniform(0.0, 8.0) if is_attack else 10.0

        steps.append(
            EvalStepInput(
                step_index=i + 1,
                timestamp_sec=t,
                flight_phase="CRUISE",
                message_type="FLIGHT_CONTROL",
                criticality="CRITICAL" if is_attack else "IMPORTANT",
                latency_budget_ms=5000.0,
                telemetry=telem,
                ground_truth_threat_level=gt_level,
                ground_truth_threat_score=gt_score,
                is_attack_step=is_attack,
                description=f"Step {i+1}: {'Active replay & integrity attack' if is_attack else 'Nominal'}",
            )
        )

    return EvalScenario(
        scenario_id="S03_HIGH_THREAT",
        name="S03: High Threat Replay Attack",
        category="ATTACK",
        description="Aggressive replay injection and ciphertext tampering requiring High-Assurance PQC.",
        primary_stress_target="Immediate escalation to ADAPTIVE-HIGH-ASSURANCE-V1 within 1 step.",
        seed=seed,
        total_steps=num_steps,
        steps=steps,
    )


def _gen_s04_critical_threat(seed: int = 1004) -> EvalScenario:
    """S04_CRITICAL_THREAT: Man-in-the-Middle transcript modification and AAD forgery."""
    rng = random.Random(seed)
    steps: list[EvalStepInput] = []
    num_steps = 20

    for i in range(num_steps):
        t = i * 2.0
        is_mitm = (4 <= i <= 16)
        replays = rng.randint(12, 22) if is_mitm else 0
        auth_fails = rng.randint(8, 18) if is_mitm else 0
        integ_fails = rng.randint(6, 14) if is_mitm else 0
        aad_tampers = rng.randint(4, 10) if is_mitm else 0
        transcript_tampers = rng.randint(2, 6) if is_mitm else 0

        telem = TelemetryInput(
            message_type="FLIGHT_CONTROL",
            criticality="SAFETY_CRITICAL" if is_mitm else "IMPORTANT",
            criticality_rank=4 if is_mitm else 2,
            latency_budget_ms=5000.0,
            observed_packet_rate_hz=70.0 if is_mitm else 22.0,
            channel_bit_error_rate=0.030 if is_mitm else 0.0002,
            replay_attempt_count=replays,
            auth_failure_count=auth_fails,
            integrity_failure_count=integ_fails,
            aad_tamper_count=aad_tampers,
            transcript_anomaly_count=transcript_tampers,
            prior_security_events_window=replays + auth_fails + integ_fails + aad_tampers,
        )
        gt_level = "CRITICAL" if is_mitm else "NORMAL"
        gt_score = 94.0 + rng.uniform(0.0, 5.0) if is_mitm else 10.0

        steps.append(
            EvalStepInput(
                step_index=i + 1,
                timestamp_sec=t,
                flight_phase="APPROACH" if is_mitm else "CRUISE",
                message_type="FLIGHT_CONTROL",
                criticality="SAFETY_CRITICAL" if is_mitm else "IMPORTANT",
                latency_budget_ms=5000.0,
                telemetry=telem,
                ground_truth_threat_level=gt_level,
                ground_truth_threat_score=gt_score,
                is_attack_step=is_mitm,
                description=f"Step {i+1}: {'Active MITM and transcript tampering' if is_mitm else 'Nominal'}",
            )
        )

    return EvalScenario(
        scenario_id="S04_CRITICAL_THREAT",
        name="S04: Critical MITM & Transcript Tampering",
        category="ATTACK",
        description="Coordinated MITM attack attempting handshake transcript modification and AAD forgery.",
        primary_stress_target="Instant fail-closed escalation to ADAPTIVE-CRITICAL-V1 (Dual PQC).",
        seed=seed,
        total_steps=num_steps,
        steps=steps,
    )


def _gen_s05_threat_escalation(seed: int = 1005) -> EvalScenario:
    """S05_THREAT_ESCALATION: Progressive escalation NORMAL -> ELEVATED -> HIGH -> CRITICAL."""
    steps: list[EvalStepInput] = []
    num_steps = 20

    for i in range(num_steps):
        t = i * 2.0
        if i < 5:
            gt_lvl, gt_sc, crit, rep, auth, integ = "NORMAL", 10.0, "ROUTINE", 0, 0, 0
        elif i < 10:
            gt_lvl, gt_sc, crit, rep, auth, integ = "ELEVATED", 38.0, "IMPORTANT", 2, 2, 0
        elif i < 15:
            gt_lvl, gt_sc, crit, rep, auth, integ = "HIGH", 72.0, "CRITICAL", 8, 6, 3
        else:
            gt_lvl, gt_sc, crit, rep, auth, integ = "CRITICAL", 95.0, "SAFETY_CRITICAL", 16, 12, 8

        telem = TelemetryInput(
            message_type="FLIGHT_CONTROL" if i >= 10 else "NAVIGATION_UPDATE",
            criticality=crit,
            criticality_rank=1 if crit == "ROUTINE" else (2 if crit == "IMPORTANT" else (3 if crit == "CRITICAL" else 4)),
            latency_budget_ms=5000.0,
            observed_packet_rate_hz=20.0 + i * 2.5,
            channel_bit_error_rate=0.0002 + i * 0.0015,
            replay_attempt_count=rep,
            auth_failure_count=auth,
            integrity_failure_count=integ,
            aad_tamper_count=1 if i >= 15 else 0,
            transcript_anomaly_count=1 if i >= 15 else 0,
            prior_security_events_window=rep + auth + integ,
        )
        steps.append(
            EvalStepInput(
                step_index=i + 1,
                timestamp_sec=t,
                flight_phase="CRUISE",
                message_type="FLIGHT_CONTROL" if i >= 10 else "NAVIGATION_UPDATE",
                criticality=crit,
                latency_budget_ms=5000.0,
                telemetry=telem,
                ground_truth_threat_level=gt_lvl,
                ground_truth_threat_score=gt_sc,
                is_attack_step=(i >= 5),
                description=f"Step {i+1}: Escalation phase {gt_lvl}",
            )
        )

    return EvalScenario(
        scenario_id="S05_THREAT_ESCALATION",
        name="S05: Multi-Stage Threat Escalation",
        category="DYNAMIC",
        description="Stepwise escalation through all 4 threat levels (NORMAL -> ELEVATED -> HIGH -> CRITICAL).",
        primary_stress_target="Verifies 0-lag instant upward transition at each escalation boundary.",
        seed=seed,
        total_steps=num_steps,
        steps=steps,
    )


def _gen_s06_threat_recovery(seed: int = 1006) -> EvalScenario:
    """S06_THREAT_RECOVERY: Progressive recovery CRITICAL -> HIGH -> ELEVATED -> NORMAL with hysteresis hold."""
    steps: list[EvalStepInput] = []
    num_steps = 20

    for i in range(num_steps):
        t = i * 2.0
        if i < 4:
            gt_lvl, gt_sc, crit, rep, auth, integ = "CRITICAL", 92.0, "CRITICAL", 14, 10, 6
        elif i < 9:
            gt_lvl, gt_sc, crit, rep, auth, integ = "HIGH", 68.0, "CRITICAL", 6, 4, 2
        elif i < 14:
            gt_lvl, gt_sc, crit, rep, auth, integ = "ELEVATED", 35.0, "IMPORTANT", 1, 1, 0
        else:
            gt_lvl, gt_sc, crit, rep, auth, integ = "NORMAL", 10.0, "ROUTINE", 0, 0, 0

        telem = TelemetryInput(
            message_type="AIRCRAFT_STATUS" if i >= 14 else "NAVIGATION_UPDATE",
            criticality=crit,
            criticality_rank=1 if crit == "ROUTINE" else (2 if crit == "IMPORTANT" else 3),
            latency_budget_ms=5000.0,
            observed_packet_rate_hz=50.0 - i * 1.5,
            channel_bit_error_rate=max(0.0001, 0.020 - i * 0.0012),
            replay_attempt_count=rep,
            auth_failure_count=auth,
            integrity_failure_count=integ,
            aad_tamper_count=0,
            transcript_anomaly_count=0,
            prior_security_events_window=rep + auth + integ,
        )
        steps.append(
            EvalStepInput(
                step_index=i + 1,
                timestamp_sec=t,
                flight_phase="CRUISE",
                message_type="AIRCRAFT_STATUS" if i >= 14 else "NAVIGATION_UPDATE",
                criticality=crit,
                latency_budget_ms=5000.0,
                telemetry=telem,
                ground_truth_threat_level=gt_lvl,
                ground_truth_threat_score=gt_sc,
                is_attack_step=(i < 14),
                description=f"Step {i+1}: Recovery phase {gt_lvl}",
            )
        )

    return EvalScenario(
        scenario_id="S06_THREAT_RECOVERY",
        name="S06: Post-Attack Threat Recovery",
        category="DYNAMIC",
        description="Stepwise recovery from CRITICAL down to NORMAL, testing hysteresis dwell-time hold.",
        primary_stress_target="Verifies K=3 dwell hold on downgrades to prevent premature security drop.",
        seed=seed,
        total_steps=num_steps,
        steps=steps,
    )


def _gen_s07_low_confidence(seed: int = 1007) -> EvalScenario:
    """S07_LOW_CONFIDENCE: Out-of-distribution high-entropy telemetry with ambiguous signals."""
    rng = random.Random(seed)
    steps: list[EvalStepInput] = []
    num_steps = 20

    for i in range(num_steps):
        t = i * 2.0
        is_ood = (5 <= i <= 15)

        telem = TelemetryInput(
            message_type="NAVIGATION_UPDATE",
            criticality="IMPORTANT",
            criticality_rank=2,
            latency_budget_ms=5000.0,
            observed_packet_rate_hz=120.0 if is_ood else 25.0,
            channel_bit_error_rate=0.018 if is_ood else 0.0003,
            replay_attempt_count=3 if is_ood else 0,
            auth_failure_count=2 if is_ood else 0,
            integrity_failure_count=1 if is_ood else 0,
            aad_tamper_count=1 if is_ood else 0,
            transcript_anomaly_count=1 if is_ood else 0,
            prior_security_events_window=4 if is_ood else 0,
        )
        steps.append(
            EvalStepInput(
                step_index=i + 1,
                timestamp_sec=t,
                flight_phase="CRUISE",
                message_type="NAVIGATION_UPDATE",
                criticality="IMPORTANT",
                latency_budget_ms=5000.0,
                telemetry=telem,
                ground_truth_threat_level="ELEVATED" if is_ood else "NORMAL",
                ground_truth_threat_score=45.0 if is_ood else 10.0,
                is_attack_step=is_ood,
                description=f"Step {i+1}: {'Out-of-distribution ambiguous telemetry' if is_ood else 'Nominal'}",
            )
        )

    return EvalScenario(
        scenario_id="S07_LOW_CONFIDENCE",
        name="S07: Low Confidence & OOD Anomaly",
        category="ROBUSTNESS",
        description="High-entropy, unseen anomaly telemetry that causes probabilistic model uncertainty.",
        primary_stress_target="Verifies fallback to higher assurance when AI confidence is low (<0.50).",
        seed=seed,
        total_steps=num_steps,
        steps=steps,
    )


def _gen_s08_critical_msg_low_ai_score(seed: int = 1008) -> EvalScenario:
    """S08_CRITICAL_MESSAGE_LOW_AI_SCORE: Safety-critical command when AI predicts NORMAL threat."""
    steps: list[EvalStepInput] = []
    num_steps = 15

    for i in range(num_steps):
        t = i * 2.0
        is_critical_cmd = (5 <= i <= 10)
        crit = "SAFETY_CRITICAL" if is_critical_cmd else "ROUTINE"
        msg = "FLIGHT_CONTROL" if is_critical_cmd else "AIRCRAFT_STATUS"

        # Perfectly clean channel telemetry (AI will predict NORMAL threat)
        telem = TelemetryInput(
            message_type=msg,
            criticality=crit,
            criticality_rank=4 if is_critical_cmd else 1,
            latency_budget_ms=5000.0,
            observed_packet_rate_hz=20.0,
            channel_bit_error_rate=0.0001,
            replay_attempt_count=0,
            auth_failure_count=0,
            integrity_failure_count=0,
            aad_tamper_count=0,
            transcript_anomaly_count=0,
            prior_security_events_window=0,
        )
        steps.append(
            EvalStepInput(
                step_index=i + 1,
                timestamp_sec=t,
                flight_phase="DESCENT" if is_critical_cmd else "CRUISE",
                message_type=msg,
                criticality=crit,
                latency_budget_ms=5000.0,
                telemetry=telem,
                ground_truth_threat_level="NORMAL",
                ground_truth_threat_score=8.0,
                is_attack_step=False,
                description=f"Step {i+1}: {'Safety-critical command with benign telemetry' if is_critical_cmd else 'Routine status'}",
            )
        )

    return EvalScenario(
        scenario_id="S08_CRITICAL_MESSAGE_LOW_AI_SCORE",
        name="S08: Critical Message with Low AI Score",
        category="SAFETY",
        description="High-criticality avionics command sent under completely clean telemetry conditions.",
        primary_stress_target="Verifies that Safety Policy overrides AI recommendation to enforce maximum assurance.",
        seed=seed,
        total_steps=num_steps,
        steps=steps,
    )


def _gen_s09_downgrade_attempt(seed: int = 1009) -> EvalScenario:
    """S09_DOWNGRADE_ATTEMPT: Adversary manipulates telemetry to trick AI into recommending STANDARD."""
    steps: list[EvalStepInput] = []
    num_steps = 15

    for i in range(num_steps):
        t = i * 2.0
        # Critical flight plan update during active mission
        telem = TelemetryInput(
            message_type="FLIGHT_PLAN",
            criticality="CRITICAL",
            criticality_rank=3,
            latency_budget_ms=5000.0,
            observed_packet_rate_hz=10.0,  # Faked low rate
            channel_bit_error_rate=0.00001,  # Faked pristine BER
            replay_attempt_count=0,
            auth_failure_count=0,
            integrity_failure_count=0,
            aad_tamper_count=0,
            transcript_anomaly_count=0,
            prior_security_events_window=0,
        )
        steps.append(
            EvalStepInput(
                step_index=i + 1,
                timestamp_sec=t,
                flight_phase="CRUISE",
                message_type="FLIGHT_PLAN",
                criticality="CRITICAL",
                latency_budget_ms=5000.0,
                telemetry=telem,
                ground_truth_threat_level="NORMAL",
                ground_truth_threat_score=6.0,
                is_attack_step=True,
                description=f"Step {i+1}: Adversarial downgrade attempt on CRITICAL flight plan",
            )
        )

    return EvalScenario(
        scenario_id="S09_DOWNGRADE_ATTEMPT",
        name="S09: Adversarial Downgrade Attack",
        category="SAFETY",
        description="Adversary suppresses anomaly signals trying to force a cryptographic downgrade to STANDARD.",
        primary_stress_target="Verifies anti-downgrade safety policy blocks 100% of unauthorized downgrades.",
        seed=seed,
        total_steps=num_steps,
        steps=steps,
    )


def _gen_s10_telemetry_perturbation(seed: int = 1010) -> EvalScenario:
    """S10_TELEMETRY_PERTURBATION: Systematic noisy perturbations across all feature dimensions."""
    rng = random.Random(seed)
    steps: list[EvalStepInput] = []
    num_steps = 20

    for i in range(num_steps):
        t = i * 2.0
        noise_mult = 1.0 + math.sin(i * 0.8) * 0.7
        pkt_rate = max(5.0, 30.0 * noise_mult + rng.uniform(-4.0, 4.0))
        ber = max(0.00005, 0.005 * noise_mult)

        telem = TelemetryInput(
            message_type="NAVIGATION_UPDATE",
            criticality="IMPORTANT",
            criticality_rank=2,
            latency_budget_ms=5000.0,
            observed_packet_rate_hz=pkt_rate,
            channel_bit_error_rate=ber,
            replay_attempt_count=rng.randint(0, 3),
            auth_failure_count=rng.randint(0, 2),
            integrity_failure_count=0,
            aad_tamper_count=0,
            transcript_anomaly_count=0,
            prior_security_events_window=rng.randint(0, 4),
        )
        steps.append(
            EvalStepInput(
                step_index=i + 1,
                timestamp_sec=t,
                flight_phase="CRUISE",
                message_type="NAVIGATION_UPDATE",
                criticality="IMPORTANT",
                latency_budget_ms=5000.0,
                telemetry=telem,
                ground_truth_threat_level="ELEVATED" if noise_mult > 1.2 else "NORMAL",
                ground_truth_threat_score=25.0 * noise_mult,
                is_attack_step=(noise_mult > 1.2),
                description=f"Step {i+1}: Perturbation factor {noise_mult:.2f}x",
            )
        )

    return EvalScenario(
        scenario_id="S10_TELEMETRY_PERTURBATION",
        name="S10: Systematic Telemetry Perturbation",
        category="ROBUSTNESS",
        description="Sinusoidal perturbation of packet rates and BER to test model stability.",
        primary_stress_target="Verifies smooth threat scoring without sporadic discontinuous jumps.",
        seed=seed,
        total_steps=num_steps,
        steps=steps,
    )


def _gen_s11_rapid_threat_oscillation(seed: int = 1011) -> EvalScenario:
    """S11_RAPID_THREAT_OSCILLATION: Alternating attack/benign steps testing anti-thrashing."""
    steps: list[EvalStepInput] = []
    num_steps = 20

    for i in range(num_steps):
        t = i * 2.0
        is_spike = (i % 2 == 1)

        telem = TelemetryInput(
            message_type="NAVIGATION_UPDATE",
            criticality="IMPORTANT",
            criticality_rank=2,
            latency_budget_ms=5000.0,
            observed_packet_rate_hz=60.0 if is_spike else 20.0,
            channel_bit_error_rate=0.015 if is_spike else 0.0002,
            replay_attempt_count=6 if is_spike else 0,
            auth_failure_count=4 if is_spike else 0,
            integrity_failure_count=2 if is_spike else 0,
            aad_tamper_count=0,
            transcript_anomaly_count=0,
            prior_security_events_window=8 if is_spike else 0,
        )
        steps.append(
            EvalStepInput(
                step_index=i + 1,
                timestamp_sec=t,
                flight_phase="CRUISE",
                message_type="NAVIGATION_UPDATE",
                criticality="IMPORTANT",
                latency_budget_ms=5000.0,
                telemetry=telem,
                ground_truth_threat_level="HIGH" if is_spike else "NORMAL",
                ground_truth_threat_score=75.0 if is_spike else 10.0,
                is_attack_step=is_spike,
                description=f"Step {i+1}: {'Spike ON' if is_spike else 'Spike OFF'}",
            )
        )

    return EvalScenario(
        scenario_id="S11_RAPID_THREAT_OSCILLATION",
        name="S11: Rapid Threat Oscillation & Anti-Thrashing",
        category="DYNAMIC",
        description="Alternating step spikes between HIGH and NORMAL to evaluate hysteresis stability.",
        primary_stress_target="Evaluates elimination of ping-pong transitions (reducing switches by >70%).",
        seed=seed,
        total_steps=num_steps,
        steps=steps,
    )


def _gen_s12_combined_threat(seed: int = 1012) -> EvalScenario:
    """S12_COMBINED_THREAT: Full mission profile with nominal cruise, multi-threat attack, emergency, and recovery."""
    rng = random.Random(seed)
    steps: list[EvalStepInput] = []
    num_steps = 30

    for i in range(num_steps):
        t = i * 2.0
        if i < 6:
            phase, msg, crit, rep, auth, integ, aad, sc = "CRUISE", "AIRCRAFT_STATUS", "ROUTINE", 0, 0, 0, 0, 8.0
        elif i < 14:
            phase, msg, crit, rep, auth, integ, aad, sc = "CRUISE", "NAVIGATION_UPDATE", "CRITICAL", 10, 6, 3, 1, 74.0
        elif i < 20:
            phase, msg, crit, rep, auth, integ, aad, sc = "DESCENT", "FLIGHT_CONTROL", "SAFETY_CRITICAL", 18, 14, 8, 4, 96.0
        elif i < 26:
            phase, msg, crit, rep, auth, integ, aad, sc = "APPROACH", "FLIGHT_PLAN", "IMPORTANT", 2, 1, 0, 0, 32.0
        else:
            phase, msg, crit, rep, auth, integ, aad, sc = "LANDING", "AIRCRAFT_STATUS", "ROUTINE", 0, 0, 0, 0, 9.0

        telem = TelemetryInput(
            message_type=msg,
            criticality=crit,
            criticality_rank=1 if crit == "ROUTINE" else (2 if crit == "IMPORTANT" else (3 if crit == "CRITICAL" else 4)),
            latency_budget_ms=5000.0,
            observed_packet_rate_hz=25.0 + rng.uniform(-2.0, 2.0) if i < 6 or i >= 26 else 65.0,
            channel_bit_error_rate=0.0001 if i < 6 or i >= 26 else (0.025 if i < 20 else 0.003),
            replay_attempt_count=rep,
            auth_failure_count=auth,
            integrity_failure_count=integ,
            aad_tamper_count=aad,
            transcript_anomaly_count=1 if aad > 0 else 0,
            prior_security_events_window=rep + auth + integ + aad,
        )
        steps.append(
            EvalStepInput(
                step_index=i + 1,
                timestamp_sec=t,
                flight_phase=phase,
                message_type=msg,
                criticality=crit,
                latency_budget_ms=5000.0,
                telemetry=telem,
                ground_truth_threat_level="CRITICAL" if sc > 85 else ("HIGH" if sc > 60 else ("ELEVATED" if sc > 25 else "NORMAL")),
                ground_truth_threat_score=sc,
                is_attack_step=(6 <= i < 26),
                description=f"Step {i+1}: Mission phase {phase} ({crit})",
            )
        )

    return EvalScenario(
        scenario_id="S12_COMBINED_THREAT",
        name="S12: Full Mission Combined Threat Lifecycle",
        category="MISSION",
        description="Comprehensive 30-step mission: nominal cruise -> EW attack -> emergency descent -> recovery -> landing.",
        primary_stress_target="End-to-end multi-phase validation under combined operational and cyber stressors.",
        seed=seed,
        total_steps=num_steps,
        steps=steps,
    )


EVAL_SCENARIOS: dict[str, Callable[[int], EvalScenario]] = {
    "S01_NORMAL": _gen_s01_normal,
    "S02_ELEVATED_THREAT": _gen_s02_elevated_threat,
    "S03_HIGH_THREAT": _gen_s03_high_threat,
    "S04_CRITICAL_THREAT": _gen_s04_critical_threat,
    "S05_THREAT_ESCALATION": _gen_s05_threat_escalation,
    "S06_THREAT_RECOVERY": _gen_s06_threat_recovery,
    "S07_LOW_CONFIDENCE": _gen_s07_low_confidence,
    "S08_CRITICAL_MESSAGE_LOW_AI_SCORE": _gen_s08_critical_msg_low_ai_score,
    "S09_DOWNGRADE_ATTEMPT": _gen_s09_downgrade_attempt,
    "S10_TELEMETRY_PERTURBATION": _gen_s10_telemetry_perturbation,
    "S11_RAPID_THREAT_OSCILLATION": _gen_s11_rapid_threat_oscillation,
    "S12_COMBINED_THREAT": _gen_s12_combined_threat,
}


def get_scenario(scenario_id: str, seed: int | None = None) -> EvalScenario:
    """Instantiate a standardized evaluation scenario by ID."""
    gen = EVAL_SCENARIOS.get(scenario_id)
    if gen is None:
        valid = ", ".join(EVAL_SCENARIOS.keys())
        raise ValueError(f"Unknown scenario ID '{scenario_id}'. Supported: {valid}")
    return gen(seed) if seed is not None else gen()


def list_scenarios() -> list[dict[str, Any]]:
    """Return summary metadata for all 12 standardized evaluation scenarios."""
    summaries = []
    for scn_id, gen_fn in EVAL_SCENARIOS.items():
        scn = gen_fn()
        summaries.append({
            "scenario_id": scn.scenario_id,
            "name": scn.name,
            "category": scn.category,
            "description": scn.description,
            "primary_stress_target": scn.primary_stress_target,
            "total_steps": scn.total_steps,
            "seed": scn.seed,
        })
    return summaries

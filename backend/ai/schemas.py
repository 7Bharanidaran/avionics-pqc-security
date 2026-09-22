"""Pydantic Schemas for AI Threat Prediction Subsystem (Phase 11).

Defines strict schemas for input telemetry, threat prediction output,
explainability signals, and integrated policy evaluations.
"""

from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field, model_validator


class ThreatLevelEnum(str, Enum):
    NORMAL = "NORMAL"
    ELEVATED = "ELEVATED"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FeatureContribution(BaseModel):
    """Local explanation of a single feature's contribution to the threat prediction."""

    model_config = ConfigDict(extra="ignore")

    feature_name: str = Field(..., description="Name of the contributing feature")
    display_name: str = Field(..., description="Human-readable feature description")
    raw_value: float = Field(..., description="Observed input value")
    importance_weight: float = Field(..., description="Global feature importance weight")
    contribution_score: float = Field(..., description="Estimated directional contribution to threat score")
    interpretation: str = Field(..., description="Risk directional interpretation (e.g., HIGH_RISK, NORMAL)")


class TelemetryInput(BaseModel):
    """Input telemetry and security event metrics for Phase 11 AI threat prediction.

    Supports both dataset-native metrics and operational network aliases.
    Strictly accepts pre-decision features only (zero cryptographic secrets).
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    # Core categorical fields
    message_type: str = Field(default="AIRCRAFT_STATUS", description="Avionics message type")
    criticality: str = Field(default="ROUTINE", description="Message criticality (ROUTINE, IMPORTANT, CRITICAL, SAFETY_CRITICAL)")
    criticality_rank: int = Field(default=1, ge=1, le=4, description="Ordinal criticality rank (1 to 4)")

    # Channel & Timing Metrics
    latency_budget_ms: float = Field(default=1000.0, gt=0.0, description="Operation deadline in milliseconds")
    observed_packet_rate_hz: float = Field(default=30.0, ge=0.0, description="Observed message rate in Hz")
    channel_bit_error_rate: float = Field(default=0.0001, ge=0.0, le=1.0, description="Link bit error rate")

    # Security Anomaly Counters (Time-windowed)
    replay_attempt_count: int = Field(default=0, ge=0, description="Replay attempts detected in window")
    auth_failure_count: int = Field(default=0, ge=0, description="Authentication / signature failures in window")
    integrity_failure_count: int = Field(default=0, ge=0, description="Ciphertext / auth tag integrity failures")
    aad_tamper_count: int = Field(default=0, ge=0, description="Additional Authenticated Data mismatch count")
    transcript_anomaly_count: int = Field(default=0, ge=0, description="Handshake transcript binding anomalies")
    routing_error_count: int = Field(default=0, ge=0, description="Unauthorized component routing errors")
    prior_security_events_window: int = Field(default=0, ge=0, description="Historical security events in window")
    anomaly_score_raw: float = Field(default=0.0, ge=0.0, le=100.0, description="Aggregated raw anomaly indicator")

    # Optional RF / Aerospace aliases for flexibility
    snr_db: float | None = Field(default=None, description="Signal-to-noise ratio in dB (optional alias)")
    packet_loss_pct: float | None = Field(default=None, description="Packet loss percentage (optional alias)")
    retransmit_rate: float | None = Field(default=None, description="Retransmit rate (optional alias)")
    link_flaps_5m: int | None = Field(default=None, description="Link flap count in 5 min (optional alias)")
    auth_failures_5m: int | None = Field(default=None, description="Auth failures in 5 min (optional alias)")
    replay_window_drops_5m: int | None = Field(default=None, description="Replay drops in 5 min (optional alias)")
    duplicate_messages_5m: int | None = Field(default=None, description="Duplicate messages in 5 min (optional alias)")
    protocol_violations_5m: int | None = Field(default=None, description="Protocol violations in 5 min (optional alias)")
    downgrade_attempts_5m: int | None = Field(default=None, description="Downgrade attempts in 5 min (optional alias)")
    known_spoofed_sources_5m: int | None = Field(default=None, description="Known spoofed sources in 5 min (optional alias)")
    flight_phase: str | None = Field(default=None, description="Flight phase (optional alias)")
    active_rf_band: str | None = Field(default=None, description="Active RF band (optional alias)")
    peer_entity_type: str | None = Field(default=None, description="Peer entity type (optional alias)")
    traffic_density_sector: int | None = Field(default=None, description="Airspace traffic density (optional alias)")

    @model_validator(mode="before")
    @classmethod
    def map_aliases_if_provided(cls, data: Any) -> Any:
        """Map alternative telemetry names to core dataset feature fields."""
        if not isinstance(data, dict):
            return data
        d = dict(data)
        if "auth_failures_5m" in d and "auth_failure_count" not in d:
            d["auth_failure_count"] = int(d["auth_failures_5m"])
        if "replay_window_drops_5m" in d and "replay_attempt_count" not in d:
            d["replay_attempt_count"] = int(d["replay_window_drops_5m"])
        if "protocol_violations_5m" in d and "transcript_anomaly_count" not in d:
            d["transcript_anomaly_count"] = int(d["protocol_violations_5m"])
        if "downgrade_attempts_5m" in d and "aad_tamper_count" not in d:
            d["aad_tamper_count"] = int(d["downgrade_attempts_5m"])
        if "known_spoofed_sources_5m" in d and "routing_error_count" not in d:
            d["routing_error_count"] = int(d["known_spoofed_sources_5m"])
        if "packet_loss_pct" in d and "channel_bit_error_rate" not in d:
            d["channel_bit_error_rate"] = float(d["packet_loss_pct"]) / 1000.0
        if "criticality" in d and "criticality_rank" not in d:
            crit = str(d["criticality"]).upper()
            rank_map = {"ROUTINE": 1, "IMPORTANT": 2, "CRITICAL": 3, "SAFETY_CRITICAL": 4}
            d["criticality_rank"] = rank_map.get(crit, 1)
        return d


class ThreatPredictionResult(BaseModel):
    """Output prediction produced by the Phase 11 AI Threat Predictor."""

    model_config = ConfigDict(extra="ignore")

    threat_level: str = Field(..., description="Predicted discrete threat tier (NORMAL, ELEVATED, HIGH, CRITICAL)")
    threat_level_numeric: int = Field(..., ge=0, le=3, description="Integer encoded threat level (0=NORMAL, 3=CRITICAL)")
    threat_score: float = Field(..., ge=0.0, le=100.0, description="Predicted continuous threat score (0.0 to 100.0)")
    normalized_threat_score: float = Field(..., ge=0.0, le=1.0, description="Normalized continuous threat score (0.0 to 1.0)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Prediction certainty derived from model probabilities")
    probabilities: dict[str, float] = Field(..., description="Class probability distribution across threat tiers")
    model_version: str = Field(default="1.0.0", description="Active AI model identifier")
    advisory_only: bool = Field(default=True, description="Enforces DO-178C safety advisory non-authoritative status")
    explanation: list[FeatureContribution] = Field(default_factory=list, description="Top contributing feature signals")


class AIEvaluationRequest(BaseModel):
    """Request payload for integrated AI Threat Prediction + Policy Engine evaluation."""

    model_config = ConfigDict(extra="ignore")

    telemetry: TelemetryInput = Field(..., description="Observed link telemetry and anomaly metrics")
    criticality: str = Field(default="ROUTINE", description="Message criticality level")
    latency_budget_ms: float = Field(default=1000.0, gt=0.0, description="Strict deadline in ms")


class AIEvaluationResponse(BaseModel):
    """Response payload showing both AI Advisory and Final Deterministic Decision."""

    model_config = ConfigDict(extra="ignore")

    ai_prediction: ThreatPredictionResult = Field(..., description="AI-generated threat advisory")
    policy_decision: dict[str, Any] = Field(..., description="Final deterministic safety policy decision")
    safety_override_triggered: bool = Field(..., description="Whether deterministic policy overrode the AI threat advisory")
    confidence_status: str = Field(..., description="Status of prediction confidence (HIGH_CONFIDENCE, MODERATE, LOW_CONFIDENCE_FALLBACK)")
    selected_construction: str = Field(..., description="Final chosen adaptive cryptographic construction")
    status: str = Field(default="APPROVED", description="Policy evaluation outcome status")


class ModelMetadataResponse(BaseModel):
    """Full AI metadata, training parameters, and comparative benchmark results."""

    model_config = ConfigDict(extra="ignore")

    model_name: str
    version: str
    training_timestamp: str
    dataset_version: str
    dataset_size: int
    feature_count: int
    features: list[str]
    target_variables: list[str]
    best_classifier: str
    best_regressor: str
    test_metrics: dict[str, Any]
    feature_importances: dict[str, float]
    confusion_matrix: list[list[int]] = Field(default_factory=list)
    classes: list[str] = Field(default_factory=lambda: ["NORMAL", "ELEVATED", "HIGH", "CRITICAL"])
    random_seed: int = 42
    safety_invariants: list[str] = Field(default_factory=list)


class ForecastRequest(BaseModel):
    """Request payload for multi-horizon temporal threat forecasting."""

    model_config = ConfigDict(extra="ignore")

    telemetry_history: list[TelemetryInput] = Field(default_factory=list, description="Historical sequence of telemetry inputs")
    recent_threat_scores: list[float] = Field(default_factory=list, description="Historical sequence of threat scores")
    lookahead_horizons: list[int] = Field(default_factory=lambda: [5, 10, 15], description="Lookahead steps in future")


"""Pydantic schemas for Avionics PQC Security Lab API."""

from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, Field


# =====================================================================
# Health Schemas
# =====================================================================


class HealthResponse(BaseModel):
    """Health check response schema."""

    status: str = Field(default="healthy", description="Service health status")
    service: str = Field(default="Avionics PQC Security Lab", description="Service name")
    api_version: str = Field(default="1.0", description="API version")


# =====================================================================
# Avionics Schemas
# =====================================================================


class AvionicsEntityResponse(BaseModel):
    """Public metadata of an avionics entity."""

    id: str = Field(..., description="Unique component ID")
    name: str = Field(..., description="Human-readable component name")
    role: str = Field(..., description="Role in simulated aerospace architecture")
    component_type: str = Field(..., description="Component classification")
    aircraft_id: Optional[str] = Field(None, description="Associated aircraft ID if airborne")
    status: str = Field(default="ACTIVE", description="Operational status")
    public_keys: dict[str, str] = Field(
        default_factory=dict,
        description="Public identity keys in hex encoding (NO private keys)",
    )


class AvionicsListResponse(BaseModel):
    """List of all simulated avionics entities."""

    entities: list[AvionicsEntityResponse]


# =====================================================================
# Protocol & Handshake Schemas
# =====================================================================


class HandshakeRequest(BaseModel):
    """Request payload to initiate a secure hybrid handshake."""

    initiator: str = Field(default="FCC", description="Initiator entity ID or alias (e.g. 'FCC', 'AIRCRAFT-001-FCC')")
    responder: str = Field(default="NAV", description="Responder entity ID or alias (e.g. 'NAV', 'AIRCRAFT-001-NAV')")
    mlkem_param: str = Field(default="ML-KEM-1024", description="ML-KEM parameter set")
    slhdsa_param: str = Field(default="shake_128f", description="SLH-DSA parameter set")


class HandshakeResponse(BaseModel):
    """Safe public summary of an established secure handshake."""

    status: str = Field(..., description="Handshake state (e.g. 'established')")
    initiator: str = Field(..., description="Initiator component ID")
    responder: str = Field(..., description="Responder component ID")
    session_id: str = Field(..., description="Unique deterministic session ID")
    key_exchange: list[str] = Field(..., description="Negotiated KEX algorithms")
    authentication: list[str] = Field(..., description="Negotiated signature algorithms")
    key_derivation: str = Field(..., description="KDF algorithm")
    encryption: str = Field(..., description="Symmetric AEAD cipher")
    established_at: float = Field(..., description="Epoch timestamp of session establishment")


class MessageSendRequest(BaseModel):
    """Request payload to send an encrypted avionics message."""

    sender: str = Field(..., description="Sender entity ID or alias")
    receiver: str = Field(..., description="Receiver entity ID or alias")
    message_type: str = Field(default="AIRCRAFT_STATUS", description="Avionics message type")
    payload: dict[str, Any] = Field(default_factory=dict, description="Structured message payload")


class MessageSendResponse(BaseModel):
    """Response payload after successful encryption, transport, and decryption."""

    status: str = Field(default="accepted", description="Processing status")
    sender: str = Field(..., description="Sender component ID")
    receiver: str = Field(..., description="Receiver component ID")
    message_id: str = Field(..., description="Unique message UUID")
    message_type: str = Field(..., description="Message classification")
    secure: bool = Field(default=True, description="True if end-to-end AEAD encryption verified")
    payload: dict[str, Any] = Field(default_factory=dict, description="Decrypted message payload")
    display_text: str = Field(..., description="Formatted message display string")


# =====================================================================
# Security & Attack Schemas
# =====================================================================


class AttackItem(BaseModel):
    """Individual security attack result item."""

    attack_id: str
    attack_name: str
    description: str
    target: str
    expected_behavior: str
    actual_behavior: str
    detected: bool
    status: str
    timestamp: float


class AttacksListResponse(BaseModel):
    """Aggregated security validation report."""

    overall_status: str
    baseline_passed: bool
    total_attacks: int
    attacks_detected: int
    attacks_not_detected: int
    attacks: list[AttackItem]


class SimulateAttackRequest(BaseModel):
    """Request to trigger a specific attack simulation."""

    attack: str = Field(..., description="Attack identifier name (e.g. 'ciphertext_tampering')")


class SimulateAttackResponse(BaseModel):
    """Result of a triggered attack simulation."""

    attack: str
    attack_id: str
    attack_name: str
    detected: bool
    status: str
    expected_behavior: str
    actual_behavior: str
    description: str


# =====================================================================
# Benchmark Schemas
# =====================================================================


class BenchmarkSummaryResponse(BaseModel):
    """Dashboard-friendly summary of benchmark results."""

    timestamp: str
    environment: dict[str, Any]
    cryptographic_operations: list[dict[str, Any]]
    handshake_latency: dict[str, Any]
    symmetric_encryption: list[dict[str, Any]]
    size_measurements: list[dict[str, Any]]
    classical_vs_hybrid: dict[str, Any]


# =====================================================================
# Adaptive Policy Schemas
# =====================================================================


class PolicyEvaluateRequest(BaseModel):
    """Safety-constrained profile evaluation input."""
    message_type: str = Field(..., min_length=1, max_length=100)
    criticality: str = Field(..., description="ROUTINE, IMPORTANT, CRITICAL, or SAFETY_CRITICAL")
    threat_level: str = Field(..., description="NORMAL, ELEVATED, HIGH, or CRITICAL")
    latency_budget_ms: float = Field(..., gt=0, le=600000)


class PolicyConstraintResponse(BaseModel):
    name: str
    passed: bool
    detail: str


class PolicyDecisionResponse(BaseModel):
    status: str
    selected_profile: Optional[str]
    assurance_level: Optional[str]
    estimated_latency_ms: Optional[float]
    latency_budget_ms: float
    criticality: Optional[str]
    threat_level: Optional[str]
    score: Optional[float]
    reason: str
    constraints: list[PolicyConstraintResponse]
    downgrade_allowed: bool
    downgrade_blocked: bool
    decision_time_ms: float
    benchmark_source: str


class PolicyProfileResponse(BaseModel):
    profile_id: str
    assurance_level: str
    key_agreement: str
    kem: str
    authentication: str
    aead: str
    allowed_criticality: list[str]
    maximum_threat: str
    downgrade_allowed: bool
    measured_latency_ms: Optional[float]


class PolicyRulesResponse(BaseModel):
    criticality_minimum_assurance: dict[str, str]
    threat_minimum_assurance: dict[str, str]
    scoring_weights: dict[str, float]
    safety_rules: list[str]


class PolicyMetricsResponse(BaseModel):
    scope: str
    total_evaluations: int
    successful_selections: int
    constraint_conflicts: int
    blocked_downgrades: int
    average_decision_time_ms: float


# =====================================================================
# Adaptive Cryptographic Constructions Schemas
# =====================================================================


class AdaptiveConstructionMetadataResponse(BaseModel):
    """Metadata response schema for an adaptive cryptographic construction."""

    construction_id: str
    security_level: str
    description: str
    primitives: dict[str, Any]
    constraints: dict[str, bool]
    target_latency_budget_ms: float
    allowed_criticalities: list[str]
    allowed_threat_levels: list[str]


class AdaptiveConstructionSelectRequest(BaseModel):
    """Request payload for deterministic construction selection."""

    criticality: str = Field(default="ROUTINE", description="Message criticality (ROUTINE, IMPORTANT, CRITICAL, SAFETY_CRITICAL)")
    threat_level: str = Field(default="NORMAL", description="Threat level (NORMAL, ELEVATED, HIGH, CRITICAL)")
    threat_score: Optional[float] = Field(None, description="Continuous threat score (0-100 or 0.0-1.0)")
    latency_budget_ms: float = Field(default=5000.0, description="Latency budget in milliseconds")


class AdaptiveConstructionDecisionResponse(BaseModel):
    """Response payload representing a construction selection decision and safety audit."""

    status: str
    selected_construction_id: Optional[str]
    security_level: Optional[str]
    criticality: str
    threat_level: str
    threat_score: Optional[float]
    latency_budget_ms: float
    estimated_latency_ms: Optional[float]
    reason: str
    constraints: list[PolicyConstraintResponse]
    downgrade_blocked: bool
    decision_time_ms: float


class AdaptiveHandshakeRequest(BaseModel):
    """Request payload to execute an adaptive cryptographic handshake between two avionics entities."""

    initiator: str = Field(default="FCC", description="Initiator entity ID or alias (e.g. 'FCC', 'AIRCRAFT-001-FCC')")
    responder: str = Field(default="GCS", description="Responder entity ID or alias (e.g. 'GCS', 'GROUND-STATION-001')")
    construction_id: Optional[str] = Field(None, description="Explicit construction override (e.g. 'ADAPTIVE-HIGH-ASSURANCE-V1')")
    criticality: str = Field(default="ROUTINE", description="Traffic criticality")
    threat_level: str = Field(default="NORMAL", description="Operational threat level")
    threat_score: Optional[float] = Field(None, description="Threat score")
    latency_budget_ms: float = Field(default=5000.0, description="Latency budget in milliseconds")


class AdaptiveHandshakeResponse(BaseModel):
    """Response payload containing established session details, audit trace, and selection rationale."""

    status: str
    session_id: str
    construction_id: str
    security_level: str
    initiator_id: str
    responder_id: str
    negotiated_algorithms: dict[str, Any]
    trace: list[dict[str, str]]
    decision: AdaptiveConstructionDecisionResponse
    handshake_time_ms: float


class AdaptiveMessageRequest(BaseModel):
    """Request payload to transmit an authenticated message over an active adaptive session."""

    sender: str = Field(default="FCC", description="Sender entity alias")
    receiver: str = Field(default="GCS", description="Receiver entity alias")
    session_id: str = Field(..., description="Active session ID")
    construction_id: str = Field(..., description="Construction ID")
    message_type: str = Field(default="AIRCRAFT_STATUS", description="Avionics message type")
    payload: dict[str, Any] = Field(default_factory=dict, description="Arbitrary message telemetry/command payload")


class AdaptiveMessageResponse(BaseModel):
    """Response payload containing encrypted envelope metrics and decrypted telemetry verification."""

    status: str
    message_id: str
    session_id: str
    construction_id: str
    envelope: dict[str, Any]
    decrypted_payload: dict[str, Any]
    encryption_time_ms: float
    decryption_time_ms: float


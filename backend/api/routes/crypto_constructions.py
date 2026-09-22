"""API routes for Project-Specific Adaptive Cryptographic Constructions."""

from __future__ import annotations

import time
from typing import Any
from fastapi import APIRouter, HTTPException

from backend.api.routes.avionics import resolve_entity
from backend.api.schemas import (
    AdaptiveConstructionDecisionResponse,
    AdaptiveConstructionMetadataResponse,
    AdaptiveConstructionSelectRequest,
    AdaptiveHandshakeRequest,
    AdaptiveHandshakeResponse,
    AdaptiveMessageRequest,
    AdaptiveMessageResponse,
    PolicyConstraintResponse,
)
from backend.avionics.messages import AvionicsMessage, MessageType
from backend.crypto import (
    CONSTRUCTION_ENGINE,
    AdaptiveSession,
    ConstructionError,
)

router = APIRouter(prefix="/crypto", tags=["Adaptive Constructions"])

# In-memory session cache for active adaptive construction sessions
_ADAPTIVE_SESSIONS: dict[str, tuple[AdaptiveSession, AdaptiveSession]] = {}


@router.get("/constructions", response_model=list[AdaptiveConstructionMetadataResponse])
def get_adaptive_constructions() -> list[AdaptiveConstructionMetadataResponse]:
    """Return public metadata and cryptographic primitives for all 4 adaptive constructions."""
    metadata_list = CONSTRUCTION_ENGINE.list_constructions()
    return [
        AdaptiveConstructionMetadataResponse(
            construction_id=m.construction_id,
            security_level=m.security_level.value,
            description=m.description,
            primitives={
                "key_agreement": [m.kex_classical, m.kex_pqc],
                "kdf": m.kdf_algorithm,
                "kdf_domain": m.kdf_domain_info,
                "authentication": [m.auth_classical] + ([m.auth_pqc] if m.auth_pqc else []),
                "aead": m.aead,
            },
            constraints={
                "downgrade_protection": m.downgrade_protection,
                "replay_protection": m.replay_protection,
                "transcript_binding": m.transcript_binding,
                "fail_closed": m.fail_closed,
            },
            target_latency_budget_ms=m.target_latency_budget_ms,
            allowed_criticalities=list(m.allowed_criticalities),
            allowed_threat_levels=list(m.allowed_threat_levels),
        )
        for m in metadata_list
    ]


@router.get("/constructions/{construction_id}", response_model=AdaptiveConstructionMetadataResponse)
def get_construction_by_id(construction_id: str) -> AdaptiveConstructionMetadataResponse:
    """Retrieve metadata for a specific adaptive construction."""
    try:
        construction = CONSTRUCTION_ENGINE.get_construction(construction_id)
        m = construction.metadata
        return AdaptiveConstructionMetadataResponse(
            construction_id=m.construction_id,
            security_level=m.security_level.value,
            description=m.description,
            primitives={
                "key_agreement": [m.kex_classical, m.kex_pqc],
                "kdf": m.kdf_algorithm,
                "kdf_domain": m.kdf_domain_info,
                "authentication": [m.auth_classical] + ([m.auth_pqc] if m.auth_pqc else []),
                "aead": m.aead,
            },
            constraints={
                "downgrade_protection": m.downgrade_protection,
                "replay_protection": m.replay_protection,
                "transcript_binding": m.transcript_binding,
                "fail_closed": m.fail_closed,
            },
            target_latency_budget_ms=m.target_latency_budget_ms,
            allowed_criticalities=list(m.allowed_criticalities),
            allowed_threat_levels=list(m.allowed_threat_levels),
        )
    except ConstructionError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/select", response_model=AdaptiveConstructionDecisionResponse)
def select_adaptive_construction(request: AdaptiveConstructionSelectRequest) -> AdaptiveConstructionDecisionResponse:
    """Deterministically select the appropriate construction and enforce safety invariants."""
    decision = CONSTRUCTION_ENGINE.select_construction(
        criticality=request.criticality,
        threat_level=request.threat_level,
        threat_score=request.threat_score,
        latency_budget_ms=request.latency_budget_ms,
    )
    return AdaptiveConstructionDecisionResponse(
        status=decision.status,
        selected_construction_id=decision.selected_construction_id,
        security_level=decision.security_level,
        criticality=decision.criticality,
        threat_level=decision.threat_level,
        threat_score=decision.threat_score,
        latency_budget_ms=decision.latency_budget_ms,
        estimated_latency_ms=decision.estimated_latency_ms,
        reason=decision.reason,
        constraints=[
            PolicyConstraintResponse(name=c.name, passed=c.passed, detail=c.detail)
            for c in decision.constraints
        ],
        downgrade_blocked=decision.downgrade_blocked,
        decision_time_ms=decision.decision_time_ms,
    )


@router.post("/handshake", response_model=AdaptiveHandshakeResponse)
def execute_adaptive_handshake(request: AdaptiveHandshakeRequest) -> AdaptiveHandshakeResponse:
    """Execute authenticated key establishment under selected or requested adaptive construction."""
    initiator = resolve_entity(request.initiator)
    if initiator is None:
        raise HTTPException(status_code=404, detail=f"Initiator entity '{request.initiator}' not found.")

    responder = resolve_entity(request.responder)
    if responder is None:
        raise HTTPException(status_code=404, detail=f"Responder entity '{request.responder}' not found.")

    if initiator.component_id == responder.component_id:
        raise HTTPException(status_code=400, detail="Initiator and responder cannot be the same entity.")

    start_ns = time.perf_counter_ns()
    try:
        init_session, resp_session, decision = CONSTRUCTION_ENGINE.execute_handshake(
            initiator=initiator,
            responder=responder,
            construction_id=request.construction_id,
            criticality=request.criticality,
            threat_level=request.threat_level,
            threat_score=request.threat_score,
            latency_budget_ms=request.latency_budget_ms,
        )
        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0

        construction = CONSTRUCTION_ENGINE.get_construction(decision.selected_construction_id)
        trace = construction.get_trace()

        # Cache session for live message transmission
        _ADAPTIVE_SESSIONS[init_session.session_id] = (init_session, resp_session)

        return AdaptiveHandshakeResponse(
            status="SUCCESS",
            session_id=init_session.session_id,
            construction_id=init_session.construction_id,
            security_level=init_session.security_level.value,
            initiator_id=initiator.component_id,
            responder_id=responder.component_id,
            negotiated_algorithms=init_session.negotiated_algorithms,
            trace=trace,
            decision=AdaptiveConstructionDecisionResponse(
                status=decision.status,
                selected_construction_id=decision.selected_construction_id,
                security_level=decision.security_level,
                criticality=decision.criticality,
                threat_level=decision.threat_level,
                threat_score=decision.threat_score,
                latency_budget_ms=decision.latency_budget_ms,
                estimated_latency_ms=decision.estimated_latency_ms,
                reason=decision.reason,
                constraints=[
                    PolicyConstraintResponse(name=c.name, passed=c.passed, detail=c.detail)
                    for c in decision.constraints
                ],
                downgrade_blocked=decision.downgrade_blocked,
                decision_time_ms=decision.decision_time_ms,
            ),
            handshake_time_ms=elapsed_ms,
        )
    except ConstructionError as exc:
        raise HTTPException(status_code=400, detail=f"Adaptive handshake failed: {exc}") from exc


@router.post("/message", response_model=AdaptiveMessageResponse)
def transmit_adaptive_message(request: AdaptiveMessageRequest) -> AdaptiveMessageResponse:
    """Encrypt and decrypt an authenticated avionics message across an established adaptive session."""
    session_pair = _ADAPTIVE_SESSIONS.get(request.session_id)
    if not session_pair:
        raise HTTPException(status_code=404, detail=f"Active session '{request.session_id}' not found.")

    init_session, resp_session = session_pair

    # Determine message type
    try:
        msg_type = MessageType(request.message_type)
    except ValueError:
        msg_type = MessageType.AIRCRAFT_STATUS

    sender_entity = resolve_entity(request.sender)
    receiver_entity = resolve_entity(request.receiver)
    sender_id = sender_entity.component_id if sender_entity else request.sender
    receiver_id = receiver_entity.component_id if receiver_entity else request.receiver

    # Determine sender session
    active_sender_session = init_session if init_session.local_id == sender_id else resp_session
    active_receiver_session = resp_session if resp_session.local_id == receiver_id else init_session

    message = AvionicsMessage(
        sender_id=sender_id,
        receiver_id=receiver_id,
        message_type=msg_type,
        payload=request.payload or {"status": "NOMINAL", "timestamp": time.time()},
    )

    t0 = time.perf_counter_ns()
    try:
        envelope = active_sender_session.encrypt_message(message)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Encryption failed: {exc}") from exc
    enc_time_ms = (time.perf_counter_ns() - t0) / 1_000_000.0

    t1 = time.perf_counter_ns()
    try:
        decrypted = active_receiver_session.decrypt_message(envelope)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Decryption/verification failed: {exc}") from exc
    dec_time_ms = (time.perf_counter_ns() - t1) / 1_000_000.0

    envelope_dict = {
        "packet_id": envelope.packet_id,
        "sender_id": envelope.sender_id,
        "receiver_id": envelope.receiver_id,
        "nonce_hex": envelope.nonce.hex(),
        "ciphertext_hex": envelope.ciphertext.hex(),
        "ciphertext_length": len(envelope.ciphertext),
        "associated_data_hex": envelope.associated_data.hex() if envelope.associated_data else "",
        "timestamp": envelope.timestamp,
        "size_bytes": envelope.size_bytes(),
    }

    return AdaptiveMessageResponse(
        status="SUCCESS",
        message_id=message.message_id,
        session_id=request.session_id,
        construction_id=request.construction_id,
        envelope=envelope_dict,
        decrypted_payload=decrypted.payload,
        encryption_time_ms=enc_time_ms,
        decryption_time_ms=dec_time_ms,
    )

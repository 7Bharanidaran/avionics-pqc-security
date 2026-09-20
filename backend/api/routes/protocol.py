"""Protocol and secure handshake API routes."""

from __future__ import annotations

from typing import Any
from fastapi import APIRouter, HTTPException

from backend.api.routes.avionics import resolve_entity
from backend.api.schemas import (
    HandshakeRequest,
    HandshakeResponse,
    MessageSendRequest,
    MessageSendResponse,
)
from backend.avionics.messages import AvionicsMessage, MessageType
from backend.protocol import perform_handshake

router = APIRouter(prefix="/protocol", tags=["Protocol"])


@router.post("/handshake", response_model=HandshakeResponse)
def execute_handshake(request: HandshakeRequest) -> HandshakeResponse:
    """Execute a simulated hybrid post-quantum secure handshake."""
    initiator = resolve_entity(request.initiator)
    if initiator is None:
        raise HTTPException(
            status_code=404,
            detail=f"Initiator entity '{request.initiator}' not found.",
        )

    responder = resolve_entity(request.responder)
    if responder is None:
        raise HTTPException(
            status_code=404,
            detail=f"Responder entity '{request.responder}' not found.",
        )

    if initiator.component_id == responder.component_id:
        raise HTTPException(
            status_code=400,
            detail="Initiator and responder cannot be the same entity.",
        )

    try:
        init_session, _ = perform_handshake(
            initiator=initiator,
            responder=responder,
            mlkem_param=request.mlkem_param,
            slhdsa_param=request.slhdsa_param,
        )

        return HandshakeResponse(
            status="established",
            initiator=initiator.component_id,
            responder=responder.component_id,
            session_id=init_session.session_id,
            key_exchange=["X25519", request.mlkem_param],
            authentication=["Ed25519", f"SLH-DSA-{request.slhdsa_param.upper()}"],
            key_derivation="HKDF-SHA256",
            encryption="AES-256-GCM",
            established_at=init_session.established_at,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Handshake failed: {exc}",
        )


@router.post("/message", response_model=MessageSendResponse)
def send_secure_message(request: MessageSendRequest) -> MessageSendResponse:
    """Encrypt, transmit, and decrypt an authenticated avionics message."""
    sender = resolve_entity(request.sender)
    if sender is None:
        raise HTTPException(
            status_code=404,
            detail=f"Sender entity '{request.sender}' not found.",
        )

    receiver = resolve_entity(request.receiver)
    if receiver is None:
        raise HTTPException(
            status_code=404,
            detail=f"Receiver entity '{request.receiver}' not found.",
        )

    if sender.component_id == receiver.component_id:
        raise HTTPException(
            status_code=400,
            detail="Sender and receiver cannot be the same entity.",
        )

    # Validate message type
    try:
        msg_type = MessageType(request.message_type.upper())
    except (ValueError, KeyError):
        valid_types = [t.value for t in MessageType]
        raise HTTPException(
            status_code=400,
            detail=f"Invalid message_type '{request.message_type}'. Valid types: {valid_types}",
        )

    # Establish session if not active
    if not sender.has_session(receiver.component_id) or not receiver.has_session(sender.component_id):
        try:
            perform_handshake(initiator=sender, responder=receiver)
        except Exception as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to automatically establish session before sending message: {exc}",
            )

    try:
        msg = AvionicsMessage(
            sender_id=sender.component_id,
            receiver_id=receiver.component_id,
            message_type=msg_type,
            payload=request.payload,
        )

        # Encrypt
        envelope = sender.encrypt_message(receiver.component_id, msg)

        # Decrypt at receiver
        decrypted_msg = receiver.decrypt_message(envelope)

        return MessageSendResponse(
            status="accepted",
            sender=sender.component_id,
            receiver=receiver.component_id,
            message_id=decrypted_msg.message_id,
            message_type=decrypted_msg.message_type.value,
            secure=True,
            payload=decrypted_msg.payload,
            display_text=decrypted_msg.display_string(),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Message encryption/decryption failed: {exc}",
        )

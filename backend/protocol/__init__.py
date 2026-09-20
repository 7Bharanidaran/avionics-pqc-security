"""Avionics Post-Quantum Secure Protocol Package.

Provides hybrid handshake state machine, canonical transcript construction,
session lifecycle management, and authenticated message encryption.
"""

from __future__ import annotations

from .handshake import (
    PROTOCOL_VERSION,
    HandshakeAuthenticationError,
    HandshakeState,
    HybridHandshake,
    InvalidStateError,
    ProtocolError,
    ReplayAttackError,
    SecureSession,
    compute_canonical_transcript,
    construct_message_aad,
    perform_handshake,
)

__all__ = [
    "PROTOCOL_VERSION",
    "HandshakeState",
    "HandshakeAuthenticationError",
    "InvalidStateError",
    "ProtocolError",
    "ReplayAttackError",
    "SecureSession",
    "HybridHandshake",
    "perform_handshake",
    "compute_canonical_transcript",
    "construct_message_aad",
]

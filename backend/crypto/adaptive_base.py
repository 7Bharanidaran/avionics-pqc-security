"""Base interfaces and data structures for project-specific adaptive cryptographic constructions.

Defines the common contracts, session management, and invariant checks
for threat-adaptive, safety-constrained avionics cryptographic constructions.
"""

from __future__ import annotations

import hashlib
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from backend.avionics.channel import EncryptedPacketEnvelope
from backend.avionics.messages import AvionicsMessage
from backend.crypto import (
    AESGCMError,
    AuthenticationTagError,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
)

PROTOCOL_VERSION = "AVIONICS-PQC-V1"


class ConstructionSecurityLevel(str, Enum):
    """Assurance classification for adaptive cryptographic constructions."""

    STANDARD = "STANDARD"
    BALANCED = "BALANCED"
    HIGH_ASSURANCE = "HIGH_ASSURANCE"
    CRITICAL = "CRITICAL"


class ConstructionError(Exception):
    """Base exception for adaptive construction errors."""


class ConstructionAuthenticationError(ConstructionError):
    """Raised when authentication or signature verification fails."""


class ConstructionDowngradeError(ConstructionError):
    """Raised when an unauthorized or unexpected construction downgrade is detected."""


class ConstructionReplayError(ConstructionError):
    """Raised when a reused nonce is detected in an established session."""


@dataclass(frozen=True)
class ConstructionMetadata:
    """Public metadata describing the capabilities and constraints of a construction."""

    construction_id: str
    security_level: ConstructionSecurityLevel
    description: str
    kex_classical: str
    kex_pqc: str
    kdf_algorithm: str
    kdf_domain_info: str
    auth_classical: str
    auth_pqc: str | None
    aead: str
    downgrade_protection: bool = True
    replay_protection: bool = True
    transcript_binding: bool = True
    fail_closed: bool = True
    target_latency_budget_ms: float = 1000.0
    allowed_criticalities: tuple[str, ...] = ("ROUTINE", "IMPORTANT", "CRITICAL", "SAFETY_CRITICAL")
    allowed_threat_levels: tuple[str, ...] = ("NORMAL", "ELEVATED", "HIGH", "CRITICAL")

    def to_dict(self) -> dict[str, Any]:
        return {
            "construction_id": self.construction_id,
            "security_level": self.security_level.value,
            "description": self.description,
            "primitives": {
                "key_agreement": [self.kex_classical, self.kex_pqc],
                "kdf": self.kdf_algorithm,
                "kdf_domain": self.kdf_domain_info,
                "authentication": [self.auth_classical] + ([self.auth_pqc] if self.auth_pqc else []),
                "aead": self.aead,
            },
            "constraints": {
                "downgrade_protection": self.downgrade_protection,
                "replay_protection": self.replay_protection,
                "transcript_binding": self.transcript_binding,
                "fail_closed": self.fail_closed,
            },
            "target_latency_budget_ms": self.target_latency_budget_ms,
            "allowed_criticalities": list(self.allowed_criticalities),
            "allowed_threat_levels": list(self.allowed_threat_levels),
        }


@dataclass
class AdaptiveSession:
    """Represents an active secure communication session established by an adaptive construction."""

    session_id: str
    construction_id: str
    security_level: ConstructionSecurityLevel
    initiator_id: str
    responder_id: str
    local_id: str
    peer_id: str
    session_key: bytes
    protocol_version: str = PROTOCOL_VERSION
    negotiated_algorithms: dict[str, str] = field(default_factory=dict)
    established_at: float = field(default_factory=time.time)
    state: str = "ESTABLISHED"
    _seen_nonces: set[bytes] = field(default_factory=set)

    def construct_aad(self, message: AvionicsMessage) -> bytes:
        """Deterministic Additional Authenticated Data binding construction ID, session ID, and message metadata."""
        aad_dict = {
            "construction_id": self.construction_id,
            "message_id": message.message_id,
            "message_type": message.message_type.value,
            "protocol_version": self.protocol_version,
            "receiver_id": message.receiver_id,
            "sender_id": message.sender_id,
            "session_id": self.session_id,
        }
        return json.dumps(aad_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")

    def encrypt_message(self, message: AvionicsMessage) -> EncryptedPacketEnvelope:
        """Encrypt an avionics message under this adaptive session."""
        if self.state != "ESTABLISHED":
            raise ConstructionError(f"Cannot encrypt: session {self.session_id} is in state {self.state}")

        if message.receiver_id != self.peer_id:
            raise ConstructionError(
                f"Session receiver mismatch: message destined for {message.receiver_id}, session with {self.peer_id}"
            )
        if message.sender_id != self.local_id:
            raise ConstructionError(
                f"Session sender mismatch: message sender {message.sender_id} does not match local {self.local_id}"
            )

        aad = self.construct_aad(message)
        ciphertext, nonce = aes_gcm_encrypt(
            key=self.session_key,
            plaintext=message.to_bytes(),
            associated_data=aad,
        )

        return EncryptedPacketEnvelope(
            sender_id=self.local_id,
            receiver_id=self.peer_id,
            nonce=nonce,
            ciphertext=ciphertext,
            associated_data=aad,
        )

    def decrypt_message(self, envelope: EncryptedPacketEnvelope) -> AvionicsMessage:
        """Decrypt and verify an incoming envelope, validating construction binding and replay status."""
        if self.state != "ESTABLISHED":
            raise ConstructionError(f"Cannot decrypt: session {self.session_id} is in state {self.state}")

        if envelope.sender_id != self.peer_id:
            raise ConstructionError(
                f"Envelope sender mismatch: received from {envelope.sender_id}, expected session peer {self.peer_id}"
            )
        if envelope.receiver_id != self.local_id:
            raise ConstructionError(
                f"Envelope receiver mismatch: addressed to {envelope.receiver_id}, local is {self.local_id}"
            )

        # Enforce Replay Protection
        if envelope.nonce in self._seen_nonces:
            raise ConstructionReplayError(
                f"Replay attack detected: nonce {envelope.nonce.hex()} already processed in session {self.session_id[:16]}"
            )

        plaintext = aes_gcm_decrypt(
            key=self.session_key,
            nonce=envelope.nonce,
            ciphertext=envelope.ciphertext,
            associated_data=envelope.associated_data,
        )

        message = AvionicsMessage.from_bytes(plaintext)

        # Validate AAD binding (ensures construction_id was not tampered with)
        expected_aad = self.construct_aad(message)
        if envelope.associated_data != expected_aad:
            raise AuthenticationTagError("Message AAD or construction ID binding failure")

        if message.sender_id != self.peer_id or message.receiver_id != self.local_id:
            raise ConstructionError("Decrypted message inner sender/receiver mismatch")

        self._seen_nonces.add(envelope.nonce)
        return message


class BaseAdaptiveConstruction(ABC):
    """Abstract Base Class defining the lifecycle and execution of an adaptive construction."""

    def __init__(self, metadata: ConstructionMetadata) -> None:
        self.metadata = metadata
        self.step_logs: list[dict[str, str]] = []

    def _log_step(self, step_num: int, name: str, status: str, detail: str = "") -> None:
        self.step_logs.append({
            "step": str(step_num),
            "name": name,
            "status": status,
            "detail": detail,
        })

    def get_trace(self) -> list[dict[str, str]]:
        """Return the audit trace of the most recent handshake execution."""
        return list(self.step_logs)

    @abstractmethod
    def establish_session(
        self,
        initiator: Any,
        responder: Any,
    ) -> tuple[AdaptiveSession, AdaptiveSession]:
        """Execute full authenticated key establishment between initiator and responder."""

    @abstractmethod
    def compute_transcript(
        self,
        initiator_id: str,
        responder_id: str,
        initiator_x_pub: bytes,
        initiator_ml_pub: bytes,
        responder_x_pub: bytes,
        ml_ciphertext: bytes,
    ) -> bytes:
        """Construct deterministic canonical transcript bytes for this construction."""

    @abstractmethod
    def derive_session_key(
        self,
        ikm: bytes,
        transcript: bytes,
    ) -> bytes:
        """Derive session key from combined hybrid IKM using construction-specific KDF and domain info."""

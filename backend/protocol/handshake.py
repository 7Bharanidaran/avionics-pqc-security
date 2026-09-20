"""Complete Hybrid Post-Quantum Secure Avionics Handshake Protocol.

Implements the end-to-end authenticated key agreement state machine combining:
- Classical Key Exchange: X25519
- Post-Quantum Key Encapsulation: ML-KEM-1024 (FIPS 203)
- Key Derivation: HKDF-SHA256 (RFC 5869)
- Classical Authentication: Ed25519 (RFC 8032)
- Post-Quantum Authentication: SLH-DSA (FIPS 205)
- Authenticated Data Encryption: AES-256-GCM

DISCLAIMER: This software is a simulation model for post-quantum cryptographic
evaluation and does NOT interface with or control real aircraft systems.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from backend.avionics.channel import EncryptedPacketEnvelope
from backend.avionics.messages import AvionicsMessage
from backend.crypto import (
    AESGCMError,
    AuthenticationTagError,
    Ed25519Error,
    HKDFError,
    MLKEMError,
    SLHDSAError,
    X25519Error,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    ed25519_sign,
    ed25519_verify,
    hkdf_derive,
    mlkem_decapsulate,
    mlkem_encapsulate,
    mlkem_generate_keypair,
    slhdsa_sign,
    slhdsa_verify,
    x25519_derive_shared_secret,
    x25519_generate_keypair,
)

PROTOCOL_VERSION = "AVIONICS-PQC-V1"


class HandshakeState(str, Enum):
    """Explicit lifecycle states for the secure avionics handshake."""

    INITIAL = "INITIAL"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    KEY_DERIVED = "KEY_DERIVED"
    AUTHENTICATING = "AUTHENTICATING"
    AUTHENTICATED = "AUTHENTICATED"
    ESTABLISHED = "ESTABLISHED"
    FAILED = "FAILED"


class ProtocolError(Exception):
    """Base exception for protocol violations or state machine errors."""


class HandshakeAuthenticationError(ProtocolError):
    """Raised when Ed25519 or SLH-DSA signature verification fails."""


class InvalidStateError(ProtocolError):
    """Raised on invalid handshake state transitions."""


class ReplayAttackError(ProtocolError):
    """Raised when an encrypted message with an already-used nonce is received."""


def compute_canonical_transcript(
    protocol_version: str,
    initiator_id: str,
    responder_id: str,
    initiator_x25519_pub: bytes,
    initiator_mlkem_pub: bytes,
    responder_x25519_pub: bytes,
    mlkem_ciphertext: bytes,
    mlkem_param: str = "ML-KEM-1024",
    slhdsa_param: str = "shake_128f",
) -> bytes:
    """Construct the canonical deterministic handshake transcript bytes.

    Binds protocol version, entity IDs, ephemeral key material, ciphertext, and algorithms.
    """
    transcript_dict = {
        "algorithms": {
            "aead": "AES-256-GCM",
            "auth_classical": "Ed25519",
            "auth_pqc": f"SLH-DSA-{slhdsa_param.upper()}",
            "kdf": "HKDF-SHA256",
            "kex_classical": "X25519",
            "kex_pqc": mlkem_param,
        },
        "initiator_id": initiator_id,
        "initiator_mlkem_pub_hex": initiator_mlkem_pub.hex(),
        "initiator_x25519_pub_hex": initiator_x25519_pub.hex(),
        "mlkem_ciphertext_hex": mlkem_ciphertext.hex(),
        "protocol_version": protocol_version,
        "responder_id": responder_id,
        "responder_x25519_pub_hex": responder_x25519_pub.hex(),
    }
    return json.dumps(transcript_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")


def construct_message_aad(
    protocol_version: str,
    session_id: str,
    sender_id: str,
    receiver_id: str,
    message_id: str,
    message_type: str,
) -> bytes:
    """Construct deterministic Additional Authenticated Data (AAD) for AES-GCM."""
    aad_dict = {
        "message_id": message_id,
        "message_type": message_type,
        "protocol_version": protocol_version,
        "receiver_id": receiver_id,
        "sender_id": sender_id,
        "session_id": session_id,
    }
    return json.dumps(aad_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")


@dataclass
class SecureSession:
    """Represents an established secure session between two avionics entities."""

    session_id: str
    initiator_id: str
    responder_id: str
    local_id: str
    peer_id: str
    session_key: bytes
    protocol_version: str = PROTOCOL_VERSION
    negotiated_algorithms: dict[str, str] = field(default_factory=dict)
    established_at: float = field(default_factory=time.time)
    state: HandshakeState = HandshakeState.ESTABLISHED
    _seen_nonces: set[bytes] = field(default_factory=set)

    def encrypt_message(self, message: AvionicsMessage) -> EncryptedPacketEnvelope:
        """Encrypt an AvionicsMessage using the established session key and authenticated metadata.

        Args:
            message: AvionicsMessage instance.

        Returns:
            EncryptedPacketEnvelope: Opaque encrypted envelope.

        Raises:
            ProtocolError: If session is not ESTABLISHED or recipient mismatch.
            AESGCMError: If encryption fails.
        """
        if self.state != HandshakeState.ESTABLISHED:
            raise ProtocolError(f"Cannot encrypt: session {self.session_id} is in state {self.state.value}")

        if message.receiver_id != self.peer_id:
            raise ProtocolError(
                f"Session receiver mismatch: message destined for {message.receiver_id}, session with {self.peer_id}"
            )
        if message.sender_id != self.local_id:
            raise ProtocolError(
                f"Session sender mismatch: message sender {message.sender_id} does not match local {self.local_id}"
            )

        aad = construct_message_aad(
            protocol_version=self.protocol_version,
            session_id=self.session_id,
            sender_id=message.sender_id,
            receiver_id=message.receiver_id,
            message_id=message.message_id,
            message_type=message.message_type.value,
        )

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
        """Decrypt and verify an incoming EncryptedPacketEnvelope.

        Args:
            envelope: EncryptedPacketEnvelope received from untrusted channel.

        Returns:
            AvionicsMessage: Decrypted and authenticated message.

        Raises:
            ProtocolError: If session is not ESTABLISHED, sender/receiver mismatch, or AAD mismatch.
            ReplayAttackError: If nonce was already processed in this session.
            AuthenticationTagError: If payload or tag is tampered.
        """
        if self.state != HandshakeState.ESTABLISHED:
            raise ProtocolError(f"Cannot decrypt: session {self.session_id} is in state {self.state.value}")

        if envelope.sender_id != self.peer_id:
            raise ProtocolError(
                f"Envelope sender mismatch: received from {envelope.sender_id}, expected session peer {self.peer_id}"
            )
        if envelope.receiver_id != self.local_id:
            raise ProtocolError(
                f"Envelope receiver mismatch: addressed to {envelope.receiver_id}, local is {self.local_id}"
            )

        # Enforce Replay Protection: Check if nonce was already received
        if envelope.nonce in self._seen_nonces:
            raise ReplayAttackError(
                f"Replay attack detected: nonce {envelope.nonce.hex()} already processed in session {self.session_id[:16]}"
            )

        plaintext = aes_gcm_decrypt(
            key=self.session_key,
            nonce=envelope.nonce,
            ciphertext=envelope.ciphertext,
            associated_data=envelope.associated_data,
        )

        message = AvionicsMessage.from_bytes(plaintext)

        # Validate AAD binding
        expected_aad = construct_message_aad(
            protocol_version=self.protocol_version,
            session_id=self.session_id,
            sender_id=message.sender_id,
            receiver_id=message.receiver_id,
            message_id=message.message_id,
            message_type=message.message_type.value,
        )

        if envelope.associated_data != expected_aad:
            raise AuthenticationTagError("Message AAD mismatch or session ID binding failure")

        if message.sender_id != self.peer_id or message.receiver_id != self.local_id:
            raise ProtocolError("Decrypted message inner sender/receiver mismatch")

        # Record nonce in replay filter
        self._seen_nonces.add(envelope.nonce)

        return message


# =====================================================================
# Handshake Orchestrator & State Machine
# =====================================================================


class HybridHandshake:
    """Manages the complete hybrid post-quantum handshake state machine."""

    def __init__(
        self,
        initiator: Any,
        responder: Any,
        mlkem_param: str = "ML-KEM-1024",
        slhdsa_param: str = "shake_128f",
    ):
        self.initiator = initiator
        self.responder = responder
        self.mlkem_param = mlkem_param
        self.slhdsa_param = slhdsa_param

        self.initiator_state = HandshakeState.INITIAL
        self.responder_state = HandshakeState.INITIAL

        self.transcript: bytes | None = None
        self.transcript_hash: bytes | None = None
        self.session_id: str | None = None

        self.initiator_session_key: bytes | None = None
        self.responder_session_key: bytes | None = None

        self.step_logs: list[dict[str, str]] = []

    def _log_step(self, step_num: int, name: str, status: str, detail: str = "") -> None:
        self.step_logs.append({
            "step": str(step_num),
            "name": name,
            "status": status,
            "detail": detail,
        })

    def run(self) -> tuple[SecureSession, SecureSession]:
        """Execute the complete authenticated hybrid handshake.

        Returns:
            tuple[SecureSession, SecureSession]: (initiator_session, responder_session)

        Raises:
            ProtocolError: If any step fails or authentication fails.
        """
        try:
            # ---------------------------------------------------------
            # Step 1: Ephemeral Key Generation (Initiator)
            # State: INITIAL -> KEY_EXCHANGE
            # ---------------------------------------------------------
            self.initiator_state = HandshakeState.KEY_EXCHANGE
            self.responder_state = HandshakeState.KEY_EXCHANGE

            init_x_priv, init_x_pub = x25519_generate_keypair()
            init_ml_seed, init_ml_pub = mlkem_generate_keypair(self.mlkem_param)
            self._log_step(1, "X25519", "Shared secret established ✓", "Initiator ephemeral keys generated")

            # ---------------------------------------------------------
            # Step 2: Key Agreement & ML-KEM Encapsulation (Responder)
            # ---------------------------------------------------------
            resp_x_priv, resp_x_pub = x25519_generate_keypair()
            resp_ml_ss, mlkem_ciphertext = mlkem_encapsulate(init_ml_pub, self.mlkem_param)
            resp_x_ss = x25519_derive_shared_secret(resp_x_priv, init_x_pub)

            self._log_step(2, "ML-KEM", "Encapsulation/decapsulation successful ✓", "Responder encapsulated ML-KEM secret")

            # ---------------------------------------------------------
            # Step 3: Decapsulation & Combined Hybrid Key Material
            # State: KEY_EXCHANGE -> KEY_DERIVED
            # ---------------------------------------------------------
            init_ml_ss = mlkem_decapsulate(init_ml_seed, mlkem_ciphertext, self.mlkem_param)
            init_x_ss = x25519_derive_shared_secret(init_x_priv, resp_x_pub)

            if init_x_ss != resp_x_ss or init_ml_ss != resp_ml_ss:
                self.initiator_state = HandshakeState.FAILED
                self.responder_state = HandshakeState.FAILED
                raise ProtocolError("Hybrid key agreement failed: shared secrets do not match")

            init_hybrid_ikm = init_x_ss + init_ml_ss
            resp_hybrid_ikm = resp_x_ss + resp_ml_ss
            self._log_step(3, "HYBRID KEY MATERIAL", "Combined ✓", "Combined 64-byte hybrid key material")

            # ---------------------------------------------------------
            # Step 4: Canonical Transcript Construction & HKDF Derivation
            # ---------------------------------------------------------
            self.transcript = compute_canonical_transcript(
                protocol_version=PROTOCOL_VERSION,
                initiator_id=self.initiator.component_id,
                responder_id=self.responder.component_id,
                initiator_x25519_pub=init_x_pub,
                initiator_mlkem_pub=init_ml_pub,
                responder_x25519_pub=resp_x_pub,
                mlkem_ciphertext=mlkem_ciphertext,
                mlkem_param=self.mlkem_param,
                slhdsa_param=self.slhdsa_param,
            )

            self.transcript_hash = hashlib.sha256(self.transcript).digest()
            self.session_id = hashlib.sha256(b"SESSION_ID:" + self.transcript).hexdigest()

            # Salt derived from transcript hash
            session_salt = hashlib.sha256(b"AVIONICS_PQC_SALT:" + self.transcript).digest()
            session_info = b"AVIONICS_HYBRID_PQC_SESSION_KEY_V1"

            self.initiator_session_key = hkdf_derive(
                ikm=init_hybrid_ikm,
                salt=session_salt,
                info=session_info,
                length=32,
                hash_name="SHA256",
            )

            self.responder_session_key = hkdf_derive(
                ikm=resp_hybrid_ikm,
                salt=session_salt,
                info=session_info,
                length=32,
                hash_name="SHA256",
            )

            if self.initiator_session_key != self.responder_session_key:
                self.initiator_state = HandshakeState.FAILED
                self.responder_state = HandshakeState.FAILED
                raise ProtocolError("HKDF session key mismatch")

            self.initiator_state = HandshakeState.KEY_DERIVED
            self.responder_state = HandshakeState.KEY_DERIVED
            self._log_step(4, "HKDF", "Session key derived ✓", "Derived 256-bit AES-GCM session key")

            # ---------------------------------------------------------
            # Step 5 & 6: Dual Authentication (Ed25519 + SLH-DSA)
            # State: KEY_DERIVED -> AUTHENTICATING -> AUTHENTICATED
            # ---------------------------------------------------------
            self.initiator_state = HandshakeState.AUTHENTICATING
            self.responder_state = HandshakeState.AUTHENTICATING

            # Responder signs transcript hash
            resp_ed_sig = ed25519_sign(self.responder._ed_private_key, self.transcript_hash)
            resp_slh_sig = slhdsa_sign(self.responder._slh_secret_key, self.transcript_hash, self.slhdsa_param)

            # Initiator signs transcript hash
            init_ed_sig = ed25519_sign(self.initiator._ed_private_key, self.transcript_hash)
            init_slh_sig = slhdsa_sign(self.initiator._slh_secret_key, self.transcript_hash, self.slhdsa_param)

            # Verification: Initiator verifies Responder
            resp_ed_ok = ed25519_verify(self.responder.ed25519_public_key, self.transcript_hash, resp_ed_sig)
            resp_slh_ok = slhdsa_verify(self.responder.slhdsa_public_key, self.transcript_hash, resp_slh_sig, self.slhdsa_param)

            # Verification: Responder verifies Initiator
            init_ed_ok = ed25519_verify(self.initiator.ed25519_public_key, self.transcript_hash, init_ed_sig)
            init_slh_ok = slhdsa_verify(self.initiator.slhdsa_public_key, self.transcript_hash, init_slh_sig, self.slhdsa_param)

            if not (resp_ed_ok and init_ed_ok):
                self.initiator_state = HandshakeState.FAILED
                self.responder_state = HandshakeState.FAILED
                raise HandshakeAuthenticationError("Ed25519 authentication failed")

            self._log_step(5, "Ed25519", "Signature generated ✓\nSignature verified ✓", "Classical signatures verified")

            if not (resp_slh_ok and init_slh_ok):
                self.initiator_state = HandshakeState.FAILED
                self.responder_state = HandshakeState.FAILED
                raise HandshakeAuthenticationError("SLH-DSA authentication failed")

            self._log_step(6, "SLH-DSA", "Signature generated ✓\nSignature verified ✓", "Post-quantum signatures verified")

            self.initiator_state = HandshakeState.AUTHENTICATED
            self.responder_state = HandshakeState.AUTHENTICATED

            # ---------------------------------------------------------
            # Step 7: Session Establishment
            # State: AUTHENTICATED -> ESTABLISHED
            # ---------------------------------------------------------
            self.initiator_state = HandshakeState.ESTABLISHED
            self.responder_state = HandshakeState.ESTABLISHED
            self._log_step(7, "SESSION", "AUTHENTICATED ✓\nESTABLISHED ✓", f"Session established ID: {self.session_id[:16]}...")

            negotiated_algos = {
                "kex_classical": "X25519",
                "kex_pqc": self.mlkem_param,
                "auth_classical": "Ed25519",
                "auth_pqc": f"SLH-DSA-{self.slhdsa_param.upper()}",
                "kdf": "HKDF-SHA256",
                "aead": "AES-256-GCM",
            }

            init_session = SecureSession(
                session_id=self.session_id,
                initiator_id=self.initiator.component_id,
                responder_id=self.responder.component_id,
                local_id=self.initiator.component_id,
                peer_id=self.responder.component_id,
                session_key=self.initiator_session_key,
                negotiated_algorithms=negotiated_algos,
                state=HandshakeState.ESTABLISHED,
            )

            resp_session = SecureSession(
                session_id=self.session_id,
                initiator_id=self.initiator.component_id,
                responder_id=self.responder.component_id,
                local_id=self.responder.component_id,
                peer_id=self.initiator.component_id,
                session_key=self.responder_session_key,
                negotiated_algorithms=negotiated_algos,
                state=HandshakeState.ESTABLISHED,
            )

            # Register established sessions in entities
            self.initiator.register_secure_session(self.responder.component_id, init_session)
            self.responder.register_secure_session(self.initiator.component_id, resp_session)

            return init_session, resp_session

        except Exception as exc:
            self.initiator_state = HandshakeState.FAILED
            self.responder_state = HandshakeState.FAILED
            if not isinstance(exc, ProtocolError):
                raise ProtocolError(f"Handshake execution failed: {exc}") from exc
            raise


def perform_handshake(
    initiator: Any,
    responder: Any,
    mlkem_param: str = "ML-KEM-1024",
    slhdsa_param: str = "shake_128f",
) -> tuple[SecureSession, SecureSession]:
    """Execute a hybrid post-quantum handshake between two avionics entities."""
    handshake = HybridHandshake(
        initiator=initiator,
        responder=responder,
        mlkem_param=mlkem_param,
        slhdsa_param=slhdsa_param,
    )
    return handshake.run()

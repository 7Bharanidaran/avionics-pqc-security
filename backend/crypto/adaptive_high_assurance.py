"""Adaptive High-Assurance Cryptographic Construction (ADAPTIVE-HIGH-ASSURANCE-V1).

Composition:
- Key Agreement: X25519 + ML-KEM-1024 (NIST Level 5)
- Key Derivation: HKDF-SHA384 with domain separation 'AVIONICS-PQC-HIGH-ASSURANCE-V1-KDF-SHA384'
- Authentication: Dual Authentication (Ed25519 classical + SLH-DSA-SHAKE_128F post-quantum)
- AEAD Encryption: AES-256-GCM
- Target: High-threat operations and CRITICAL traffic requiring proven dual authentication.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from backend.crypto import (
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
from .adaptive_base import (
    AdaptiveSession,
    BaseAdaptiveConstruction,
    ConstructionAuthenticationError,
    ConstructionError,
    ConstructionMetadata,
    ConstructionSecurityLevel,
    PROTOCOL_VERSION,
)

METADATA_HIGH_ASSURANCE = ConstructionMetadata(
    construction_id="ADAPTIVE-HIGH-ASSURANCE-V1",
    security_level=ConstructionSecurityLevel.HIGH_ASSURANCE,
    description="High-Assurance Hybrid PQC construction (X25519 + ML-KEM-1024 + HKDF-SHA384 + Dual Ed25519/SLH-DSA + AES-256-GCM).",
    kex_classical="X25519",
    kex_pqc="ML-KEM-1024",
    kdf_algorithm="HKDF-SHA384",
    kdf_domain_info="AVIONICS-PQC-HIGH-ASSURANCE-V1-KDF-SHA384",
    auth_classical="Ed25519",
    auth_pqc="SLH-DSA-SHAKE_128F",
    aead="AES-256-GCM",
    downgrade_protection=True,
    replay_protection=True,
    transcript_binding=True,
    fail_closed=True,
    target_latency_budget_ms=3000.0,
    allowed_criticalities=("ROUTINE", "IMPORTANT", "CRITICAL", "SAFETY_CRITICAL"),
    allowed_threat_levels=("NORMAL", "ELEVATED", "HIGH", "CRITICAL"),
)


class AdaptiveHighAssuranceConstruction(BaseAdaptiveConstruction):
    """Implements ADAPTIVE-HIGH-ASSURANCE-V1."""

    def __init__(self) -> None:
        super().__init__(METADATA_HIGH_ASSURANCE)

    def compute_transcript(
        self,
        initiator_id: str,
        responder_id: str,
        initiator_x_pub: bytes,
        initiator_ml_pub: bytes,
        responder_x_pub: bytes,
        ml_ciphertext: bytes,
    ) -> bytes:
        transcript_dict = {
            "algorithms": {
                "aead": self.metadata.aead,
                "auth_classical": self.metadata.auth_classical,
                "auth_pqc": self.metadata.auth_pqc,
                "construction_id": self.metadata.construction_id,
                "kdf": self.metadata.kdf_algorithm,
                "kex_classical": self.metadata.kex_classical,
                "kex_pqc": self.metadata.kex_pqc,
            },
            "construction_id": self.metadata.construction_id,
            "initiator_id": initiator_id,
            "initiator_mlkem_pub_hex": initiator_ml_pub.hex(),
            "initiator_x25519_pub_hex": initiator_x_pub.hex(),
            "mlkem_ciphertext_hex": ml_ciphertext.hex(),
            "protocol_version": PROTOCOL_VERSION,
            "responder_id": responder_id,
            "responder_x25519_pub_hex": responder_x_pub.hex(),
        }
        return json.dumps(transcript_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")

    def derive_session_key(self, ikm: bytes, transcript: bytes) -> bytes:
        salt = hashlib.sha384(b"SALT:" + self.metadata.construction_id.encode() + b":" + transcript).digest()
        return hkdf_derive(
            ikm=ikm,
            salt=salt,
            info=self.metadata.kdf_domain_info.encode(),
            length=32,
            hash_name="SHA384",
        )

    def establish_session(
        self,
        initiator: Any,
        responder: Any,
    ) -> tuple[AdaptiveSession, AdaptiveSession]:
        self.step_logs.clear()

        # Step 1: Initiator generates ephemeral X25519 + ML-KEM-1024
        init_x_priv, init_x_pub = x25519_generate_keypair()
        init_ml_seed, init_ml_pub = mlkem_generate_keypair("ML-KEM-1024")
        self._log_step(1, "X25519 + ML-KEM-1024", "Generated initiator ephemeral keys ✓")

        # Step 2: Responder generates X25519 + encapsulates ML-KEM-1024
        resp_x_priv, resp_x_pub = x25519_generate_keypair()
        resp_ml_ss, ml_ciphertext = mlkem_encapsulate(init_ml_pub, "ML-KEM-1024")
        resp_x_ss = x25519_derive_shared_secret(resp_x_priv, init_x_pub)
        self._log_step(2, "ML-KEM-1024 Encapsulation", "Responder encapsulated Level-5 post-quantum secret ✓")

        # Step 3: Initiator decapsulates ML-KEM-1024 & derives X25519 secret
        init_ml_ss = mlkem_decapsulate(init_ml_seed, ml_ciphertext, "ML-KEM-1024")
        init_x_ss = x25519_derive_shared_secret(init_x_priv, resp_x_pub)

        if init_x_ss != resp_x_ss or init_ml_ss != resp_ml_ss:
            raise ConstructionError("High-Assurance key exchange agreement mismatch")

        init_ikm = init_x_ss + init_ml_ss
        resp_ikm = resp_x_ss + resp_ml_ss
        self._log_step(3, "Hybrid Secret Processing", "Validated and combined 64-byte hybrid secret ✓")

        # Step 4: Transcript & HKDF-SHA384 Derivation
        transcript = self.compute_transcript(
            initiator_id=initiator.component_id,
            responder_id=responder.component_id,
            initiator_x_pub=init_x_pub,
            initiator_ml_pub=init_ml_pub,
            responder_x_pub=resp_x_pub,
            ml_ciphertext=ml_ciphertext,
        )
        transcript_hash = hashlib.sha384(transcript).digest()
        session_id = hashlib.sha384(b"SESSION:" + self.metadata.construction_id.encode() + b":" + transcript).hexdigest()

        init_key = self.derive_session_key(init_ikm, transcript)
        resp_key = self.derive_session_key(resp_ikm, transcript)

        if init_key != resp_key:
            raise ConstructionError("High-Assurance session key derivation mismatch")
        self._log_step(4, "HKDF-SHA384 Derivation", "Derived 256-bit AES key with domain separation ✓")

        # Step 5: Classical Authentication (Ed25519)
        auth_context = b"AUTH:" + self.metadata.construction_id.encode() + b":" + transcript_hash
        resp_ed_sig = ed25519_sign(responder._ed_private_key, auth_context)
        init_ed_sig = ed25519_sign(initiator._ed_private_key, auth_context)

        resp_ed_ok = ed25519_verify(responder.ed25519_public_key, auth_context, resp_ed_sig)
        init_ed_ok = ed25519_verify(initiator.ed25519_public_key, auth_context, init_ed_sig)

        if not (resp_ed_ok and init_ed_ok):
            raise ConstructionAuthenticationError("Ed25519 authentication failed in ADAPTIVE-HIGH-ASSURANCE-V1")
        self._log_step(5, "Classical Authentication (Ed25519)", "Classical signatures verified on both sides ✓")

        # Step 6: Post-Quantum Authentication (SLH-DSA-SHAKE_128F)
        resp_slh_sig = slhdsa_sign(responder._slh_secret_key, auth_context, "shake_128f")
        init_slh_sig = slhdsa_sign(initiator._slh_secret_key, auth_context, "shake_128f")

        resp_slh_ok = slhdsa_verify(responder.slhdsa_public_key, auth_context, resp_slh_sig, "shake_128f")
        init_slh_ok = slhdsa_verify(initiator.slhdsa_public_key, auth_context, init_slh_sig, "shake_128f")

        if not (resp_slh_ok and init_slh_ok):
            raise ConstructionAuthenticationError("SLH-DSA authentication failed in ADAPTIVE-HIGH-ASSURANCE-V1")
        self._log_step(6, "Post-Quantum Authentication (SLH-DSA)", "FIPS 205 post-quantum signatures verified on both sides ✓")

        # Step 7: Session Creation
        negotiated = {
            "construction_id": self.metadata.construction_id,
            "kex_classical": self.metadata.kex_classical,
            "kex_pqc": self.metadata.kex_pqc,
            "kdf": self.metadata.kdf_algorithm,
            "auth_classical": self.metadata.auth_classical,
            "auth_pqc": self.metadata.auth_pqc,
            "aead": self.metadata.aead,
        }

        init_session = AdaptiveSession(
            session_id=session_id,
            construction_id=self.metadata.construction_id,
            security_level=self.metadata.security_level,
            initiator_id=initiator.component_id,
            responder_id=responder.component_id,
            local_id=initiator.component_id,
            peer_id=responder.component_id,
            session_key=init_key,
            negotiated_algorithms=negotiated,
        )

        resp_session = AdaptiveSession(
            session_id=session_id,
            construction_id=self.metadata.construction_id,
            security_level=self.metadata.security_level,
            initiator_id=initiator.component_id,
            responder_id=responder.component_id,
            local_id=responder.component_id,
            peer_id=initiator.component_id,
            session_key=resp_key,
            negotiated_algorithms=negotiated,
        )

        self._log_step(7, "Session Established", f"Established session ID: {session_id[:16]}... ✓")
        return init_session, resp_session


ADAPTIVE_HIGH_ASSURANCE = AdaptiveHighAssuranceConstruction()

"""Security Attack Simulation Framework for Avionics PQC Security Lab.

Provides controlled, deterministic security simulations against the hybrid PQC protocol.
Evaluates protocol resilience against ciphertext tampering, tag tampering, AAD manipulation,
signature forgery (Ed25519 and SLH-DSA), transcript modification, session confusion,
receiver spoofing, and message replay.

DISCLAIMER: This framework executes purely in-memory software simulations against local
test sessions for academic evaluation. It does NOT execute network-level attacks.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable

from backend.avionics import (
    EncryptedPacketEnvelope,
    FlightControlComputer,
    GroundControlStation,
    MessageType,
    NavigationComputer,
    SessionNotFoundError,
    SimulatedChannel,
)
from backend.crypto import (
    AuthenticationTagError,
    ed25519_generate_keypair,
    ed25519_sign,
    ed25519_verify,
    slhdsa_generate_keypair,
    slhdsa_sign,
    slhdsa_verify,
)
from backend.protocol import (
    HandshakeAuthenticationError,
    HandshakeState,
    HybridHandshake,
    ProtocolError,
    ReplayAttackError,
    SecureSession,
    compute_canonical_transcript,
    construct_message_aad,
)


class AttackStatus(str, Enum):
    """Execution status of an attack simulation."""

    DETECTED = "DETECTED"
    NOT_DETECTED = "NOT_DETECTED"
    ERROR = "ERROR"


@dataclass
class AttackResult:
    """Structured result model for a security attack simulation."""

    attack_id: str
    attack_name: str
    description: str
    target: str
    original_result: str
    modified_result: str
    expected_behavior: str
    actual_behavior: str
    detected: bool
    status: AttackStatus
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        """Serialize result to dictionary."""
        return {
            "attack_id": self.attack_id,
            "attack_name": self.attack_name,
            "description": self.description,
            "target": self.target,
            "original_result": self.original_result,
            "modified_result": self.modified_result,
            "expected_behavior": self.expected_behavior,
            "actual_behavior": self.actual_behavior,
            "detected": self.detected,
            "status": self.status.value,
            "timestamp": self.timestamp,
        }


# =====================================================================
# Individual Attack Simulation Implementations
# =====================================================================


def run_baseline_test() -> AttackResult:
    """Run baseline legitimate communication between FCC and NAV."""
    try:
        fcc = FlightControlComputer()
        nav = NavigationComputer()
        channel = SimulatedChannel(name="BASELINE_CHANNEL")

        # Establish secure session
        fcc.establish_secure_session(nav)

        # Create message
        original_msg = fcc.create_altitude_message(nav.component_id, altitude_ft=32000)

        # Encrypt and send
        envelope = fcc.send_via_channel(nav.component_id, original_msg, channel)

        # Decrypt
        recovered_msg = nav.decrypt_message(envelope)

        success = recovered_msg.display_string() == original_msg.display_string()

        return AttackResult(
            attack_id="ATK-00",
            attack_name="Baseline Legitimate Transmission",
            description="Legitimate transmission of ALTITUDE telemetry without tampering",
            target="FCC -> NAV Protocol Channel",
            original_result="ALTITUDE = 32000 FT",
            modified_result=recovered_msg.display_string(),
            expected_behavior="Message accepted and authenticated by receiver",
            actual_behavior="Message successfully decrypted and verified",
            detected=False,  # Legitimate message is not an attack
            status=AttackStatus.DETECTED if success else AttackStatus.ERROR,
        )
    except Exception as exc:
        return AttackResult(
            attack_id="ATK-00",
            attack_name="Baseline Legitimate Transmission",
            description="Legitimate transmission of ALTITUDE telemetry",
            target="FCC -> NAV Protocol Channel",
            original_result="ALTITUDE = 32000 FT",
            modified_result=f"EXCEPTION: {exc}",
            expected_behavior="Message accepted and authenticated",
            actual_behavior=f"Failed with exception: {exc}",
            detected=False,
            status=AttackStatus.ERROR,
        )


def simulate_ciphertext_tampering() -> AttackResult:
    """Simulate modifying encrypted ciphertext bits in transit."""
    try:
        fcc = FlightControlComputer()
        nav = NavigationComputer()
        fcc.establish_secure_session(nav)

        msg = fcc.create_altitude_message(nav.component_id, altitude_ft=32000)
        envelope = fcc.encrypt_message(nav.component_id, msg)

        # Tamper with ciphertext
        tampered_ct = bytearray(envelope.ciphertext)
        tampered_ct[4] ^= 0x55

        tampered_envelope = EncryptedPacketEnvelope(
            packet_id=envelope.packet_id,
            sender_id=envelope.sender_id,
            receiver_id=envelope.receiver_id,
            nonce=envelope.nonce,
            ciphertext=bytes(tampered_ct),
            associated_data=envelope.associated_data,
            timestamp=envelope.timestamp,
        )

        detected = False
        try:
            nav.decrypt_message(tampered_envelope)
            actual = "UNAUTHENTICATED ACCEPTANCE (SECURITY VULNERABILITY)"
        except AuthenticationTagError:
            detected = True
            actual = "AuthenticationTagError raised; tampered ciphertext rejected by GCM"

        return AttackResult(
            attack_id="ATK-01",
            attack_name="Ciphertext Tampering",
            description="Inverts bits in AES-GCM ciphertext during channel transit",
            target="Encrypted Packet Payload",
            original_result="Valid Ciphertext",
            modified_result="Bit-flipped Ciphertext",
            expected_behavior="GCM tag verification failure and packet drop",
            actual_behavior=actual,
            detected=detected,
            status=AttackStatus.DETECTED if detected else AttackStatus.NOT_DETECTED,
        )
    except Exception as exc:
        return AttackResult(
            attack_id="ATK-01",
            attack_name="Ciphertext Tampering",
            description="Ciphertext bit-flip attack",
            target="Encrypted Packet Payload",
            original_result="Valid Ciphertext",
            modified_result="Bit-flipped Ciphertext",
            expected_behavior="GCM tag verification failure",
            actual_behavior=f"Unexpected error: {exc}",
            detected=False,
            status=AttackStatus.ERROR,
        )


def simulate_auth_tag_tampering() -> AttackResult:
    """Simulate modifying the 16-byte AES-GCM authentication tag."""
    try:
        fcc = FlightControlComputer()
        nav = NavigationComputer()
        fcc.establish_secure_session(nav)

        msg = fcc.create_heading_message(nav.component_id, heading_deg=275)
        envelope = fcc.encrypt_message(nav.component_id, msg)

        # GCM tag is the final 16 bytes of ciphertext
        tampered_ct = bytearray(envelope.ciphertext)
        tampered_ct[-1] ^= 0xAA

        tampered_envelope = EncryptedPacketEnvelope(
            packet_id=envelope.packet_id,
            sender_id=envelope.sender_id,
            receiver_id=envelope.receiver_id,
            nonce=envelope.nonce,
            ciphertext=bytes(tampered_ct),
            associated_data=envelope.associated_data,
            timestamp=envelope.timestamp,
        )

        detected = False
        try:
            nav.decrypt_message(tampered_envelope)
            actual = "TAMPERED TAG ACCEPTED (SECURITY VULNERABILITY)"
        except AuthenticationTagError:
            detected = True
            actual = "AuthenticationTagError raised; tampered tag rejected"

        return AttackResult(
            attack_id="ATK-02",
            attack_name="GCM Tag Tampering",
            description="Modifies the 128-bit authentication tag appended to the ciphertext",
            target="AES-256-GCM Authentication Tag",
            original_result="Valid Tag",
            modified_result="Corrupted Tag",
            expected_behavior="Cryptographic tag verification fails",
            actual_behavior=actual,
            detected=detected,
            status=AttackStatus.DETECTED if detected else AttackStatus.NOT_DETECTED,
        )
    except Exception as exc:
        return AttackResult(
            attack_id="ATK-02",
            attack_name="GCM Tag Tampering",
            description="Authentication tag modification",
            target="AES-GCM Tag",
            original_result="Valid Tag",
            modified_result="Corrupted Tag",
            expected_behavior="Tag verification failure",
            actual_behavior=f"Unexpected error: {exc}",
            detected=False,
            status=AttackStatus.ERROR,
        )


def simulate_aad_tampering() -> AttackResult:
    """Simulate modifying the Additional Authenticated Data (metadata) without modifying ciphertext."""
    try:
        fcc = FlightControlComputer()
        nav = NavigationComputer()
        fcc.establish_secure_session(nav)

        msg = fcc.create_flight_mode_message(nav.component_id, flight_mode="CRUISE")
        envelope = fcc.encrypt_message(nav.component_id, msg)

        # Tamper with AAD
        tampered_aad = b'{"forged_sender":"GROUND_ATTACKER","session_id":"fake"}'

        tampered_envelope = EncryptedPacketEnvelope(
            packet_id=envelope.packet_id,
            sender_id=envelope.sender_id,
            receiver_id=envelope.receiver_id,
            nonce=envelope.nonce,
            ciphertext=envelope.ciphertext,
            associated_data=tampered_aad,
            timestamp=envelope.timestamp,
        )

        detected = False
        try:
            nav.decrypt_message(tampered_envelope)
            actual = "TAMPERED AAD ACCEPTED (SECURITY VULNERABILITY)"
        except AuthenticationTagError:
            detected = True
            actual = "AuthenticationTagError raised; modified AAD rejected by AEAD integrity check"

        return AttackResult(
            attack_id="ATK-03",
            attack_name="AAD Tampering",
            description="Alters unencrypted authenticated metadata (sender, receiver, session ID)",
            target="AEAD Associated Authenticated Data (AAD)",
            original_result="Canonical AAD",
            modified_result="Tampered AAD",
            expected_behavior="Integrity check fails due to AAD mismatch",
            actual_behavior=actual,
            detected=detected,
            status=AttackStatus.DETECTED if detected else AttackStatus.NOT_DETECTED,
        )
    except Exception as exc:
        return AttackResult(
            attack_id="ATK-03",
            attack_name="AAD Tampering",
            description="AAD modification",
            target="AEAD AAD",
            original_result="Canonical AAD",
            modified_result="Tampered AAD",
            expected_behavior="Integrity failure",
            actual_behavior=f"Unexpected error: {exc}",
            detected=False,
            status=AttackStatus.ERROR,
        )


def simulate_ed25519_forgery() -> AttackResult:
    """Simulate forging an Ed25519 classical signature during handshake authentication."""
    try:
        fcc = FlightControlComputer()
        nav = NavigationComputer()

        # Substitute responder's Ed25519 private key with unauthorized attacker key
        attacker_ed_priv, _ = ed25519_generate_keypair()
        nav._ed_private_key = attacker_ed_priv

        handshake = HybridHandshake(initiator=fcc, responder=nav)
        detected = False
        try:
            handshake.run()
            actual = "FORGED ED25519 SIGNATURE ACCEPTED (SECURITY VULNERABILITY)"
        except HandshakeAuthenticationError:
            detected = True
            actual = "HandshakeAuthenticationError raised; Ed25519 signature rejected, session transitioned to FAILED"

        return AttackResult(
            attack_id="ATK-04",
            attack_name="Ed25519 Forgery",
            description="Substitutes unauthorized Ed25519 signing key during handshake transcript authentication",
            target="Classical Digital Signature (Ed25519)",
            original_result="Authentic Signature",
            modified_result="Forged Signature",
            expected_behavior="Handshake aborted with authentication failure",
            actual_behavior=actual,
            detected=detected,
            status=AttackStatus.DETECTED if detected else AttackStatus.NOT_DETECTED,
        )
    except Exception as exc:
        return AttackResult(
            attack_id="ATK-04",
            attack_name="Ed25519 Forgery",
            description="Ed25519 signature substitution",
            target="Ed25519 Signature",
            original_result="Authentic Signature",
            modified_result="Forged Signature",
            expected_behavior="Authentication failure",
            actual_behavior=f"Unexpected error: {exc}",
            detected=False,
            status=AttackStatus.ERROR,
        )


def simulate_slhdsa_forgery() -> AttackResult:
    """Simulate forging an SLH-DSA post-quantum signature during handshake authentication."""
    try:
        fcc = FlightControlComputer()
        nav = NavigationComputer()

        # Substitute responder's SLH-DSA secret key with unauthorized attacker key
        attacker_slh_sec, _ = slhdsa_generate_keypair("shake_128f")
        nav._slh_secret_key = attacker_slh_sec

        handshake = HybridHandshake(initiator=fcc, responder=nav)
        detected = False
        try:
            handshake.run()
            actual = "FORGED SLH-DSA SIGNATURE ACCEPTED (SECURITY VULNERABILITY)"
        except HandshakeAuthenticationError:
            detected = True
            actual = "HandshakeAuthenticationError raised; SLH-DSA signature rejected, session transitioned to FAILED"

        return AttackResult(
            attack_id="ATK-05",
            attack_name="SLH-DSA Forgery",
            description="Substitutes unauthorized SLH-DSA post-quantum secret key during handshake authentication",
            target="Post-Quantum Digital Signature (SLH-DSA FIPS 205)",
            original_result="Authentic Signature",
            modified_result="Forged Signature",
            expected_behavior="Handshake aborted with post-quantum authentication failure",
            actual_behavior=actual,
            detected=detected,
            status=AttackStatus.DETECTED if detected else AttackStatus.NOT_DETECTED,
        )
    except Exception as exc:
        return AttackResult(
            attack_id="ATK-05",
            attack_name="SLH-DSA Forgery",
            description="SLH-DSA signature substitution",
            target="SLH-DSA Signature",
            original_result="Authentic Signature",
            modified_result="Forged Signature",
            expected_behavior="Post-quantum authentication failure",
            actual_behavior=f"Unexpected error: {exc}",
            detected=False,
            status=AttackStatus.ERROR,
        )


def simulate_transcript_modification() -> AttackResult:
    """Simulate altering the canonical handshake transcript before signature verification."""
    try:
        from backend.crypto import (
            mlkem_encapsulate,
            mlkem_generate_keypair,
            x25519_generate_keypair,
        )

        fcc = FlightControlComputer()
        nav = NavigationComputer()

        init_x_priv, init_x_pub = x25519_generate_keypair()
        _, init_ml_pub = mlkem_generate_keypair("ML-KEM-1024")
        resp_x_priv, resp_x_pub = x25519_generate_keypair()
        _, mlkem_ct = mlkem_encapsulate(init_ml_pub, "ML-KEM-1024")

        # Legitimate transcript
        legit_transcript = compute_canonical_transcript(
            protocol_version="AVIONICS-PQC-V1",
            initiator_id=fcc.component_id,
            responder_id=nav.component_id,
            initiator_x25519_pub=init_x_pub,
            initiator_mlkem_pub=init_ml_pub,
            responder_x25519_pub=resp_x_pub,
            mlkem_ciphertext=mlkem_ct,
        )
        legit_hash = hashlib.sha256(legit_transcript).digest()

        # Sign legitimate transcript
        ed_sig = ed25519_sign(fcc._ed_private_key, legit_hash)
        slh_sig = slhdsa_sign(fcc._slh_secret_key, legit_hash, "shake_128f")

        # Attacker modifies transcript (e.g. injects rogue parameter)
        tampered_transcript = compute_canonical_transcript(
            protocol_version="AVIONICS-PQC-V1",
            initiator_id="AIRCRAFT-ROGUE-FCC",
            responder_id=nav.component_id,
            initiator_x25519_pub=init_x_pub,
            initiator_mlkem_pub=init_ml_pub,
            responder_x25519_pub=resp_x_pub,
            mlkem_ciphertext=mlkem_ct,
        )
        tampered_hash = hashlib.sha256(tampered_transcript).digest()

        # Verification
        ed_valid = ed25519_verify(fcc.ed25519_public_key, tampered_hash, ed_sig)
        slh_valid = slhdsa_verify(fcc.slhdsa_public_key, tampered_hash, slh_sig, "shake_128f")

        detected = (not ed_valid) and (not slh_valid)
        actual = "Signatures on modified transcript hash evaluated to False; session rejected"

        return AttackResult(
            attack_id="ATK-06",
            attack_name="Handshake Transcript Modification",
            description="Modifies initiator identity and protocol context in canonical transcript",
            target="Handshake Transcript & Hash",
            original_result="Authentic Transcript Hash",
            modified_result="Tampered Transcript Hash",
            expected_behavior="Signature verification fails on tampered transcript hash",
            actual_behavior=actual,
            detected=detected,
            status=AttackStatus.DETECTED if detected else AttackStatus.NOT_DETECTED,
        )
    except Exception as exc:
        return AttackResult(
            attack_id="ATK-06",
            attack_name="Handshake Transcript Modification",
            description="Handshake transcript tampering",
            target="Transcript Hash",
            original_result="Authentic Hash",
            modified_result="Tampered Hash",
            expected_behavior="Signature verification failure",
            actual_behavior=f"Unexpected error: {exc}",
            detected=False,
            status=AttackStatus.ERROR,
        )


def simulate_wrong_session_attack() -> AttackResult:
    """Simulate delivering a message encrypted under Session A to a node holding only Session B."""
    try:
        fcc1 = FlightControlComputer()
        nav1 = NavigationComputer()
        fcc1.establish_secure_session(nav1)

        fcc2 = FlightControlComputer(component_id="AIRCRAFT-002-FCC")
        nav2 = NavigationComputer(component_id="AIRCRAFT-002-NAV")
        fcc2.establish_secure_session(nav2)

        # Message encrypted under Session 1
        msg = fcc1.create_altitude_message(nav1.component_id, altitude_ft=32000)
        envelope = fcc1.encrypt_message(nav1.component_id, msg)

        # Retarget envelope headers to simulate cross-session injection into nav2
        spoofed_envelope = EncryptedPacketEnvelope(
            packet_id=envelope.packet_id,
            sender_id=fcc2.component_id,
            receiver_id=nav2.component_id,
            nonce=envelope.nonce,
            ciphertext=envelope.ciphertext,
            associated_data=envelope.associated_data,
            timestamp=envelope.timestamp,
        )

        detected = False
        try:
            nav2.decrypt_message(spoofed_envelope)
            actual = "CROSS-SESSION MESSAGE ACCEPTED (SECURITY VULNERABILITY)"
        except (AuthenticationTagError, ProtocolError):
            detected = True
            actual = "AuthenticationTagError/ProtocolError raised; key and AAD session ID mismatch detected"

        return AttackResult(
            attack_id="ATK-07",
            attack_name="Wrong Session Confusion",
            description="Injects packet encrypted under Session A into an independent Session B",
            target="Session Isolation & Key Separation",
            original_result="Session A Ciphertext",
            modified_result="Injected into Session B",
            expected_behavior="Decryption fails due to distinct session keys and session ID AAD binding",
            actual_behavior=actual,
            detected=detected,
            status=AttackStatus.DETECTED if detected else AttackStatus.NOT_DETECTED,
        )
    except Exception as exc:
        return AttackResult(
            attack_id="ATK-07",
            attack_name="Wrong Session Confusion",
            description="Cross-session injection",
            target="Session Key Isolation",
            original_result="Session A",
            modified_result="Session B Injection",
            expected_behavior="Decryption failure",
            actual_behavior=f"Unexpected error: {exc}",
            detected=False,
            status=AttackStatus.ERROR,
        )


def simulate_wrong_receiver_attack() -> AttackResult:
    """Simulate delivering a message intended for GCS to NAV."""
    try:
        fcc = FlightControlComputer()
        nav = NavigationComputer()
        gcs = GroundControlStation()

        fcc.establish_secure_session(nav)
        fcc.establish_secure_session(gcs)

        # FCC creates message specifically for GCS
        msg_for_gcs = fcc.create_status_message(gcs.component_id, status="NOMINAL")
        envelope_for_gcs = fcc.encrypt_message(gcs.component_id, msg_for_gcs)

        detected = False
        try:
            nav.decrypt_message(envelope_for_gcs)
            actual = "WRONG RECEIVER MESSAGE ACCEPTED (SECURITY VULNERABILITY)"
        except ProtocolError:
            detected = True
            actual = "ProtocolError raised; receiver ID mismatch caught before/during processing"

        return AttackResult(
            attack_id="ATK-08",
            attack_name="Wrong Receiver Spoofing",
            description="Redirects message addressed to GCS to NAV computer",
            target="Receiver Identity Validation",
            original_result="Destined for GCS",
            modified_result="Redirected to NAV",
            expected_behavior="Receiver rejects packet due to component ID mismatch",
            actual_behavior=actual,
            detected=detected,
            status=AttackStatus.DETECTED if detected else AttackStatus.NOT_DETECTED,
        )
    except Exception as exc:
        return AttackResult(
            attack_id="ATK-08",
            attack_name="Wrong Receiver Spoofing",
            description="Receiver redirection",
            target="Receiver Validation",
            original_result="Destined for GCS",
            modified_result="Delivered to NAV",
            expected_behavior="Receiver mismatch rejection",
            actual_behavior=f"Unexpected error: {exc}",
            detected=False,
            status=AttackStatus.ERROR,
        )


def simulate_replay_attack() -> AttackResult:
    """Simulate replaying an exact duplicate legitimate encrypted message."""
    try:
        fcc = FlightControlComputer()
        nav = NavigationComputer()
        fcc.establish_secure_session(nav)

        msg = fcc.create_altitude_message(nav.component_id, altitude_ft=32000)
        envelope = fcc.encrypt_message(nav.component_id, msg)

        # First delivery: should succeed
        nav.decrypt_message(envelope)

        # Replay duplicate envelope: should be rejected
        detected = False
        try:
            nav.decrypt_message(envelope)
            actual = "REPLAYED MESSAGE ACCEPTED (REPLAY PROTECTION INEFFECTIVE)"
        except ReplayAttackError:
            detected = True
            actual = "ReplayAttackError raised; duplicate nonce detected and rejected"

        return AttackResult(
            attack_id="ATK-09",
            attack_name="Replay Attack",
            description="Re-transmits previously captured legitimate encrypted packet",
            target="Nonce Freshness & Replay Filter",
            original_result="Accepted (1st Transmission)",
            modified_result="Replayed (2nd Transmission)",
            expected_behavior="Replay filter detects duplicate nonce and rejects duplicate packet",
            actual_behavior=actual,
            detected=detected,
            status=AttackStatus.DETECTED if detected else AttackStatus.NOT_DETECTED,
        )
    except Exception as exc:
        return AttackResult(
            attack_id="ATK-09",
            attack_name="Replay Attack",
            description="Packet replay",
            target="Nonce Freshness",
            original_result="Accepted",
            modified_result="Replayed",
            expected_behavior="Rejection of replayed packet",
            actual_behavior=f"Unexpected error: {exc}",
            detected=False,
            status=AttackStatus.ERROR,
        )


# =====================================================================
# Attack Simulation Suite Runner
# =====================================================================


def run_all_attack_simulations() -> list[AttackResult]:
    """Execute all security attack simulations in sequence."""
    simulations = [
        run_baseline_test,
        simulate_ciphertext_tampering,
        simulate_auth_tag_tampering,
        simulate_aad_tampering,
        simulate_ed25519_forgery,
        simulate_slhdsa_forgery,
        simulate_transcript_modification,
        simulate_wrong_session_attack,
        simulate_wrong_receiver_attack,
        simulate_replay_attack,
    ]

    results = []
    for sim in simulations:
        results.append(sim())
    return results

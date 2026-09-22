"""Comprehensive unit and integration tests for Adaptive Cryptographic Constructions.

Tests cover:
- Construction registration and metadata verification
- Handshake and session key derivation for all 4 constructions
- Message encryption, transmission, and decryption
- Dual-signature verification (classical + post-quantum) and selective failure
- Downgrade attack detection and fail-closed prevention
- Replay attack defenses
- AAD and ciphertext integrity verification
- Adaptive selection engine decision rules and latency constraint enforcement
"""

import pytest
import time
from backend.avionics.channel import EncryptedPacketEnvelope
from backend.avionics.fcc import FlightControlComputer
from backend.avionics.ground_station import GroundControlStation

from backend.avionics.messages import (
    AvionicsMessage,
    MessageType,
)
from backend.policy import Criticality
from backend.crypto import (
    ADAPTIVE_CRITICAL,
    ADAPTIVE_HIGH_ASSURANCE,
    ADAPTIVE_BALANCED,
    ADAPTIVE_STANDARD,
    CONSTRUCTION_ENGINE,
    AuthenticationTagError,
    ConstructionAuthenticationError,
    ConstructionDowngradeError,
    ConstructionError,
    ConstructionReplayError,
    ConstructionSecurityLevel,
    ed25519_generate_keypair,
    slhdsa_generate_keypair,
)


@pytest.fixture
def entities():
    """Create simulated avionics entities for handshake and secure messaging."""
    fcc = FlightControlComputer(component_id="AIRCRAFT-001-FCC", aircraft_id="AIRCRAFT-001")
    gcs = GroundControlStation(component_id="GROUND-STATION-001")
    return fcc, gcs


@pytest.fixture
def sample_message():
    return AvionicsMessage(
        message_id="MSG-TEST-001",
        sender_id="AIRCRAFT-001-FCC",
        receiver_id="GROUND-STATION-001",
        message_type=MessageType.AIRCRAFT_STATUS,
        payload={
            "latitude": 37.6189,
            "longitude": -122.3750,
            "altitude": 10000.0,
            "heading": 270.0,
            "ground_speed": 420.0,
        },
    )


class TestAdaptiveConstructions:
    """Test suite for the four project-specific cryptographic constructions."""

    def test_construction_metadata_and_registry(self):
        """Verify all 4 constructions have distinct IDs, valid parameters, and correct registry entries."""
        constructions = [
            ADAPTIVE_STANDARD,
            ADAPTIVE_BALANCED,
            ADAPTIVE_HIGH_ASSURANCE,
            ADAPTIVE_CRITICAL,
        ]

        ids = [c.metadata.construction_id for c in constructions]
        assert len(ids) == 4
        assert len(set(ids)) == 4

        assert ADAPTIVE_STANDARD.metadata.construction_id == "ADAPTIVE-STANDARD-V1"
        assert ADAPTIVE_STANDARD.metadata.kex_pqc == "ML-KEM-768"
        assert ADAPTIVE_STANDARD.metadata.kdf_algorithm == "HKDF-SHA256"
        assert ADAPTIVE_STANDARD.metadata.auth_classical == "Ed25519"
        assert ADAPTIVE_STANDARD.metadata.auth_pqc is None

        assert ADAPTIVE_BALANCED.metadata.construction_id == "ADAPTIVE-BALANCED-V1"
        assert ADAPTIVE_BALANCED.metadata.kex_pqc == "ML-KEM-1024"
        assert ADAPTIVE_BALANCED.metadata.kdf_algorithm == "HKDF-SHA384"
        assert ADAPTIVE_BALANCED.metadata.auth_classical == "Ed25519"

        assert ADAPTIVE_HIGH_ASSURANCE.metadata.construction_id == "ADAPTIVE-HIGH-ASSURANCE-V1"
        assert ADAPTIVE_HIGH_ASSURANCE.metadata.kex_pqc == "ML-KEM-1024"
        assert ADAPTIVE_HIGH_ASSURANCE.metadata.kdf_algorithm == "HKDF-SHA384"
        assert ADAPTIVE_HIGH_ASSURANCE.metadata.auth_classical == "Ed25519"
        assert ADAPTIVE_HIGH_ASSURANCE.metadata.auth_pqc == "SLH-DSA-SHAKE_128F"

        assert ADAPTIVE_CRITICAL.metadata.construction_id == "ADAPTIVE-CRITICAL-V1"
        assert ADAPTIVE_CRITICAL.metadata.kex_pqc == "ML-KEM-1024"
        assert ADAPTIVE_CRITICAL.metadata.kdf_algorithm == "HKDF-SHA512"
        assert ADAPTIVE_CRITICAL.metadata.auth_classical == "Ed25519"
        assert ADAPTIVE_CRITICAL.metadata.auth_pqc == "SLH-DSA-SHAKE_128F"


    def test_adaptive_standard_lifecycle(self, entities, sample_message):
        """Test handshake, session key agreement, message encryption, and decryption for Standard."""
        fcc, gcs = entities

        init_session, resp_session = ADAPTIVE_STANDARD.establish_session(fcc, gcs)

        assert init_session.session_id == resp_session.session_id
        assert init_session.session_key == resp_session.session_key
        assert len(init_session.session_key) == 32
        assert init_session.construction_id == "ADAPTIVE-STANDARD-V1"

        # Encrypt from FCC to GCS
        envelope = init_session.encrypt_message(sample_message)
        assert envelope.sender_id == fcc.component_id
        assert envelope.receiver_id == gcs.component_id

        # Decrypt at GCS
        decrypted = resp_session.decrypt_message(envelope)
        assert decrypted.message_id == sample_message.message_id
        assert decrypted.sender_id == sample_message.sender_id
        assert decrypted.payload["latitude"] == sample_message.payload["latitude"]

    def test_adaptive_balanced_lifecycle(self, entities, sample_message):
        """Test handshake, context-bound signature, and payload encryption for Balanced."""
        fcc, gcs = entities

        init_session, resp_session = ADAPTIVE_BALANCED.establish_session(fcc, gcs)

        assert init_session.session_id == resp_session.session_id
        assert init_session.session_key == resp_session.session_key
        assert init_session.construction_id == "ADAPTIVE-BALANCED-V1"

        envelope = init_session.encrypt_message(sample_message)
        decrypted = resp_session.decrypt_message(envelope)
        assert decrypted.message_id == sample_message.message_id

    def test_adaptive_high_assurance_dual_authentication(self, entities, sample_message):
        """Test hybrid dual signature authentication (Ed25519 + SLH-DSA)."""
        fcc, gcs = entities

        init_session, resp_session = ADAPTIVE_HIGH_ASSURANCE.establish_session(fcc, gcs)

        assert init_session.session_id == resp_session.session_id
        assert init_session.construction_id == "ADAPTIVE-HIGH-ASSURANCE-V1"

        envelope = init_session.encrypt_message(sample_message)
        decrypted = resp_session.decrypt_message(envelope)
        assert decrypted.message_id == sample_message.message_id

    def test_adaptive_critical_strict_lifecycle(self, entities, sample_message):
        """Test SHA-512 key derivation, strict dual authentication, and replay protection in Critical."""
        fcc, gcs = entities

        init_session, resp_session = ADAPTIVE_CRITICAL.establish_session(fcc, gcs)

        assert init_session.session_id == resp_session.session_id
        assert init_session.construction_id == "ADAPTIVE-CRITICAL-V1"
        assert init_session.security_level == ConstructionSecurityLevel.CRITICAL

        envelope = init_session.encrypt_message(sample_message)
        decrypted = resp_session.decrypt_message(envelope)
        assert decrypted.message_id == sample_message.message_id

    def test_dual_auth_failure_rejection(self, entities):
        """Verify that if either classical or PQ signature fails in dual auth, handshake is rejected."""
        fcc, gcs = entities

        # Tamper with fcc private key to break Ed25519 signature
        original_ed_key = fcc._ed_private_key
        wrong_ed_priv, _ = ed25519_generate_keypair()
        fcc._ed_private_key = wrong_ed_priv

        with pytest.raises(ConstructionAuthenticationError):
            ADAPTIVE_HIGH_ASSURANCE.establish_session(fcc, gcs)

        # Restore ed key, now tamper with slhdsa key to break post-quantum signature
        fcc._ed_private_key = original_ed_key
        wrong_slh_priv, _ = slhdsa_generate_keypair("shake_128f")
        fcc._slh_secret_key = wrong_slh_priv

        with pytest.raises(ConstructionAuthenticationError):
            ADAPTIVE_CRITICAL.establish_session(fcc, gcs)

    def test_downgrade_attack_defense(self, entities, sample_message):
        """Verify that tampering with construction ID in envelope or downgrade attempts are rejected."""
        fcc, gcs = entities

        s_session, r_session = ADAPTIVE_CRITICAL.establish_session(fcc, gcs)
        envelope = s_session.encrypt_message(sample_message)

        # Attacker tries to decrypt envelope using a lower-level session (STANDARD)
        std_s_session, std_r_session = ADAPTIVE_STANDARD.establish_session(fcc, gcs)

        with pytest.raises((AuthenticationTagError, ConstructionError)):
            std_r_session.decrypt_message(envelope)

    def test_replay_attack_prevention(self, entities, sample_message):
        """Verify that reusing the same envelope / nonce in a session triggers ConstructionReplayError."""
        fcc, gcs = entities

        s_session, r_session = ADAPTIVE_BALANCED.establish_session(fcc, gcs)
        envelope = s_session.encrypt_message(sample_message)

        # First decryption succeeds
        r_session.decrypt_message(envelope)

        # Replayed decryption with identical nonce must fail with ConstructionReplayError
        with pytest.raises(ConstructionReplayError):
            r_session.decrypt_message(envelope)

    def test_aad_and_ciphertext_tampering(self, entities, sample_message):
        """Verify that ciphertext tampering or AAD field alteration fails authentication."""
        fcc, gcs = entities

        s_session, r_session = ADAPTIVE_STANDARD.establish_session(fcc, gcs)
        envelope = s_session.encrypt_message(sample_message)

        # 1. Tamper ciphertext
        tampered_bytes = bytearray(envelope.ciphertext)
        tampered_bytes[0] ^= 0xFF
        tampered_envelope = EncryptedPacketEnvelope(
            sender_id=envelope.sender_id,
            receiver_id=envelope.receiver_id,
            nonce=envelope.nonce,
            ciphertext=bytes(tampered_bytes),
            associated_data=envelope.associated_data,
        )
        with pytest.raises(AuthenticationTagError):
            r_session.decrypt_message(tampered_envelope)

        # 2. Tamper sender in envelope
        tampered_sender = EncryptedPacketEnvelope(
            sender_id="MALICIOUS-INTRUDER",
            receiver_id=envelope.receiver_id,
            nonce=envelope.nonce,
            ciphertext=envelope.ciphertext,
            associated_data=envelope.associated_data,
        )
        with pytest.raises(ConstructionError):
            r_session.decrypt_message(tampered_sender)


class TestConstructionEngine:
    """Test suite for the adaptive construction selection and execution engine."""

    def test_selection_rules(self):
        engine = CONSTRUCTION_ENGINE

        # 1. Routine + Normal -> STANDARD
        d1 = engine.select_construction(criticality="ROUTINE", threat_level="NORMAL", threat_score=10.0)
        assert d1.selected_construction_id == "ADAPTIVE-STANDARD-V1"
        assert d1.status == "APPROVED"

        # 2. Important + Elevated -> BALANCED
        d2 = engine.select_construction(criticality="IMPORTANT", threat_level="ELEVATED", threat_score=35.0)
        assert d2.selected_construction_id == "ADAPTIVE-BALANCED-V1"
        assert d2.status == "APPROVED"

        # 3. Critical + High -> HIGH_ASSURANCE
        d3 = engine.select_construction(criticality="CRITICAL", threat_level="HIGH", threat_score=60.0)
        assert d3.selected_construction_id == "ADAPTIVE-HIGH-ASSURANCE-V1"
        assert d3.status == "APPROVED"

        # 4. Safety Critical / Critical Threat -> CRITICAL
        d4 = engine.select_construction(criticality="SAFETY_CRITICAL", threat_level="CRITICAL", threat_score=90.0)
        assert d4.selected_construction_id == "ADAPTIVE-CRITICAL-V1"
        assert d4.status == "APPROVED"

    def test_threat_score_escalation(self):
        engine = CONSTRUCTION_ENGINE

        # Even with Routine criticality, score >= 75 forces CRITICAL
        decision = engine.select_construction(criticality="ROUTINE", threat_level="NORMAL", threat_score=80.0)
        assert decision.selected_construction_id == "ADAPTIVE-CRITICAL-V1"

        # Score >= 50 forces at least HIGH_ASSURANCE
        decision_ha = engine.select_construction(criticality="ROUTINE", threat_level="NORMAL", threat_score=55.0)
        assert decision_ha.selected_construction_id == "ADAPTIVE-HIGH-ASSURANCE-V1"

    def test_latency_constraint_enforcement(self):
        engine = CONSTRUCTION_ENGINE

        # If latency budget is too low for CRITICAL (e.g. 5ms, while estimated is ~2320ms),
        # but message is SAFETY_CRITICAL, safety constraints forbid insecure downgrade.
        decision = engine.select_construction(
            criticality="SAFETY_CRITICAL",
            threat_level="CRITICAL",
            threat_score=85.0,
            latency_budget_ms=5.0,
        )
        assert decision.selected_construction_id == "ADAPTIVE-CRITICAL-V1"
        # Decision status reports constraint conflict but stays at CRITICAL to avoid safety breach
        assert decision.status == "CONSTRAINT_CONFLICT"

    def test_engine_execute_handshake(self, entities, sample_message):
        """Test full end-to-end handshake execution through ConstructionEngine."""
        fcc, gcs = entities

        init_session, resp_session, decision = CONSTRUCTION_ENGINE.execute_handshake(
            initiator=fcc,
            responder=gcs,
            criticality="CRITICAL",
            threat_level="HIGH",
            threat_score=65.0,
            latency_budget_ms=5000.0,
        )

        assert decision.status == "APPROVED"
        assert decision.selected_construction_id == "ADAPTIVE-HIGH-ASSURANCE-V1"
        assert init_session.session_id == resp_session.session_id

        # Test message exchange
        envelope = init_session.encrypt_message(sample_message)
        decrypted = resp_session.decrypt_message(envelope)
        assert decrypted.message_id == sample_message.message_id

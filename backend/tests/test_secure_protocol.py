"""Comprehensive integration and failure tests for hybrid post-quantum secure protocol (Phase 4)."""

import hashlib
import json
import pytest
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
    AESGCMError,
    AuthenticationTagError,
    ed25519_generate_keypair,
    slhdsa_generate_keypair,
)
from backend.protocol import (
    HandshakeAuthenticationError,
    HandshakeState,
    HybridHandshake,
    ProtocolError,
    SecureSession,
    compute_canonical_transcript,
    construct_message_aad,
    perform_handshake,
)


def test_complete_fcc_to_nav_hybrid_secure_handshake_and_messaging():
    """Test the full end-to-end hybrid secure protocol between FCC and NAV."""
    fcc = FlightControlComputer()
    nav = NavigationComputer()
    channel = SimulatedChannel(name="UNTRUSTED_AIRBORNE_BUS")

    # 1. Execute Handshake
    handshake = HybridHandshake(initiator=fcc, responder=nav, mlkem_param="ML-KEM-1024", slhdsa_param="shake_128f")
    init_session, resp_session = handshake.run()

    # Verify Handshake States
    assert handshake.initiator_state == HandshakeState.ESTABLISHED
    assert handshake.responder_state == HandshakeState.ESTABLISHED
    assert init_session.state == HandshakeState.ESTABLISHED
    assert resp_session.state == HandshakeState.ESTABLISHED

    # Verify Session Keys match and are 32 bytes (256 bits)
    assert init_session.session_key == resp_session.session_key
    assert len(init_session.session_key) == 32
    assert init_session.session_id == resp_session.session_id
    assert len(init_session.session_id) == 64  # SHA-256 hex digest

    # Verify entities have registered the sessions
    assert fcc.has_session(nav.component_id)
    assert nav.has_session(fcc.component_id)

    # 2. Create and Encrypt Avionics Message
    original_msg = fcc.create_altitude_message(nav.component_id, altitude_ft=32000)
    assert original_msg.display_string() == "ALTITUDE = 32000 FT"

    # Send across untrusted channel
    envelope = fcc.send_via_channel(nav.component_id, original_msg, channel)

    assert channel.total_packets_transmitted == 1
    # Untrusted channel cannot access plaintext
    assert b"ALTITUDE" not in envelope.ciphertext
    assert b"32000" not in envelope.ciphertext

    # 3. NAV receives and decrypts message
    recovered_msg = nav.decrypt_message(envelope)
    assert recovered_msg.message_id == original_msg.message_id
    assert recovered_msg.sender_id == fcc.component_id
    assert recovered_msg.receiver_id == nav.component_id
    assert recovered_msg.message_type == MessageType.ALTITUDE
    assert recovered_msg.payload == {"altitude_ft": 32000}
    assert recovered_msg.display_string() == "ALTITUDE = 32000 FT"
    assert nav.get_latest_received_display() == "ALTITUDE = 32000 FT"


def test_gcs_to_fcc_and_gcs_to_nav_sessions():
    """Test that Ground Control Station can establish independent secure sessions with both FCC and NAV."""
    gcs = GroundControlStation()
    fcc = FlightControlComputer()
    nav = NavigationComputer()
    channel = SimulatedChannel(name="SATCOM_LINK")

    # GCS <-> FCC Handshake
    gcs_fcc_session = gcs.establish_secure_session(fcc)
    assert gcs.has_session(fcc.component_id)
    assert fcc.has_session(gcs.component_id)

    # GCS <-> NAV Handshake
    gcs_nav_session = gcs.establish_secure_session(nav)
    assert gcs.has_session(nav.component_id)
    assert nav.has_session(gcs.component_id)

    # Distinct sessions have distinct session IDs and distinct keys
    assert gcs_fcc_session.session_id != gcs_nav_session.session_id
    assert gcs_fcc_session.session_key != gcs_nav_session.session_key

    # GCS sends command to FCC
    cmd_msg = gcs.create_command_message(
        receiver_id=fcc.component_id,
        message_type=MessageType.FLIGHT_MODE,
        payload={"flight_mode": "APPROACH"},
    )
    envelope = gcs.send_via_channel(fcc.component_id, cmd_msg, channel)
    recovered_cmd = fcc.decrypt_message(envelope)
    assert recovered_cmd.payload == {"flight_mode": "APPROACH"}


# =====================================================================
# FAILURE AND TAMPERING TESTS
# =====================================================================


def test_failure_wrong_ed25519_signature_rejected():
    """Failure Test 1: Invalid Ed25519 signature causes handshake authentication failure."""
    fcc = FlightControlComputer()
    nav = NavigationComputer()

    # Tamper with responder's Ed25519 private key so signature is signed by unauthorized key
    impostor_ed_priv, _ = ed25519_generate_keypair()
    nav._ed_private_key = impostor_ed_priv

    handshake = HybridHandshake(initiator=fcc, responder=nav)
    with pytest.raises(HandshakeAuthenticationError, match="Ed25519"):
        handshake.run()

    assert handshake.initiator_state == HandshakeState.FAILED
    assert handshake.responder_state == HandshakeState.FAILED


def test_failure_wrong_slhdsa_signature_rejected():
    """Failure Test 2: Invalid SLH-DSA signature causes handshake authentication failure."""
    fcc = FlightControlComputer()
    nav = NavigationComputer()

    # Tamper with responder's SLH-DSA secret key so signature is signed by unauthorized key
    impostor_slh_sec, _ = slhdsa_generate_keypair("shake_128f")
    nav._slh_secret_key = impostor_slh_sec

    handshake = HybridHandshake(initiator=fcc, responder=nav)
    with pytest.raises(HandshakeAuthenticationError, match="SLH-DSA"):
        handshake.run()

    assert handshake.initiator_state == HandshakeState.FAILED
    assert handshake.responder_state == HandshakeState.FAILED


def test_failure_modified_handshake_transcript_rejected():
    """Failure Test 3: Modification to transcript or key material causes authentication failure."""
    fcc = FlightControlComputer()
    nav = NavigationComputer()

    # If an attacker alters the transcript before verification, signature checks must fail
    handshake = HybridHandshake(initiator=fcc, responder=nav)

    # Generate legitimate keypairs
    from backend.crypto import x25519_generate_keypair, mlkem_generate_keypair, mlkem_encapsulate, ed25519_sign, slhdsa_sign

    init_x_priv, init_x_pub = x25519_generate_keypair()
    _, init_ml_pub = mlkem_generate_keypair("ML-KEM-1024")
    resp_x_priv, resp_x_pub = x25519_generate_keypair()
    _, mlkem_ct = mlkem_encapsulate(init_ml_pub, "ML-KEM-1024")

    # Original transcript
    transcript = compute_canonical_transcript(
        protocol_version="AVIONICS-PQC-V1",
        initiator_id=fcc.component_id,
        responder_id=nav.component_id,
        initiator_x25519_pub=init_x_pub,
        initiator_mlkem_pub=init_ml_pub,
        responder_x25519_pub=resp_x_pub,
        mlkem_ciphertext=mlkem_ct,
    )
    transcript_hash = hashlib.sha256(transcript).digest()

    # Sign original transcript
    ed_sig = ed25519_sign(nav._ed_private_key, transcript_hash)
    slh_sig = slhdsa_sign(nav._slh_secret_key, transcript_hash, "shake_128f")

    # Attacker alters transcript (e.g. injects different initiator_id)
    tampered_transcript = compute_canonical_transcript(
        protocol_version="AVIONICS-PQC-V1",
        initiator_id="MALICIOUS-INTRUDER-NODE",
        responder_id=nav.component_id,
        initiator_x25519_pub=init_x_pub,
        initiator_mlkem_pub=init_ml_pub,
        responder_x25519_pub=resp_x_pub,
        mlkem_ciphertext=mlkem_ct,
    )
    tampered_hash = hashlib.sha256(tampered_transcript).digest()

    # Verification against tampered transcript must fail
    from backend.crypto import ed25519_verify, slhdsa_verify
    assert ed25519_verify(nav.ed25519_public_key, tampered_hash, ed_sig) is False
    assert slhdsa_verify(nav.slhdsa_public_key, tampered_hash, slh_sig, "shake_128f") is False


def test_failure_modified_ciphertext_rejected():
    """Failure Test 4: Tampered ciphertext bytes are rejected by GCM tag verification."""
    fcc = FlightControlComputer()
    nav = NavigationComputer()
    fcc.establish_secure_session(nav)

    msg = fcc.create_heading_message(nav.component_id, heading_deg=275)
    envelope = fcc.encrypt_message(nav.component_id, msg)

    tampered_ct = bytearray(envelope.ciphertext)
    tampered_ct[2] ^= 0xFF

    tampered_envelope = EncryptedPacketEnvelope(
        packet_id=envelope.packet_id,
        sender_id=envelope.sender_id,
        receiver_id=envelope.receiver_id,
        nonce=envelope.nonce,
        ciphertext=bytes(tampered_ct),
        associated_data=envelope.associated_data,
        timestamp=envelope.timestamp,
    )

    with pytest.raises(AuthenticationTagError):
        nav.decrypt_message(tampered_envelope)


def test_failure_modified_gcm_tag_rejected():
    """Failure Test 5: Tampering with 16-byte GCM authentication tag causes rejection."""
    fcc = FlightControlComputer()
    nav = NavigationComputer()
    fcc.establish_secure_session(nav)

    msg = fcc.create_flight_mode_message(nav.component_id, flight_mode="CRUISE")
    envelope = fcc.encrypt_message(nav.component_id, msg)

    # GCM tag is the final 16 bytes of ciphertext
    tampered_ct = bytearray(envelope.ciphertext)
    tampered_ct[-1] ^= 0x01

    tampered_envelope = EncryptedPacketEnvelope(
        packet_id=envelope.packet_id,
        sender_id=envelope.sender_id,
        receiver_id=envelope.receiver_id,
        nonce=envelope.nonce,
        ciphertext=bytes(tampered_ct),
        associated_data=envelope.associated_data,
        timestamp=envelope.timestamp,
    )

    with pytest.raises(AuthenticationTagError):
        nav.decrypt_message(tampered_envelope)


def test_failure_modified_aad_rejected():
    """Failure Test 6: Tampering with authenticated metadata (AAD) causes rejection."""
    fcc = FlightControlComputer()
    nav = NavigationComputer()
    fcc.establish_secure_session(nav)

    msg = fcc.create_status_message(nav.component_id, status="NOMINAL")
    envelope = fcc.encrypt_message(nav.component_id, msg)

    # Modify AAD (e.g. attacker alters metadata)
    tampered_envelope = EncryptedPacketEnvelope(
        packet_id=envelope.packet_id,
        sender_id=envelope.sender_id,
        receiver_id=envelope.receiver_id,
        nonce=envelope.nonce,
        ciphertext=envelope.ciphertext,
        associated_data=b'{"altered":"metadata"}',
        timestamp=envelope.timestamp,
    )

    with pytest.raises(AuthenticationTagError):
        nav.decrypt_message(tampered_envelope)


def test_failure_wrong_session_id_rejected():
    """Failure Test 7: Envelope with incorrect session ID in AAD is rejected."""
    fcc = FlightControlComputer()
    nav = NavigationComputer()
    session = fcc.establish_secure_session(nav)

    msg = fcc.create_altitude_message(nav.component_id, altitude_ft=32000)
    envelope = fcc.encrypt_message(nav.component_id, msg)

    # Construct AAD with fraudulent session ID
    spoofed_aad = construct_message_aad(
        protocol_version="AVIONICS-PQC-V1",
        session_id="0000000000000000000000000000000000000000000000000000000000000000",
        sender_id=msg.sender_id,
        receiver_id=msg.receiver_id,
        message_id=msg.message_id,
        message_type=msg.message_type.value,
    )

    spoofed_envelope = EncryptedPacketEnvelope(
        packet_id=envelope.packet_id,
        sender_id=envelope.sender_id,
        receiver_id=envelope.receiver_id,
        nonce=envelope.nonce,
        ciphertext=envelope.ciphertext,
        associated_data=spoofed_aad,
        timestamp=envelope.timestamp,
    )

    with pytest.raises(AuthenticationTagError):
        nav.decrypt_message(spoofed_envelope)


def test_failure_wrong_receiver_id_rejected():
    """Failure Test 8: Attempting to decrypt a message addressed to a different receiver is rejected."""
    fcc = FlightControlComputer()
    nav = NavigationComputer()
    gcs = GroundControlStation()

    fcc.establish_secure_session(nav)
    fcc.establish_secure_session(gcs)

    # FCC encrypts message specifically for GCS
    msg_for_gcs = fcc.create_status_message(gcs.component_id, status="NOMINAL")
    envelope_for_gcs = fcc.encrypt_message(gcs.component_id, msg_for_gcs)

    # NAV attempts to decrypt GCS's packet
    with pytest.raises(ProtocolError):
        nav.decrypt_message(envelope_for_gcs)


def test_failure_encrypt_before_session_established_rejected():
    """Failure Test 9: Attempting to encrypt before establishing a session raises SessionNotFoundError."""
    fcc = FlightControlComputer()
    nav = NavigationComputer()

    msg = fcc.create_altitude_message(nav.component_id, altitude_ft=32000)

    # No session established yet
    with pytest.raises(SessionNotFoundError):
        fcc.encrypt_message(nav.component_id, msg)


def test_failure_decrypt_using_wrong_session_rejected():
    """Failure Test 10: Attempting to decrypt ciphertext with an unrelated session key is rejected."""
    fcc1 = FlightControlComputer()
    nav1 = NavigationComputer()
    fcc1.establish_secure_session(nav1)

    fcc2 = FlightControlComputer(component_id="AIRCRAFT-002-FCC")
    nav2 = NavigationComputer(component_id="AIRCRAFT-002-NAV")
    fcc2.establish_secure_session(nav2)

    msg = fcc1.create_altitude_message(nav1.component_id, altitude_ft=32000)
    envelope = fcc1.encrypt_message(nav1.component_id, msg)

    # Force envelope sender/receiver to match nav2's peer expectations
    envelope_rewritten = EncryptedPacketEnvelope(
        packet_id=envelope.packet_id,
        sender_id=fcc2.component_id,
        receiver_id=nav2.component_id,
        nonce=envelope.nonce,
        ciphertext=envelope.ciphertext,
        associated_data=envelope.associated_data,
        timestamp=envelope.timestamp,
    )

    with pytest.raises((AuthenticationTagError, ProtocolError)):
        nav2.decrypt_message(envelope_rewritten)

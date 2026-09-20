"""Unit and validation tests for security attack simulation framework (Phase 5)."""

import pytest
from backend.avionics import (
    FlightControlComputer,
    GroundControlStation,
    MessageType,
    NavigationComputer,
    SessionNotFoundError,
)
from backend.crypto import (
    AuthenticationTagError,
    ed25519_generate_keypair,
    slhdsa_generate_keypair,
)
from backend.protocol import (
    HandshakeAuthenticationError,
    HandshakeState,
    HybridHandshake,
    ProtocolError,
    ReplayAttackError,
)
from backend.security import (
    AttackResult,
    AttackStatus,
    generate_security_report,
    run_all_attack_simulations,
    run_baseline_test,
    simulate_aad_tampering,
    simulate_auth_tag_tampering,
    simulate_ciphertext_tampering,
    simulate_ed25519_forgery,
    simulate_replay_attack,
    simulate_slhdsa_forgery,
    simulate_transcript_modification,
    simulate_wrong_receiver_attack,
    simulate_wrong_session_attack,
)


# =====================================================================
# Individual Attack Simulation Tests
# =====================================================================


def test_attack_simulation_baseline():
    """Test that baseline legitimate telemetry communication passes successfully."""
    result = run_baseline_test()
    assert isinstance(result, AttackResult)
    assert result.status == AttackStatus.DETECTED  # Means baseline passed
    assert "ALTITUDE = 32000 FT" in result.modified_result


def test_attack_simulation_ciphertext_tampering():
    """Test that ciphertext tampering is detected and rejected."""
    result = simulate_ciphertext_tampering()
    assert result.detected is True
    assert result.status == AttackStatus.DETECTED
    assert "AuthenticationTagError" in result.actual_behavior


def test_attack_simulation_auth_tag_tampering():
    """Test that GCM authentication tag tampering is detected and rejected."""
    result = simulate_auth_tag_tampering()
    assert result.detected is True
    assert result.status == AttackStatus.DETECTED
    assert "AuthenticationTagError" in result.actual_behavior


def test_attack_simulation_aad_tampering():
    """Test that AAD authenticated metadata tampering is detected and rejected."""
    result = simulate_aad_tampering()
    assert result.detected is True
    assert result.status == AttackStatus.DETECTED
    assert "AuthenticationTagError" in result.actual_behavior


def test_attack_simulation_ed25519_forgery():
    """Test that forged Ed25519 signature is detected and rejects handshake."""
    result = simulate_ed25519_forgery()
    assert result.detected is True
    assert result.status == AttackStatus.DETECTED
    assert "HandshakeAuthenticationError" in result.actual_behavior


def test_attack_simulation_slhdsa_forgery():
    """Test that forged SLH-DSA post-quantum signature is detected and rejects handshake."""
    result = simulate_slhdsa_forgery()
    assert result.detected is True
    assert result.status == AttackStatus.DETECTED
    assert "HandshakeAuthenticationError" in result.actual_behavior


def test_attack_simulation_transcript_modification():
    """Test that modifying the canonical transcript is detected by signature checks."""
    result = simulate_transcript_modification()
    assert result.detected is True
    assert result.status == AttackStatus.DETECTED


def test_attack_simulation_wrong_session():
    """Test that cross-session injection is detected and rejected."""
    result = simulate_wrong_session_attack()
    assert result.detected is True
    assert result.status == AttackStatus.DETECTED


def test_attack_simulation_wrong_receiver():
    """Test that misdirected / spoofed receiver packet is detected and rejected."""
    result = simulate_wrong_receiver_attack()
    assert result.detected is True
    assert result.status == AttackStatus.DETECTED


def test_attack_simulation_replay_attack():
    """Test that replaying a duplicate packet is detected and rejected."""
    result = simulate_replay_attack()
    assert result.detected is True
    assert result.status == AttackStatus.DETECTED
    assert "ReplayAttackError" in result.actual_behavior


# =====================================================================
# Security Invariant Verification Tests
# =====================================================================


def test_security_invariant_1_valid_message_accepted():
    """INVARIANT 1: A valid message is accepted."""
    fcc = FlightControlComputer()
    nav = NavigationComputer()
    fcc.establish_secure_session(nav)

    msg = fcc.create_altitude_message(nav.component_id, altitude_ft=32000)
    envelope = fcc.encrypt_message(nav.component_id, msg)
    decrypted = nav.decrypt_message(envelope)

    assert decrypted.display_string() == "ALTITUDE = 32000 FT"


def test_security_invariant_2_modified_ciphertext_rejected():
    """INVARIANT 2: A modified ciphertext is rejected."""
    fcc = FlightControlComputer()
    nav = NavigationComputer()
    fcc.establish_secure_session(nav)

    msg = fcc.create_heading_message(nav.component_id, heading_deg=275)
    envelope = fcc.encrypt_message(nav.component_id, msg)

    tampered_ct = bytearray(envelope.ciphertext)
    tampered_ct[0] ^= 0x01
    tampered_envelope = type(envelope)(
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


def test_security_invariant_3_modified_gcm_tag_rejected():
    """INVARIANT 3: A modified GCM tag is rejected."""
    fcc = FlightControlComputer()
    nav = NavigationComputer()
    fcc.establish_secure_session(nav)

    msg = fcc.create_flight_mode_message(nav.component_id, flight_mode="CRUISE")
    envelope = fcc.encrypt_message(nav.component_id, msg)

    tampered_ct = bytearray(envelope.ciphertext)
    tampered_ct[-1] ^= 0xFF
    tampered_envelope = type(envelope)(
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


def test_security_invariant_4_modified_metadata_rejected():
    """INVARIANT 4: Modified authenticated metadata (AAD) is rejected."""
    fcc = FlightControlComputer()
    nav = NavigationComputer()
    fcc.establish_secure_session(nav)

    msg = fcc.create_status_message(nav.component_id, status="NOMINAL")
    envelope = fcc.encrypt_message(nav.component_id, msg)

    tampered_envelope = type(envelope)(
        packet_id=envelope.packet_id,
        sender_id=envelope.sender_id,
        receiver_id=envelope.receiver_id,
        nonce=envelope.nonce,
        ciphertext=envelope.ciphertext,
        associated_data=b'{"tampered":"aad"}',
        timestamp=envelope.timestamp,
    )

    with pytest.raises(AuthenticationTagError):
        nav.decrypt_message(tampered_envelope)


def test_security_invariant_5_invalid_ed25519_auth_cannot_establish_session():
    """INVARIANT 5: Invalid Ed25519 authentication cannot establish a session."""
    fcc = FlightControlComputer()
    nav = NavigationComputer()
    nav._ed_private_key, _ = ed25519_generate_keypair()

    handshake = HybridHandshake(initiator=fcc, responder=nav)
    with pytest.raises(HandshakeAuthenticationError):
        handshake.run()

    assert handshake.initiator_state == HandshakeState.FAILED
    assert handshake.responder_state == HandshakeState.FAILED


def test_security_invariant_6_invalid_slhdsa_auth_cannot_establish_session():
    """INVARIANT 6: Invalid SLH-DSA authentication cannot establish a session."""
    fcc = FlightControlComputer()
    nav = NavigationComputer()
    nav._slh_secret_key, _ = slhdsa_generate_keypair("shake_128f")

    handshake = HybridHandshake(initiator=fcc, responder=nav)
    with pytest.raises(HandshakeAuthenticationError):
        handshake.run()

    assert handshake.initiator_state == HandshakeState.FAILED
    assert handshake.responder_state == HandshakeState.FAILED


def test_security_invariant_7_modified_transcript_cannot_establish_session():
    """INVARIANT 7: A modified handshake transcript cannot establish a session."""
    from backend.crypto import x25519_generate_keypair, mlkem_generate_keypair, mlkem_encapsulate, ed25519_sign, ed25519_verify
    import hashlib
    from backend.protocol import compute_canonical_transcript

    fcc = FlightControlComputer()
    nav = NavigationComputer()

    init_x_priv, init_x_pub = x25519_generate_keypair()
    _, init_ml_pub = mlkem_generate_keypair("ML-KEM-1024")
    resp_x_priv, resp_x_pub = x25519_generate_keypair()
    _, mlkem_ct = mlkem_encapsulate(init_ml_pub, "ML-KEM-1024")

    # Original
    orig_tx = compute_canonical_transcript("AVIONICS-PQC-V1", fcc.component_id, nav.component_id, init_x_pub, init_ml_pub, resp_x_pub, mlkem_ct)
    orig_hash = hashlib.sha256(orig_tx).digest()
    sig = ed25519_sign(fcc._ed_private_key, orig_hash)

    # Tampered transcript
    tampered_tx = compute_canonical_transcript("AVIONICS-PQC-V1", "ATTACKER", nav.component_id, init_x_pub, init_ml_pub, resp_x_pub, mlkem_ct)
    tampered_hash = hashlib.sha256(tampered_tx).digest()

    assert ed25519_verify(fcc.ed25519_public_key, tampered_hash, sig) is False


def test_security_invariant_8_cannot_accept_under_wrong_session():
    """INVARIANT 8: A message cannot be accepted using the wrong session."""
    fcc1 = FlightControlComputer()
    nav1 = NavigationComputer()
    fcc1.establish_secure_session(nav1)

    fcc2 = FlightControlComputer(component_id="AIRCRAFT-002-FCC")
    nav2 = NavigationComputer(component_id="AIRCRAFT-002-NAV")
    fcc2.establish_secure_session(nav2)

    msg = fcc1.create_altitude_message(nav1.component_id, altitude_ft=32000)
    envelope = fcc1.encrypt_message(nav1.component_id, msg)

    spoofed = type(envelope)(
        packet_id=envelope.packet_id,
        sender_id=fcc2.component_id,
        receiver_id=nav2.component_id,
        nonce=envelope.nonce,
        ciphertext=envelope.ciphertext,
        associated_data=envelope.associated_data,
        timestamp=envelope.timestamp,
    )

    with pytest.raises((AuthenticationTagError, ProtocolError)):
        nav2.decrypt_message(spoofed)


def test_security_invariant_9_wrong_receiver_rejected():
    """INVARIANT 9: A message intended for another receiver is rejected."""
    fcc = FlightControlComputer()
    nav = NavigationComputer()
    gcs = GroundControlStation()

    fcc.establish_secure_session(nav)
    fcc.establish_secure_session(gcs)

    msg = fcc.create_status_message(gcs.component_id, status="NOMINAL")
    envelope = fcc.encrypt_message(gcs.component_id, msg)

    with pytest.raises(ProtocolError):
        nav.decrypt_message(envelope)


def test_security_report_generation():
    """Test full security report generation and metrics calculation."""
    report = generate_security_report()

    assert report.baseline_passed is True
    assert report.total_attacks == 9
    assert report.attacks_detected == 9
    assert report.attacks_not_detected == 0
    assert report.errors == 0
    assert report.overall_status == "PASS"

    # Test dictionary serialization
    report_dict = report.to_dict()
    assert report_dict["overall_status"] == "PASS"
    assert len(report_dict["results"]) == 10

    # Test text summary output
    summary_text = report.generate_summary_text()
    assert "SECURITY VALIDATION REPORT" in summary_text
    assert "Attacks detected    : 9 / 9" in summary_text
    assert "Security validation : PASS" in summary_text

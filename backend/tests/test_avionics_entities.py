"""Unit tests for simulated avionics entities, message models, and communication channel."""

import json
import pytest
from backend.avionics import (
    AvionicsEntity,
    AvionicsMessage,
    ComponentType,
    EncryptedPacketEnvelope,
    FlightControlComputer,
    GroundControlStation,
    MessageType,
    NavigationComputer,
    SessionNotFoundError,
    SimulatedChannel,
    create_aircraft_status_message,
    create_altitude_message,
    create_flight_mode_message,
    create_heading_message,
    create_navigation_update_message,
)
from backend.crypto import (
    AuthenticationTagError,
    aes_gcm_generate_key,
)


def test_fcc_creation():
    """Test FlightControlComputer instantiation and defaults."""
    fcc = FlightControlComputer()
    assert fcc.component_id == "AIRCRAFT-001-FCC"
    assert fcc.aircraft_id == "AIRCRAFT-001"
    assert fcc.component_type == ComponentType.FLIGHT_CONTROL_COMPUTER
    assert isinstance(fcc.ed25519_public_key, bytes)
    assert len(fcc.ed25519_public_key) == 32
    assert isinstance(fcc.slhdsa_public_key, bytes)
    assert len(fcc.slhdsa_public_key) == 32


def test_nav_creation():
    """Test NavigationComputer instantiation and defaults."""
    nav = NavigationComputer()
    assert nav.component_id == "AIRCRAFT-001-NAV"
    assert nav.aircraft_id == "AIRCRAFT-001"
    assert nav.component_type == ComponentType.NAVIGATION_COMPUTER
    assert isinstance(nav.ed25519_public_key, bytes)
    assert isinstance(nav.slhdsa_public_key, bytes)


def test_gcs_creation():
    """Test GroundControlStation instantiation and defaults."""
    gcs = GroundControlStation()
    assert gcs.component_id == "GROUND-STATION-001"
    assert gcs.aircraft_id is None
    assert gcs.component_type == ComponentType.GROUND_CONTROL_STATION
    assert isinstance(gcs.ed25519_public_key, bytes)
    assert isinstance(gcs.slhdsa_public_key, bytes)


def test_unique_component_identities():
    """Test that all three entities have distinct IDs and distinct cryptographic keypairs."""
    fcc = FlightControlComputer()
    nav = NavigationComputer()
    gcs = GroundControlStation()

    # Distinct Component IDs
    ids = {fcc.component_id, nav.component_id, gcs.component_id}
    assert len(ids) == 3

    # Distinct Ed25519 Public Keys
    ed_keys = {fcc.ed25519_public_key, nav.ed25519_public_key, gcs.ed25519_public_key}
    assert len(ed_keys) == 3

    # Distinct SLH-DSA Public Keys
    slh_keys = {fcc.slhdsa_public_key, nav.slhdsa_public_key, gcs.slhdsa_public_key}
    assert len(slh_keys) == 3


def test_representative_avionics_message_creation():
    """Test creation of all 5 supported avionics message types."""
    fcc = FlightControlComputer()
    nav = NavigationComputer()

    # 1. ALTITUDE
    msg_alt = fcc.create_altitude_message(nav.component_id, altitude_ft=32000)
    assert msg_alt.message_type == MessageType.ALTITUDE
    assert msg_alt.payload == {"altitude_ft": 32000}
    assert msg_alt.display_string() == "ALTITUDE = 32000 FT"

    # 2. HEADING
    msg_hdg = fcc.create_heading_message(nav.component_id, heading_deg=275)
    assert msg_hdg.message_type == MessageType.HEADING
    assert msg_hdg.payload == {"heading_deg": 275}
    assert msg_hdg.display_string() == "HEADING = 275 DEG"

    # 3. FLIGHT_MODE
    msg_mode = fcc.create_flight_mode_message(nav.component_id, flight_mode="CRUISE")
    assert msg_mode.message_type == MessageType.FLIGHT_MODE
    assert msg_mode.payload == {"flight_mode": "CRUISE"}
    assert msg_mode.display_string() == "FLIGHT_MODE = CRUISE"

    # 4. AIRCRAFT_STATUS
    msg_status = fcc.create_status_message(nav.component_id, status="NOMINAL")
    assert msg_status.message_type == MessageType.AIRCRAFT_STATUS
    assert msg_status.payload == {"status": "NOMINAL"}
    assert msg_status.display_string() == "AIRCRAFT_STATUS = NOMINAL"

    # 5. NAVIGATION_UPDATE
    msg_nav = nav.create_navigation_update(fcc.component_id, latitude=37.7749, longitude=-122.4194, altitude_ft=32000)
    assert msg_nav.message_type == MessageType.NAVIGATION_UPDATE
    assert msg_nav.payload["latitude"] == 37.7749
    assert msg_nav.payload["longitude"] == -122.4194
    assert "LAT:37.7749 LON:-122.4194" in msg_nav.display_string()


def test_message_metadata_and_serialization():
    """Test message metadata fields and JSON byte serialization roundtrip."""
    sender = "AIRCRAFT-001-FCC"
    receiver = "AIRCRAFT-001-NAV"
    msg = create_altitude_message(sender, receiver, altitude_ft=32000)

    # Metadata checks
    assert msg.sender_id == sender
    assert msg.receiver_id == receiver
    assert isinstance(msg.message_id, str) and len(msg.message_id) > 0
    assert isinstance(msg.timestamp, float) and msg.timestamp > 0

    # Serialization roundtrip
    raw_bytes = msg.to_bytes()
    assert isinstance(raw_bytes, bytes)

    reconstructed = AvionicsMessage.from_bytes(raw_bytes)
    assert reconstructed.message_id == msg.message_id
    assert reconstructed.sender_id == msg.sender_id
    assert reconstructed.receiver_id == msg.receiver_id
    assert reconstructed.timestamp == msg.timestamp
    assert reconstructed.message_type == msg.message_type
    assert reconstructed.payload == msg.payload


def test_communication_channel_creation():
    """Test instantiation and logging of the untrusted communication channel."""
    channel = SimulatedChannel(name="AVIONICS_BUS_01")
    assert channel.name == "AVIONICS_BUS_01"
    assert channel.total_packets_transmitted == 0
    assert channel.traffic_log == []


def test_encrypted_payload_passes_through_channel_without_plaintext_access():
    """Test that encrypted payload passes through untrusted channel without exposing plaintext."""
    fcc = FlightControlComputer()
    nav = NavigationComputer()
    channel = SimulatedChannel(name="UNTRUSTED_RADIO_LINK")

    # Establish simulated session key between FCC and NAV
    session_key = aes_gcm_generate_key()
    fcc.register_session(nav.component_id, session_key)
    nav.register_session(fcc.component_id, session_key)

    # Create message: "ALTITUDE = 32000 FT"
    original_msg = fcc.create_altitude_message(nav.component_id, altitude_ft=32000)
    plaintext_bytes = original_msg.to_bytes()

    # FCC encrypts and sends across untrusted channel
    envelope = fcc.send_via_channel(nav.component_id, original_msg, channel)

    # Verify channel traffic
    assert channel.total_packets_transmitted == 1
    log_entry = channel.traffic_log[0]
    assert log_entry["sender_id"] == fcc.component_id
    assert log_entry["receiver_id"] == nav.component_id

    # The channel/envelope MUST NOT contain the plaintext string or unencrypted JSON
    assert b"ALTITUDE" not in envelope.ciphertext
    assert b"32000" not in envelope.ciphertext
    assert envelope.ciphertext != plaintext_bytes

    # NAV receives and decrypts
    decrypted_msg = nav.decrypt_message(envelope)
    assert decrypted_msg.message_id == original_msg.message_id
    assert decrypted_msg.display_string() == "ALTITUDE = 32000 FT"
    assert nav.get_latest_received_display() == "ALTITUDE = 32000 FT"


def test_invalid_message_handling():
    """Test rejection of tampered packets, missing sessions, and altered headers."""
    fcc = FlightControlComputer()
    nav = NavigationComputer()
    gcs = GroundControlStation()

    session_key = aes_gcm_generate_key()
    fcc.register_session(nav.component_id, session_key)
    nav.register_session(fcc.component_id, session_key)

    msg = fcc.create_heading_message(nav.component_id, heading_deg=275)
    aad = b"SECURITY_ZONE=AIRCRAFT_BUS"
    envelope = fcc.encrypt_message(nav.component_id, msg, associated_data=aad)

    # 1. Tampered ciphertext rejection
    tampered_ct = bytearray(envelope.ciphertext)
    tampered_ct[5] ^= 0xFF
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

    # 2. Tampered AAD rejection
    tampered_aad_envelope = EncryptedPacketEnvelope(
        packet_id=envelope.packet_id,
        sender_id=envelope.sender_id,
        receiver_id=envelope.receiver_id,
        nonce=envelope.nonce,
        ciphertext=envelope.ciphertext,
        associated_data=b"SECURITY_ZONE=GROUND_BUS",
        timestamp=envelope.timestamp,
    )
    with pytest.raises(AuthenticationTagError):
        nav.decrypt_message(tampered_aad_envelope)

    # 3. Missing session error (GCS has no session with FCC)
    with pytest.raises(SessionNotFoundError):
        gcs.decrypt_message(envelope)

    with pytest.raises(SessionNotFoundError):
        gcs.encrypt_message(fcc.component_id, msg)

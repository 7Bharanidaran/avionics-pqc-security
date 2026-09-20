"""Unit tests for SLH-DSA post-quantum digital signature primitive (FIPS 205)."""

import pytest
from backend.crypto.slhdsa import (
    SLHDSAError,
    generate_keypair,
    public_key_from_secret_key,
    sign,
    verify,
)


@pytest.mark.parametrize("parameter_set", ["shake_128f", "sha2_128f"])
def test_slhdsa_keypair_generation(parameter_set):
    """Test SLH-DSA keypair generation across standard parameter sets."""
    sec, pub = generate_keypair(parameter_set=parameter_set)
    assert isinstance(sec, bytes)
    assert isinstance(pub, bytes)
    assert len(sec) == 64
    assert len(pub) == 32

    # Extract public key from secret key
    derived_pub = public_key_from_secret_key(sec, parameter_set=parameter_set)
    assert derived_pub == pub


@pytest.mark.parametrize("parameter_set", ["shake_128f", "sha2_128f"])
def test_slhdsa_sign_and_verify_valid(parameter_set):
    """Test signing a message and verifying the SLH-DSA signature."""
    sec, pub = generate_keypair(parameter_set=parameter_set)
    message = b"AVIONICS_TELEMETRY:LAT=37.7749,LON=-122.4194,ALT=35000"

    signature = sign(sec, message, parameter_set=parameter_set)
    assert isinstance(signature, bytes)
    assert len(signature) == 17088

    # Valid verification
    assert verify(pub, message, signature, parameter_set=parameter_set) is True


def test_slhdsa_tampered_message_fails():
    """Test that modifying the signed message fails SLH-DSA verification."""
    sec, pub = generate_keypair("shake_128f")
    message = b"FLIGHT_DIRECTOR_MODE=AUTONAV"
    signature = sign(sec, message, "shake_128f")

    tampered_msg = b"FLIGHT_DIRECTOR_MODE=MANUAL"
    assert verify(pub, tampered_msg, signature, "shake_128f") is False


def test_slhdsa_tampered_signature_fails():
    """Test that modifying the signature bytes fails SLH-DSA verification."""
    sec, pub = generate_keypair("shake_128f")
    message = b"EMERGENCY_DESCENT_COMMAND"
    signature = sign(sec, message, "shake_128f")

    tampered_sig = bytearray(signature)
    tampered_sig[100] ^= 0xFF

    assert verify(pub, message, bytes(tampered_sig), "shake_128f") is False


def test_slhdsa_wrong_public_key_fails():
    """Test verification fails against a different SLH-DSA public key."""
    sec1, _ = generate_keypair("shake_128f")
    _, pub2 = generate_keypair("shake_128f")

    message = b"ILS_FREQUENCY=109.50"
    signature = sign(sec1, message, "shake_128f")

    assert verify(pub2, message, signature, "shake_128f") is False


def test_slhdsa_invalid_inputs():
    """Test validation of inputs and error cases."""
    sec, pub = generate_keypair("shake_128f")
    msg = b"TEST"
    sig = sign(sec, msg, "shake_128f")

    # Unsupported parameter set
    with pytest.raises(ValueError, match="Unsupported SLH-DSA parameter set"):
        generate_keypair("invalid_param")  # type: ignore

    # Invalid types
    with pytest.raises(TypeError):
        sign("not_bytes", msg, "shake_128f")  # type: ignore

    with pytest.raises(TypeError):
        verify(pub, msg, 12345, "shake_128f")  # type: ignore

    # Invalid lengths
    with pytest.raises(ValueError, match="secret key must be"):
        sign(b"short_key", msg, "shake_128f")

    with pytest.raises(ValueError, match="public key must be"):
        verify(b"short_pub", msg, sig, "shake_128f")

    with pytest.raises(ValueError, match="signature must be"):
        verify(pub, msg, b"short_sig", "shake_128f")

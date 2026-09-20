"""Unit tests for Ed25519 digital signature primitive."""

import pytest
from backend.crypto.ed25519 import (
    Ed25519Error,
    generate_keypair,
    public_key_from_private_key,
    sign,
    verify,
)


def test_ed25519_keypair_generation():
    """Test Ed25519 key generation."""
    priv, pub = generate_keypair()
    assert isinstance(priv, bytes)
    assert isinstance(pub, bytes)
    assert len(priv) == 32
    assert len(pub) == 32
    assert priv != pub


def test_ed25519_public_key_from_private_key():
    """Test public key derivation from private key."""
    priv, pub = generate_keypair()
    derived_pub = public_key_from_private_key(priv)
    assert derived_pub == pub


def test_ed25519_sign_and_verify_valid():
    """Test signing a message and successfully verifying signature."""
    priv, pub = generate_keypair()
    message = b"HEADING=270,ALTITUDE=32000,SPEED=450KTS"

    signature = sign(priv, message)
    assert isinstance(signature, bytes)
    assert len(signature) == 64

    # Verification must succeed
    assert verify(pub, message, signature) is True


def test_ed25519_tampered_message_fails():
    """Test that modifying the signed message fails verification."""
    priv, pub = generate_keypair()
    message = b"WAYPOINT=ALPHA"
    signature = sign(priv, message)

    tampered_message = b"WAYPOINT=BRAVO"
    assert verify(pub, tampered_message, signature) is False


def test_ed25519_tampered_signature_fails():
    """Test that tampering with signature bytes fails verification."""
    priv, pub = generate_keypair()
    message = b"WAYPOINT=ALPHA"
    signature = sign(priv, message)

    tampered_sig = bytearray(signature)
    tampered_sig[10] ^= 0x01

    assert verify(pub, message, bytes(tampered_sig)) is False


def test_ed25519_wrong_public_key_fails():
    """Test that verification fails when checking against a different public key."""
    priv1, _ = generate_keypair()
    _, pub2 = generate_keypair()

    message = b"AUTOPILOT_ENGAGE"
    signature = sign(priv1, message)

    assert verify(pub2, message, signature) is False


def test_ed25519_invalid_inputs():
    """Test validation of inputs and error conditions."""
    priv, pub = generate_keypair()
    msg = b"TEST"
    sig = sign(priv, msg)

    # Invalid types
    with pytest.raises(TypeError):
        sign("not_bytes", msg)  # type: ignore

    with pytest.raises(TypeError):
        sign(priv, "not_bytes_msg")  # type: ignore

    with pytest.raises(TypeError):
        verify(pub, msg, "not_bytes_sig")  # type: ignore

    # Invalid lengths
    with pytest.raises(ValueError, match="32 bytes"):
        sign(b"short_key", msg)

    with pytest.raises(ValueError, match="32 bytes"):
        verify(b"short_pub", msg, sig)

    with pytest.raises(ValueError, match="64 bytes"):
        verify(pub, msg, b"short_sig")

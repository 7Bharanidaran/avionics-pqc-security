"""Unit tests for X25519 key exchange primitive."""

import pytest
from backend.crypto.x25519 import (
    X25519Error,
    derive_shared_secret,
    generate_keypair,
    public_key_from_private_key,
)


def test_x25519_keypair_generation():
    """Test generation of valid 32-byte keypairs."""
    priv, pub = generate_keypair()
    assert isinstance(priv, bytes)
    assert isinstance(pub, bytes)
    assert len(priv) == 32
    assert len(pub) == 32
    assert priv != pub

    # Ensure two generations produce distinct keys
    priv2, pub2 = generate_keypair()
    assert priv != priv2
    assert pub != pub2


def test_x25519_public_key_from_private_key():
    """Test public key extraction matches generated public key."""
    priv, pub = generate_keypair()
    derived_pub = public_key_from_private_key(priv)
    assert derived_pub == pub


def test_x25519_shared_secret_agreement():
    """Test that two independent parties derive the exact same shared secret."""
    # Party A (e.g. Flight Control Computer)
    priv_a, pub_a = generate_keypair()

    # Party B (e.g. Ground Station)
    priv_b, pub_b = generate_keypair()

    # Both parties derive shared secret
    ss_a = derive_shared_secret(priv_a, pub_b)
    ss_b = derive_shared_secret(priv_b, pub_a)

    assert isinstance(ss_a, bytes)
    assert isinstance(ss_b, bytes)
    assert len(ss_a) == 32
    assert len(ss_b) == 32
    assert ss_a == ss_b, "Both parties must arrive at identical shared secret"


def test_x25519_invalid_inputs():
    """Test validation and error handling for malformed or invalid inputs."""
    priv, pub = generate_keypair()

    # Invalid types
    with pytest.raises(TypeError):
        derive_shared_secret("invalid_type_str", pub)  # type: ignore

    with pytest.raises(TypeError):
        derive_shared_secret(priv, 12345)  # type: ignore

    with pytest.raises(TypeError):
        public_key_from_private_key(None)  # type: ignore

    # Invalid lengths
    with pytest.raises(ValueError, match="32 bytes"):
        derive_shared_secret(b"too_short", pub)

    with pytest.raises(ValueError, match="32 bytes"):
        derive_shared_secret(priv, b"too_long" * 10)

    with pytest.raises(ValueError, match="32 bytes"):
        public_key_from_private_key(b"\x00" * 31)

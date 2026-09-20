"""Unit tests for ML-KEM post-quantum key encapsulation mechanism (FIPS 203)."""

import pytest
from backend.crypto.mlkem import (
    MLKEMError,
    decapsulate,
    encapsulate,
    generate_keypair,
    public_key_from_private_key,
)


@pytest.mark.parametrize("parameter_set", ["ML-KEM-1024", "ML-KEM-768"])
def test_mlkem_keypair_generation(parameter_set):
    """Test ML-KEM keypair generation for supported parameter sets."""
    priv_seed, pub = generate_keypair(parameter_set=parameter_set)
    assert isinstance(priv_seed, bytes)
    assert isinstance(pub, bytes)
    assert len(priv_seed) == 64

    expected_pub_len = 1568 if parameter_set == "ML-KEM-1024" else 1184
    assert len(pub) == expected_pub_len

    # Derive public key from seed and ensure match
    derived_pub = public_key_from_private_key(priv_seed, parameter_set=parameter_set)
    assert derived_pub == pub


@pytest.mark.parametrize("parameter_set", ["ML-KEM-1024", "ML-KEM-768"])
def test_mlkem_encapsulate_decapsulate(parameter_set):
    """Test full KEM roundtrip: encapsulation and decapsulation produce matching shared secret."""
    priv_seed, pub = generate_keypair(parameter_set=parameter_set)

    # Sender encapsulates against recipient's public key
    ss_sender, ciphertext = encapsulate(pub, parameter_set=parameter_set)

    assert isinstance(ss_sender, bytes)
    assert isinstance(ciphertext, bytes)
    assert len(ss_sender) == 32

    expected_ct_len = 1568 if parameter_set == "ML-KEM-1024" else 1088
    assert len(ciphertext) == expected_ct_len

    # Recipient decapsulates ciphertext with private seed
    ss_recipient = decapsulate(priv_seed, ciphertext, parameter_set=parameter_set)

    assert isinstance(ss_recipient, bytes)
    assert len(ss_recipient) == 32
    assert ss_sender == ss_recipient, "Sender and recipient shared secrets must match exactly"


def test_mlkem_invalid_ciphertext_handling():
    """Test that decapsulating a tampered ciphertext does not yield the original shared secret or raises error."""
    priv_seed, pub = generate_keypair("ML-KEM-1024")
    ss_sender, ciphertext = encapsulate(pub, "ML-KEM-1024")

    # In ML-KEM / Kyber implicit rejection (Fujisaki-Okamoto transform), decapsulation of a modified
    # ciphertext produces a pseudorandom key distinct from ss_sender or raises an error.
    tampered_ct = bytearray(ciphertext)
    tampered_ct[42] ^= 0xFF

    ss_recipient = decapsulate(priv_seed, bytes(tampered_ct), "ML-KEM-1024")
    assert ss_recipient != ss_sender, "Tampered ciphertext must not produce valid shared secret"


def test_mlkem_invalid_inputs():
    """Test input validation for wrong types, lengths, and unsupported parameter sets."""
    priv_seed, pub = generate_keypair("ML-KEM-1024")
    _, ciphertext = encapsulate(pub, "ML-KEM-1024")

    # Unsupported parameter set
    with pytest.raises(ValueError, match="Unsupported ML-KEM parameter set"):
        generate_keypair("ML-KEM-512")  # type: ignore

    # Invalid types
    with pytest.raises(TypeError):
        encapsulate("not_bytes_pubkey")  # type: ignore

    with pytest.raises(TypeError):
        decapsulate(12345, ciphertext)  # type: ignore

    # Invalid lengths
    with pytest.raises(ValueError, match="public key must be"):
        encapsulate(b"short_pubkey")

    with pytest.raises(ValueError, match="private key seed must be"):
        decapsulate(b"short_priv_seed", ciphertext)

    with pytest.raises(ValueError, match="ciphertext must be"):
        decapsulate(priv_seed, b"short_ct")

"""Unit tests for HKDF Key Derivation Function (RFC 5869)."""

import pytest
from backend.crypto.hkdf import (
    HKDFError,
    hkdf_derive,
    hkdf_expand,
    hkdf_extract,
)


def test_hkdf_deterministic_derivation():
    """Test that same inputs produce the exact same derived key."""
    ikm = b"secret_hybrid_key_material_32bytes"
    salt = b"flight_session_salt_01"
    info = b"avionics_aes_session_key"

    key1 = hkdf_derive(ikm, salt=salt, info=info, length=32)
    key2 = hkdf_derive(ikm, salt=salt, info=info, length=32)

    assert isinstance(key1, bytes)
    assert len(key1) == 32
    assert key1 == key2, "HKDF must be deterministic"


def test_hkdf_extract_and_expand_match_derive():
    """Test that two-step extract + expand produces the exact same output as unified derive."""
    ikm = b"secret_hybrid_key_material_32bytes"
    salt = b"flight_session_salt_01"
    info = b"avionics_aes_session_key"

    prk = hkdf_extract(salt, ikm, hash_name="SHA256")
    assert len(prk) == 32

    okm = hkdf_expand(prk, info=info, length=32, hash_name="SHA256")
    unified_okm = hkdf_derive(ikm, salt=salt, info=info, length=32, hash_name="SHA256")

    assert okm == unified_okm


def test_hkdf_different_info_produces_different_keys():
    """Test context separation: different info strings yield completely different keys."""
    ikm = b"shared_master_secret"
    salt = b"common_salt"

    key_fcc_to_nav = hkdf_derive(ikm, salt=salt, info=b"FCC-TO-NAV-KEY", length=32)
    key_nav_to_gcs = hkdf_derive(ikm, salt=salt, info=b"NAV-TO-GCS-KEY", length=32)

    assert key_fcc_to_nav != key_nav_to_gcs


def test_hkdf_different_ikm_produces_different_keys():
    """Test that different input keying material produces distinct keys."""
    salt = b"fixed_salt"
    info = b"fixed_info"

    key1 = hkdf_derive(b"secret_key_material_1", salt=salt, info=info, length=32)
    key2 = hkdf_derive(b"secret_key_material_2", salt=salt, info=info, length=32)

    assert key1 != key2


def test_hkdf_configurable_lengths_and_hashes():
    """Test varying output lengths and supported hash algorithms."""
    ikm = b"hybrid_shared_key_material"

    # 16-byte key (AES-128)
    key_16 = hkdf_derive(ikm, length=16)
    assert len(key_16) == 16

    # 32-byte key (AES-256)
    key_32 = hkdf_derive(ikm, length=32)
    assert len(key_32) == 32

    # 64-byte key (512-bit combined keys)
    key_64 = hkdf_derive(ikm, length=64)
    assert len(key_64) == 64

    # SHA384 and SHA512
    key_sha384 = hkdf_derive(ikm, length=32, hash_name="SHA384")
    key_sha512 = hkdf_derive(ikm, length=32, hash_name="SHA512")
    assert key_32 != key_sha384
    assert key_32 != key_sha512


def test_hkdf_invalid_inputs():
    """Test validation of arguments and boundary conditions."""
    # Empty IKM
    with pytest.raises(ValueError, match="cannot be empty"):
        hkdf_derive(b"")

    # Invalid types
    with pytest.raises(TypeError):
        hkdf_derive("not_bytes")  # type: ignore

    with pytest.raises(TypeError):
        hkdf_derive(b"valid_ikm", salt=123)  # type: ignore

    # Invalid lengths
    with pytest.raises(ValueError, match="positive integer"):
        hkdf_derive(b"valid_ikm", length=0)

    # Exceeding maximum HKDF output length
    with pytest.raises(ValueError, match="exceeds maximum"):
        hkdf_derive(b"valid_ikm", length=255 * 32 + 1, hash_name="SHA256")

    # Unsupported hash
    with pytest.raises(ValueError, match="Unsupported hash algorithm"):
        hkdf_derive(b"valid_ikm", hash_name="MD5")  # type: ignore

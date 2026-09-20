"""Unit tests for AES-256-GCM AEAD symmetric encryption."""

import pytest
from backend.crypto.aes_gcm import (
    AESGCMError,
    AuthenticationTagError,
    decrypt,
    encrypt,
    generate_key,
    generate_nonce,
)


def test_aes_gcm_key_and_nonce_generation():
    """Test cryptographic generation of keys and nonces."""
    key = generate_key()
    assert isinstance(key, bytes)
    assert len(key) == 32

    nonce = generate_nonce()
    assert isinstance(nonce, bytes)
    assert len(nonce) == 12

    # Verify uniqueness
    nonce2 = generate_nonce()
    assert nonce != nonce2


def test_aes_gcm_normal_encrypt_decrypt():
    """Test basic encryption and decryption roundtrip."""
    key = generate_key()
    plaintext = b"AIRSPEED=480KTS,PITCH=+2.5DEG,ROLL=0.0DEG"

    ciphertext, nonce = encrypt(key, plaintext)
    assert isinstance(ciphertext, bytes)
    assert isinstance(nonce, bytes)
    assert len(nonce) == 12
    # Ciphertext length should be plaintext length + 16-byte tag
    assert len(ciphertext) == len(plaintext) + 16

    decrypted = decrypt(key, nonce, ciphertext)
    assert decrypted == plaintext


def test_aes_gcm_with_associated_data():
    """Test encryption and decryption with Additional Authenticated Data (AAD)."""
    key = generate_key()
    plaintext = b"FLIGHT_PLAN_WAYPOINTS=KLAX-KJFK"
    aad = b"HEADER:PACKET_ID=1024,SRC=FCC,DST=GCS"

    ciphertext, nonce = encrypt(key, plaintext, associated_data=aad)
    decrypted = decrypt(key, nonce, ciphertext, associated_data=aad)
    assert decrypted == plaintext


def test_aes_gcm_tampered_ciphertext_rejected():
    """Test that tampering with any bit in the ciphertext triggers AuthenticationTagError."""
    key = generate_key()
    plaintext = b"ENGINE_1_THRUST=98.5%"

    ciphertext, nonce = encrypt(key, plaintext)

    tampered_ct = bytearray(ciphertext)
    tampered_ct[0] ^= 0x01

    with pytest.raises(AuthenticationTagError):
        decrypt(key, nonce, bytes(tampered_ct))


def test_aes_gcm_tampered_tag_rejected():
    """Test that tampering with authentication tag at end of ciphertext fails authentication."""
    key = generate_key()
    plaintext = b"AUTOLAND_ARMED"

    ciphertext, nonce = encrypt(key, plaintext)

    # Tag is the last 16 bytes
    tampered_ct = bytearray(ciphertext)
    tampered_ct[-1] ^= 0xFF

    with pytest.raises(AuthenticationTagError):
        decrypt(key, nonce, bytes(tampered_ct))


def test_aes_gcm_tampered_aad_rejected():
    """Test that modifying associated data fails authentication."""
    key = generate_key()
    plaintext = b"SPOILER_EXTEND"
    aad = b"TRANSACTION_ID=999"

    ciphertext, nonce = encrypt(key, plaintext, associated_data=aad)

    tampered_aad = b"TRANSACTION_ID=1000"
    with pytest.raises(AuthenticationTagError):
        decrypt(key, nonce, ciphertext, associated_data=tampered_aad)

    # Missing AAD when it was used during encryption must also fail
    with pytest.raises(AuthenticationTagError):
        decrypt(key, nonce, ciphertext, associated_data=None)


def test_aes_gcm_invalid_key():
    """Test rejection of invalid key sizes and wrong decryption keys."""
    valid_key = generate_key()
    wrong_key = generate_key()
    plaintext = b"CABIN_PRESSURE_NORMAL"

    ciphertext, nonce = encrypt(valid_key, plaintext)

    # Decrypt with wrong key
    with pytest.raises(AuthenticationTagError):
        decrypt(wrong_key, nonce, ciphertext)

    # Invalid key length (must be 32 bytes)
    with pytest.raises(ValueError, match="32-byte key"):
        encrypt(b"short_key", plaintext)

    with pytest.raises(ValueError, match="32-byte key"):
        decrypt(b"short_key", nonce, ciphertext)


def test_aes_gcm_invalid_nonce():
    """Test validation of nonce lengths and types."""
    key = generate_key()
    plaintext = b"FLAPS_POSITION=15"

    with pytest.raises(ValueError, match="at least 12 bytes"):
        encrypt(key, plaintext, nonce=b"short_iv")

    with pytest.raises(ValueError, match="at least 12 bytes"):
        decrypt(key, b"short_iv", b"dummy_ciphertext_16bytes!!")


def test_aes_gcm_invalid_types():
    """Test validation of argument types."""
    key = generate_key()
    nonce = generate_nonce()

    with pytest.raises(TypeError):
        encrypt("str_key", b"msg")  # type: ignore

    with pytest.raises(TypeError):
        encrypt(key, "str_plaintext")  # type: ignore

    with pytest.raises(TypeError):
        decrypt(key, nonce, "str_ciphertext")  # type: ignore

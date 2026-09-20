"""AES-256-GCM Authenticated Encryption with Associated Data (AEAD).

Provides authenticated symmetric encryption with 256-bit keys and 96-bit nonces.
Guarantees both confidentiality and integrity/authenticity for avionics telemetry and control packets.
"""

from __future__ import annotations

import os
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AESGCMError(Exception):
    """Base exception for AES-GCM operations."""


class AuthenticationTagError(AESGCMError):
    """Raised when ciphertext, authentication tag, or associated data integrity check fails."""


KEY_SIZE_BYTES = 32  # AES-256 requires 32 bytes (256 bits)
RECOMMENDED_NONCE_SIZE_BYTES = 12  # Standard 96-bit nonce for GCM
MIN_NONCE_SIZE_BYTES = 12


def generate_key() -> bytes:
    """Generate a cryptographically secure 256-bit (32-byte) AES key.

    Returns:
        bytes: 32 random bytes from OS CSPRNG.
    """
    return AESGCM.generate_key(bit_length=256)


def generate_nonce(length: int = RECOMMENDED_NONCE_SIZE_BYTES) -> bytes:
    """Generate a cryptographically secure random nonce.

    Args:
        length: Nonce length in bytes (defaults to 12 bytes / 96 bits).

    Returns:
        bytes: Random nonce bytes.

    Raises:
        ValueError: If length is less than 12 bytes.
    """
    if not isinstance(length, int) or length < MIN_NONCE_SIZE_BYTES:
        raise ValueError(f"Nonce length must be at least {MIN_NONCE_SIZE_BYTES} bytes, got {length}")
    return os.urandom(length)


def encrypt(
    key: bytes,
    plaintext: bytes,
    associated_data: bytes | None = None,
    nonce: bytes | None = None,
) -> tuple[bytes, bytes]:
    """Encrypt plaintext using AES-256-GCM.

    Args:
        key: 32-byte (256-bit) AES key.
        plaintext: Plaintext message bytes to encrypt.
        associated_data: Optional Additional Authenticated Data (AAD).
        nonce: Optional 12-byte nonce. If not provided, a secure random nonce is generated.

    Returns:
        tuple[bytes, bytes]: (ciphertext_with_tag, nonce)
            - ciphertext_with_tag contains the encrypted data + 16-byte authentication tag
            - nonce is the 12-byte initialization vector used for encryption

    Raises:
        TypeError: If key, plaintext, or associated_data are invalid types.
        ValueError: If key or nonce length is invalid.
        AESGCMError: If encryption fails.
    """
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError(f"key must be bytes, got {type(key).__name__}")
    if len(key) != KEY_SIZE_BYTES:
        raise ValueError(f"AES-256 requires a {KEY_SIZE_BYTES}-byte key, got {len(key)} bytes")

    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError(f"plaintext must be bytes, got {type(plaintext).__name__}")

    if associated_data is not None and not isinstance(associated_data, (bytes, bytearray)):
        raise TypeError(f"associated_data must be bytes or None, got {type(associated_data).__name__}")

    if nonce is None:
        used_nonce = generate_nonce(RECOMMENDED_NONCE_SIZE_BYTES)
    else:
        if not isinstance(nonce, (bytes, bytearray)):
            raise TypeError(f"nonce must be bytes, got {type(nonce).__name__}")
        if len(nonce) < MIN_NONCE_SIZE_BYTES:
            raise ValueError(f"Nonce must be at least {MIN_NONCE_SIZE_BYTES} bytes, got {len(nonce)}")
        used_nonce = bytes(nonce)

    aad_bytes = bytes(associated_data) if associated_data is not None else None

    try:
        aesgcm = AESGCM(bytes(key))
        ciphertext = aesgcm.encrypt(used_nonce, bytes(plaintext), aad_bytes)
        return ciphertext, used_nonce
    except Exception as exc:
        raise AESGCMError(f"AES-GCM encryption failed: {exc}") from exc


def decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    """Decrypt and verify ciphertext using AES-256-GCM.

    Args:
        key: 32-byte (256-bit) AES key.
        nonce: Nonce / IV used during encryption.
        ciphertext: Ciphertext bytes including authentication tag (appended 16 bytes).
        associated_data: Optional Additional Authenticated Data that was passed during encryption.

    Returns:
        bytes: Decrypted plaintext message.

    Raises:
        TypeError: If any argument is of incorrect type.
        ValueError: If key or nonce length is invalid.
        AuthenticationTagError: If ciphertext, tag, or associated data was modified or tampered with.
        AESGCMError: If decryption fails for other reasons.
    """
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError(f"key must be bytes, got {type(key).__name__}")
    if len(key) != KEY_SIZE_BYTES:
        raise ValueError(f"AES-256 requires a {KEY_SIZE_BYTES}-byte key, got {len(key)} bytes")

    if not isinstance(nonce, (bytes, bytearray)):
        raise TypeError(f"nonce must be bytes, got {type(nonce).__name__}")
    if len(nonce) < MIN_NONCE_SIZE_BYTES:
        raise ValueError(f"Nonce must be at least {MIN_NONCE_SIZE_BYTES} bytes, got {len(nonce)}")

    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError(f"ciphertext must be bytes, got {type(ciphertext).__name__}")
    if len(ciphertext) < 16:  # Tag size is 16 bytes
        raise ValueError(f"Ciphertext must include at least 16-byte authentication tag, got {len(ciphertext)} bytes")

    if associated_data is not None and not isinstance(associated_data, (bytes, bytearray)):
        raise TypeError(f"associated_data must be bytes or None, got {type(associated_data).__name__}")

    aad_bytes = bytes(associated_data) if associated_data is not None else None

    try:
        aesgcm = AESGCM(bytes(key))
        plaintext = aesgcm.decrypt(bytes(nonce), bytes(ciphertext), aad_bytes)
        return plaintext
    except InvalidTag as exc:
        raise AuthenticationTagError(
            "AES-GCM decryption/authentication failed: ciphertext, tag, or associated data tampered"
        ) from exc
    except Exception as exc:
        raise AESGCMError(f"AES-GCM decryption failed: {exc}") from exc

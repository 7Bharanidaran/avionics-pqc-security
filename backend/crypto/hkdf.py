"""HKDF Key Derivation Function (RFC 5869).

Provides HMAC-based Extract-and-Expand Key Derivation Function.
Used to derive cryptographic session keys from hybrid key exchange material (X25519 + ML-KEM).
"""

from __future__ import annotations

from typing import Literal
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand


class HKDFError(Exception):
    """Base exception for HKDF operations."""


SUPPORTED_HASHES = {
    "SHA256": hashes.SHA256,
    "SHA384": hashes.SHA384,
    "SHA512": hashes.SHA512,
}

HashAlgorithmName = Literal["SHA256", "SHA384", "SHA512"]


def _get_hash_algorithm(hash_name: str) -> hashes.HashAlgorithm:
    """Retrieve hash instance or raise ValueError."""
    normalized = hash_name.upper().replace("-", "")
    if normalized not in SUPPORTED_HASHES:
        supported = ", ".join(SUPPORTED_HASHES.keys())
        raise ValueError(f"Unsupported hash algorithm '{hash_name}'. Supported: {supported}")
    return SUPPORTED_HASHES[normalized]()


def hkdf_extract(
    salt: bytes | None,
    ikm: bytes,
    hash_name: HashAlgorithmName = "SHA256",
) -> bytes:
    """Perform HKDF-Extract step to generate a Pseudorandom Key (PRK).

    Args:
        salt: Optional salt value (a non-secret random value). If None or empty,
            a string of HashLen zeros is used per RFC 5869.
        ikm: Input Keying Material (e.g. combined hybrid shared secrets).
        hash_name: Hash algorithm to use. Defaults to "SHA256".

    Returns:
        bytes: Pseudorandom key (PRK) of length HashLen.

    Raises:
        TypeError: If ikm is not bytes or salt is invalid.
        ValueError: If ikm is empty.
        HKDFError: If extraction fails.
    """
    if not isinstance(ikm, (bytes, bytearray)):
        raise TypeError(f"ikm must be bytes, got {type(ikm).__name__}")
    if len(ikm) == 0:
        raise ValueError("Input Keying Material (ikm) cannot be empty")

    if salt is not None and not isinstance(salt, (bytes, bytearray)):
        raise TypeError(f"salt must be bytes or None, got {type(salt).__name__}")

    algo = _get_hash_algorithm(hash_name)
    hash_len = algo.digest_size

    if salt is None or len(salt) == 0:
        salt_bytes = b"\x00" * hash_len
    else:
        salt_bytes = bytes(salt)

    try:
        h = hmac.HMAC(salt_bytes, algo)
        h.update(bytes(ikm))
        return h.finalize()
    except Exception as exc:
        raise HKDFError(f"HKDF-Extract failed: {exc}") from exc


def hkdf_expand(
    prk: bytes,
    info: bytes = b"",
    length: int = 32,
    hash_name: HashAlgorithmName = "SHA256",
) -> bytes:
    """Perform HKDF-Expand step to expand a Pseudorandom Key (PRK) into Output Keying Material (OKM).

    Args:
        prk: Pseudorandom key of at least HashLen bytes (usually output of hkdf_extract).
        info: Context and application-specific information bytes.
        length: Length of output keying material in bytes (must be <= 255 * HashLen).
        hash_name: Hash algorithm to use. Defaults to "SHA256".

    Returns:
        bytes: Output keying material (OKM) of the requested length.

    Raises:
        TypeError: If arguments are not of the expected types.
        ValueError: If lengths or constraints are invalid.
        HKDFError: If expansion fails.
    """
    if not isinstance(prk, (bytes, bytearray)):
        raise TypeError(f"prk must be bytes, got {type(prk).__name__}")
    if not isinstance(info, (bytes, bytearray)):
        raise TypeError(f"info must be bytes, got {type(info).__name__}")
    if not isinstance(length, int) or length <= 0:
        raise ValueError(f"Output length must be a positive integer, got {length}")

    algo = _get_hash_algorithm(hash_name)
    max_length = 255 * algo.digest_size
    if length > max_length:
        raise ValueError(f"Requested length {length} exceeds maximum allowable length {max_length} for {hash_name}")

    if len(prk) < algo.digest_size:
        raise ValueError(f"PRK length ({len(prk)}) must be at least hash digest size ({algo.digest_size})")

    try:
        hkdf_expander = HKDFExpand(
            algorithm=algo,
            length=length,
            info=bytes(info),
        )
        return hkdf_expander.derive(bytes(prk))
    except Exception as exc:
        raise HKDFError(f"HKDF-Expand failed: {exc}") from exc


def hkdf_derive(
    ikm: bytes,
    salt: bytes | None = None,
    info: bytes = b"",
    length: int = 32,
    hash_name: HashAlgorithmName = "SHA256",
) -> bytes:
    """Perform full HKDF (Extract and Expand) in a single unified step.

    Args:
        ikm: Input Keying Material (e.g. combined hybrid shared secrets).
        salt: Optional salt value (non-secret random bytes).
        info: Optional application/context-specific info string.
        length: Desired output key length in bytes. Defaults to 32 (suitable for AES-256).
        hash_name: Hash algorithm to use. Defaults to "SHA256".

    Returns:
        bytes: Derived key material of specified length.

    Raises:
        TypeError: If arguments have invalid types.
        ValueError: If arguments have invalid lengths or constraints.
        HKDFError: If key derivation fails.
    """
    if not isinstance(ikm, (bytes, bytearray)):
        raise TypeError(f"ikm must be bytes, got {type(ikm).__name__}")
    if len(ikm) == 0:
        raise ValueError("Input Keying Material (ikm) cannot be empty")

    if salt is not None and not isinstance(salt, (bytes, bytearray)):
        raise TypeError(f"salt must be bytes or None, got {type(salt).__name__}")
    if not isinstance(info, (bytes, bytearray)):
        raise TypeError(f"info must be bytes, got {type(info).__name__}")
    if not isinstance(length, int) or length <= 0:
        raise ValueError(f"Output length must be a positive integer, got {length}")

    algo = _get_hash_algorithm(hash_name)
    max_length = 255 * algo.digest_size
    if length > max_length:
        raise ValueError(f"Requested length {length} exceeds maximum allowable length {max_length} for {hash_name}")

    try:
        hkdf = HKDF(
            algorithm=algo,
            length=length,
            salt=bytes(salt) if salt is not None else None,
            info=bytes(info),
        )
        return hkdf.derive(bytes(ikm))
    except Exception as exc:
        raise HKDFError(f"HKDF key derivation failed: {exc}") from exc

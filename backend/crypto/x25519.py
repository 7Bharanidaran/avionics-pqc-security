"""X25519 Elliptic Curve Diffie-Hellman Key Exchange.

Provides modern classical key exchange primitives based on Curve25519 (RFC 7748).
Used as the classical component in the hybrid post-quantum key exchange.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519


class X25519Error(Exception):
    """Base exception for X25519 operations."""


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a new X25519 private/public keypair.

    Returns:
        tuple[bytes, bytes]: A tuple of (private_key_raw_bytes, public_key_raw_bytes),
            both exactly 32 bytes long.
    """
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_bytes = private_key.private_bytes_raw()
    pub_bytes = public_key.public_bytes_raw()
    return priv_bytes, pub_bytes


def public_key_from_private_key(private_key_bytes: bytes) -> bytes:
    """Derive the corresponding public key from an X25519 private key.

    Args:
        private_key_bytes: 32-byte raw private key.

    Returns:
        bytes: 32-byte raw public key.

    Raises:
        TypeError: If private_key_bytes is not bytes.
        ValueError: If private_key_bytes length is not 32 bytes.
        X25519Error: If key loading fails.
    """
    if not isinstance(private_key_bytes, (bytes, bytearray)):
        raise TypeError(f"private_key_bytes must be bytes, got {type(private_key_bytes).__name__}")
    if len(private_key_bytes) != 32:
        raise ValueError(f"X25519 private key must be 32 bytes, got {len(private_key_bytes)}")

    try:
        priv_key = x25519.X25519PrivateKey.from_private_bytes(bytes(private_key_bytes))
        return priv_key.public_key().public_bytes_raw()
    except Exception as exc:
        raise X25519Error(f"Failed to derive public key: {exc}") from exc


def derive_shared_secret(private_key_bytes: bytes, peer_public_key_bytes: bytes) -> bytes:
    """Perform X25519 Diffie-Hellman key exchange to derive a shared secret.

    Args:
        private_key_bytes: 32-byte raw private key of the local party.
        peer_public_key_bytes: 32-byte raw public key of the peer party.

    Returns:
        bytes: 32-byte raw shared secret.

    Raises:
        TypeError: If either key is not bytes.
        ValueError: If either key length is invalid.
        X25519Error: If key exchange or validation fails.
    """
    if not isinstance(private_key_bytes, (bytes, bytearray)):
        raise TypeError(f"private_key_bytes must be bytes, got {type(private_key_bytes).__name__}")
    if not isinstance(peer_public_key_bytes, (bytes, bytearray)):
        raise TypeError(f"peer_public_key_bytes must be bytes, got {type(peer_public_key_bytes).__name__}")

    if len(private_key_bytes) != 32:
        raise ValueError(f"X25519 private key must be 32 bytes, got {len(private_key_bytes)}")
    if len(peer_public_key_bytes) != 32:
        raise ValueError(f"X25519 peer public key must be 32 bytes, got {len(peer_public_key_bytes)}")

    try:
        priv_key = x25519.X25519PrivateKey.from_private_bytes(bytes(private_key_bytes))
        peer_pub_key = x25519.X25519PublicKey.from_public_bytes(bytes(peer_public_key_bytes))
        shared_secret = priv_key.exchange(peer_pub_key)
        return shared_secret
    except (ValueError, TypeError, InvalidKey) as exc:
        raise X25519Error(f"X25519 shared secret derivation failed: {exc}") from exc

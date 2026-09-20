"""Ed25519 Digital Signature Algorithm (RFC 8032).

Provides modern classical digital signatures over Edwards-curve 25519.
Used as the classical component in the hybrid post-quantum authentication scheme.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519


class Ed25519Error(Exception):
    """Base exception for Ed25519 operations."""


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a new Ed25519 private/public keypair.

    Returns:
        tuple[bytes, bytes]: (private_key_raw_bytes, public_key_raw_bytes),
            both exactly 32 bytes long.
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_bytes = private_key.private_bytes_raw()
    pub_bytes = public_key.public_bytes_raw()
    return priv_bytes, pub_bytes


def public_key_from_private_key(private_key_bytes: bytes) -> bytes:
    """Derive the corresponding 32-byte public key from an Ed25519 private key.

    Args:
        private_key_bytes: 32-byte raw private key.

    Returns:
        bytes: 32-byte raw public key.

    Raises:
        TypeError: If private_key_bytes is not bytes.
        ValueError: If private_key_bytes length is not 32 bytes.
        Ed25519Error: If key loading fails.
    """
    if not isinstance(private_key_bytes, (bytes, bytearray)):
        raise TypeError(f"private_key_bytes must be bytes, got {type(private_key_bytes).__name__}")
    if len(private_key_bytes) != 32:
        raise ValueError(f"Ed25519 private key must be 32 bytes, got {len(private_key_bytes)}")

    try:
        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(private_key_bytes))
        return priv_key.public_key().public_bytes_raw()
    except Exception as exc:
        raise Ed25519Error(f"Failed to derive public key: {exc}") from exc


def sign(private_key_bytes: bytes, message: bytes) -> bytes:
    """Sign a message using an Ed25519 private key.

    Args:
        private_key_bytes: 32-byte raw private key.
        message: Message bytes to sign.

    Returns:
        bytes: 64-byte Ed25519 signature.

    Raises:
        TypeError: If inputs are not bytes.
        ValueError: If private key length is invalid.
        Ed25519Error: If signing fails.
    """
    if not isinstance(private_key_bytes, (bytes, bytearray)):
        raise TypeError(f"private_key_bytes must be bytes, got {type(private_key_bytes).__name__}")
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError(f"message must be bytes, got {type(message).__name__}")
    if len(private_key_bytes) != 32:
        raise ValueError(f"Ed25519 private key must be 32 bytes, got {len(private_key_bytes)}")

    try:
        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(private_key_bytes))
        signature = priv_key.sign(bytes(message))
        return signature
    except Exception as exc:
        raise Ed25519Error(f"Ed25519 signing failed: {exc}") from exc


def verify(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature against a public key and message.

    Args:
        public_key_bytes: 32-byte raw public key.
        message: Original message bytes.
        signature: 64-byte signature to verify.

    Returns:
        bool: True if signature is valid, False otherwise.

    Raises:
        TypeError: If any argument is not bytes.
        ValueError: If public key or signature length is invalid.
    """
    if not isinstance(public_key_bytes, (bytes, bytearray)):
        raise TypeError(f"public_key_bytes must be bytes, got {type(public_key_bytes).__name__}")
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError(f"message must be bytes, got {type(message).__name__}")
    if not isinstance(signature, (bytes, bytearray)):
        raise TypeError(f"signature must be bytes, got {type(signature).__name__}")

    if len(public_key_bytes) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(public_key_bytes)}")
    if len(signature) != 64:
        raise ValueError(f"Ed25519 signature must be 64 bytes, got {len(signature)}")

    try:
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes(public_key_bytes))
        pub_key.verify(bytes(signature), bytes(message))
        return True
    except InvalidSignature:
        return False
    except Exception as exc:
        raise Ed25519Error(f"Ed25519 verification error: {exc}") from exc

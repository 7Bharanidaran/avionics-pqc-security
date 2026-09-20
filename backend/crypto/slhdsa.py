"""SLH-DSA (Stateless Hash-Based Digital Signature Algorithm, FIPS 205).

Provides post-quantum digital signatures based on the standardized SLH-DSA (SPHINCS+) scheme.
Used as the post-quantum component in the hybrid authentication scheme.
"""

from __future__ import annotations

from typing import Literal
import slhdsa


class SLHDSAError(Exception):
    """Base exception for SLH-DSA operations."""


SUPPORTED_PARAMETER_SETS = {
    "shake_128f": {
        "param": slhdsa.shake_128f,
        "public_key_len": 32,
        "secret_key_len": 64,
        "signature_len": 17088,
    },
    "sha2_128f": {
        "param": slhdsa.sha2_128f,
        "public_key_len": 32,
        "secret_key_len": 64,
        "signature_len": 17088,
    },
    "shake_128s": {
        "param": slhdsa.shake_128s,
        "public_key_len": 32,
        "secret_key_len": 64,
        "signature_len": 7856,
    },
    "sha2_128s": {
        "param": slhdsa.sha2_128s,
        "public_key_len": 32,
        "secret_key_len": 64,
        "signature_len": 7856,
    },
    "shake_256f": {
        "param": slhdsa.shake_256f,
        "public_key_len": 64,
        "secret_key_len": 128,
        "signature_len": 49856,
    },
}

SLHDSAParameterSet = Literal["shake_128f", "sha2_128f", "shake_128s", "sha2_128s", "shake_256f"]
DEFAULT_PARAMETER_SET: SLHDSAParameterSet = "shake_128f"


def _get_param_info(parameter_set: str) -> dict:
    """Retrieve parameter set metadata or raise ValueError."""
    if parameter_set not in SUPPORTED_PARAMETER_SETS:
        supported = ", ".join(SUPPORTED_PARAMETER_SETS.keys())
        raise ValueError(f"Unsupported SLH-DSA parameter set: '{parameter_set}'. Supported: {supported}")
    return SUPPORTED_PARAMETER_SETS[parameter_set]


def generate_keypair(parameter_set: SLHDSAParameterSet = DEFAULT_PARAMETER_SET) -> tuple[bytes, bytes]:
    """Generate a new SLH-DSA secret/public keypair.

    Args:
        parameter_set: Standardized parameter set name. Defaults to 'shake_128f'.

    Returns:
        tuple[bytes, bytes]: (secret_key_bytes, public_key_bytes)
    """
    param_info = _get_param_info(parameter_set)
    param = param_info["param"]

    try:
        kp = slhdsa.KeyPair.gen(param)
        return kp.sec.digest(), kp.pub.digest()
    except Exception as exc:
        raise SLHDSAError(f"SLH-DSA keypair generation failed: {exc}") from exc


def public_key_from_secret_key(
    secret_key_bytes: bytes,
    parameter_set: SLHDSAParameterSet = DEFAULT_PARAMETER_SET,
) -> bytes:
    """Extract the public key from an SLH-DSA secret key.

    Args:
        secret_key_bytes: Raw secret key bytes.
        parameter_set: Standardized parameter set name.

    Returns:
        bytes: Raw public key bytes.
    """
    param_info = _get_param_info(parameter_set)
    if not isinstance(secret_key_bytes, (bytes, bytearray)):
        raise TypeError(f"secret_key_bytes must be bytes, got {type(secret_key_bytes).__name__}")
    if len(secret_key_bytes) != param_info["secret_key_len"]:
        raise ValueError(
            f"{parameter_set} secret key must be {param_info['secret_key_len']} bytes, got {len(secret_key_bytes)}"
        )

    try:
        sec = slhdsa.SecretKey.from_digest(bytes(secret_key_bytes), param_info["param"])
        return sec.pubkey.digest()
    except Exception as exc:
        raise SLHDSAError(f"Failed to extract public key: {exc}") from exc


def sign(
    secret_key_bytes: bytes,
    message: bytes,
    parameter_set: SLHDSAParameterSet = DEFAULT_PARAMETER_SET,
) -> bytes:
    """Sign a message using an SLH-DSA secret key.

    Args:
        secret_key_bytes: Raw secret key bytes.
        message: Message bytes to sign.
        parameter_set: Standardized parameter set name.

    Returns:
        bytes: Raw SLH-DSA signature bytes.

    Raises:
        TypeError: If arguments are not bytes.
        ValueError: If key length is invalid.
        SLHDSAError: If signing fails.
    """
    param_info = _get_param_info(parameter_set)
    if not isinstance(secret_key_bytes, (bytes, bytearray)):
        raise TypeError(f"secret_key_bytes must be bytes, got {type(secret_key_bytes).__name__}")
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError(f"message must be bytes, got {type(message).__name__}")

    if len(secret_key_bytes) != param_info["secret_key_len"]:
        raise ValueError(
            f"{parameter_set} secret key must be {param_info['secret_key_len']} bytes, got {len(secret_key_bytes)}"
        )

    try:
        sec = slhdsa.SecretKey.from_digest(bytes(secret_key_bytes), param_info["param"])
        signature = sec.sign(bytes(message))
        return signature
    except Exception as exc:
        raise SLHDSAError(f"SLH-DSA signing failed: {exc}") from exc


def verify(
    public_key_bytes: bytes,
    message: bytes,
    signature: bytes,
    parameter_set: SLHDSAParameterSet = DEFAULT_PARAMETER_SET,
) -> bool:
    """Verify an SLH-DSA signature against a message and public key.

    Args:
        public_key_bytes: Raw public key bytes.
        message: Original message bytes.
        signature: Raw signature bytes to verify.
        parameter_set: Standardized parameter set name.

    Returns:
        bool: True if signature is valid, False otherwise.

    Raises:
        TypeError: If arguments are not bytes.
        ValueError: If key or signature length is invalid.
    """
    param_info = _get_param_info(parameter_set)
    if not isinstance(public_key_bytes, (bytes, bytearray)):
        raise TypeError(f"public_key_bytes must be bytes, got {type(public_key_bytes).__name__}")
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError(f"message must be bytes, got {type(message).__name__}")
    if not isinstance(signature, (bytes, bytearray)):
        raise TypeError(f"signature must be bytes, got {type(signature).__name__}")

    if len(public_key_bytes) != param_info["public_key_len"]:
        raise ValueError(
            f"{parameter_set} public key must be {param_info['public_key_len']} bytes, got {len(public_key_bytes)}"
        )
    if len(signature) != param_info["signature_len"]:
        raise ValueError(
            f"{parameter_set} signature must be {param_info['signature_len']} bytes, got {len(signature)}"
        )

    try:
        pub = slhdsa.PublicKey.from_digest(bytes(public_key_bytes), param_info["param"])
        return bool(pub.verify(bytes(message), bytes(signature)))
    except Exception:
        return False

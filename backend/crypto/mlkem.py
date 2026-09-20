"""ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism, FIPS 203).

Provides post-quantum key encapsulation mechanism based on ML-KEM-1024 (NIST Category 5)
and ML-KEM-768 (NIST Category 3).
Used as the post-quantum component in the hybrid key exchange.
"""

from __future__ import annotations

from typing import Literal
from cryptography.hazmat.primitives.asymmetric import mlkem


class MLKEMError(Exception):
    """Base exception for ML-KEM operations."""


SUPPORTED_PARAMETER_SETS = {
    "ML-KEM-1024": {
        "priv_class": mlkem.MLKEM1024PrivateKey,
        "pub_class": mlkem.MLKEM1024PublicKey,
        "public_key_len": 1568,
        "private_key_len": 64,
        "ciphertext_len": 1568,
        "shared_secret_len": 32,
    },
    "ML-KEM-768": {
        "priv_class": mlkem.MLKEM768PrivateKey,
        "pub_class": mlkem.MLKEM768PublicKey,
        "public_key_len": 1184,
        "private_key_len": 64,
        "ciphertext_len": 1088,
        "shared_secret_len": 32,
    },
}

ParameterSet = Literal["ML-KEM-1024", "ML-KEM-768"]
DEFAULT_PARAMETER_SET: ParameterSet = "ML-KEM-1024"


def _get_params(parameter_set: str) -> dict:
    """Retrieve parameter set metadata or raise ValueError."""
    if parameter_set not in SUPPORTED_PARAMETER_SETS:
        supported = ", ".join(SUPPORTED_PARAMETER_SETS.keys())
        raise ValueError(f"Unsupported ML-KEM parameter set: '{parameter_set}'. Supported: {supported}")
    return SUPPORTED_PARAMETER_SETS[parameter_set]


def generate_keypair(parameter_set: ParameterSet = DEFAULT_PARAMETER_SET) -> tuple[bytes, bytes]:
    """Generate a new ML-KEM private/public keypair.

    Args:
        parameter_set: Standard parameter set name ("ML-KEM-1024" or "ML-KEM-768").
            Defaults to "ML-KEM-1024" (NIST Level 5).

    Returns:
        tuple[bytes, bytes]: (private_key_seed_bytes (64 bytes), public_key_bytes)
    """
    params = _get_params(parameter_set)
    priv_cls = params["priv_class"]

    private_key = priv_cls.generate()
    public_key = private_key.public_key()

    priv_bytes = private_key.private_bytes_raw()
    pub_bytes = public_key.public_bytes_raw()
    return priv_bytes, pub_bytes


def public_key_from_private_key(
    private_key_bytes: bytes,
    parameter_set: ParameterSet = DEFAULT_PARAMETER_SET,
) -> bytes:
    """Derive the public key from an ML-KEM private key seed.

    Args:
        private_key_bytes: 64-byte raw private key seed.
        parameter_set: ML-KEM parameter set name.

    Returns:
        bytes: Raw public key bytes.
    """
    params = _get_params(parameter_set)
    if not isinstance(private_key_bytes, (bytes, bytearray)):
        raise TypeError(f"private_key_bytes must be bytes, got {type(private_key_bytes).__name__}")
    if len(private_key_bytes) != params["private_key_len"]:
        raise ValueError(
            f"{parameter_set} private key seed must be {params['private_key_len']} bytes, got {len(private_key_bytes)}"
        )

    try:
        priv_cls = params["priv_class"]
        priv_key = priv_cls.from_seed_bytes(bytes(private_key_bytes))
        return priv_key.public_key().public_bytes_raw()
    except Exception as exc:
        raise MLKEMError(f"Failed to derive public key: {exc}") from exc


def encapsulate(
    public_key_bytes: bytes,
    parameter_set: ParameterSet = DEFAULT_PARAMETER_SET,
) -> tuple[bytes, bytes]:
    """Encapsulate a random shared secret against an ML-KEM public key.

    Args:
        public_key_bytes: Raw public key bytes of recipient.
        parameter_set: ML-KEM parameter set name.

    Returns:
        tuple[bytes, bytes]: (shared_secret, ciphertext)
            - shared_secret is 32 bytes
            - ciphertext is 1568 bytes for ML-KEM-1024, 1088 bytes for ML-KEM-768
    """
    params = _get_params(parameter_set)
    if not isinstance(public_key_bytes, (bytes, bytearray)):
        raise TypeError(f"public_key_bytes must be bytes, got {type(public_key_bytes).__name__}")
    if len(public_key_bytes) != params["public_key_len"]:
        raise ValueError(
            f"{parameter_set} public key must be {params['public_key_len']} bytes, got {len(public_key_bytes)}"
        )

    try:
        pub_cls = params["pub_class"]
        pub_key = pub_cls.from_public_bytes(bytes(public_key_bytes))
        shared_secret, ciphertext = pub_key.encapsulate()
        return shared_secret, ciphertext
    except Exception as exc:
        raise MLKEMError(f"ML-KEM encapsulation failed: {exc}") from exc


def decapsulate(
    private_key_bytes: bytes,
    ciphertext: bytes,
    parameter_set: ParameterSet = DEFAULT_PARAMETER_SET,
) -> bytes:
    """Decapsulate an ML-KEM ciphertext using the private key seed to recover the shared secret.

    Args:
        private_key_bytes: 64-byte raw private key seed.
        ciphertext: Ciphertext bytes to decapsulate.
        parameter_set: ML-KEM parameter set name.

    Returns:
        bytes: 32-byte recovered shared secret.

    Raises:
        TypeError: If arguments are not bytes.
        ValueError: If argument lengths are invalid.
        MLKEMError: If decapsulation fails.
    """
    params = _get_params(parameter_set)
    if not isinstance(private_key_bytes, (bytes, bytearray)):
        raise TypeError(f"private_key_bytes must be bytes, got {type(private_key_bytes).__name__}")
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError(f"ciphertext must be bytes, got {type(ciphertext).__name__}")

    if len(private_key_bytes) != params["private_key_len"]:
        raise ValueError(
            f"{parameter_set} private key seed must be {params['private_key_len']} bytes, got {len(private_key_bytes)}"
        )
    if len(ciphertext) != params["ciphertext_len"]:
        raise ValueError(
            f"{parameter_set} ciphertext must be {params['ciphertext_len']} bytes, got {len(ciphertext)}"
        )

    try:
        priv_cls = params["priv_class"]
        priv_key = priv_cls.from_seed_bytes(bytes(private_key_bytes))
        shared_secret = priv_key.decapsulate(bytes(ciphertext))
        return shared_secret
    except Exception as exc:
        raise MLKEMError(f"ML-KEM decapsulation failed: {exc}") from exc

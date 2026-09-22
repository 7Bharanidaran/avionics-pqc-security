"""Cryptographic Foundation for Avionics PQC Security.

Exposes clean, isolated public interfaces for:
- Classical Key Exchange: X25519
- Post-Quantum Key Encapsulation: ML-KEM (FIPS 203)
- Classical Digital Signatures: Ed25519 (RFC 8032)
- Post-Quantum Digital Signatures: SLH-DSA (FIPS 205)
- Key Derivation: HKDF (RFC 5869)
- Authenticated Symmetric Encryption: AES-256-GCM
"""

from __future__ import annotations

from .aes_gcm import (
    AESGCMError,
    AuthenticationTagError,
    decrypt as aes_gcm_decrypt,
    encrypt as aes_gcm_encrypt,
    generate_key as aes_gcm_generate_key,
    generate_nonce as aes_gcm_generate_nonce,
)
from .ed25519 import (
    Ed25519Error,
    generate_keypair as ed25519_generate_keypair,
    public_key_from_private_key as ed25519_public_key_from_private_key,
    sign as ed25519_sign,
    verify as ed25519_verify,
)
from .hkdf import (
    HKDFError,
    hkdf_derive,
    hkdf_expand,
    hkdf_extract,
)
from .mlkem import (
    MLKEMError,
    decapsulate as mlkem_decapsulate,
    encapsulate as mlkem_encapsulate,
    generate_keypair as mlkem_generate_keypair,
    public_key_from_private_key as mlkem_public_key_from_private_key,
)
from .slhdsa import (
    SLHDSAError,
    generate_keypair as slhdsa_generate_keypair,
    public_key_from_secret_key as slhdsa_public_key_from_secret_key,
    sign as slhdsa_sign,
    verify as slhdsa_verify,
)
from .x25519 import (
    X25519Error,
    derive_shared_secret as x25519_derive_shared_secret,
    generate_keypair as x25519_generate_keypair,
    public_key_from_private_key as x25519_public_key_from_private_key,
)
from .adaptive_base import (
    AdaptiveSession,
    BaseAdaptiveConstruction,
    ConstructionAuthenticationError,
    ConstructionDowngradeError,
    ConstructionError,
    ConstructionMetadata,
    ConstructionReplayError,
    ConstructionSecurityLevel,
)
from .adaptive_standard import (
    METADATA_STANDARD,
    ADAPTIVE_STANDARD,
    AdaptiveStandardConstruction,
)
from .adaptive_balanced import (
    METADATA_BALANCED,
    ADAPTIVE_BALANCED,
    AdaptiveBalancedConstruction,
)
from .adaptive_high_assurance import (
    METADATA_HIGH_ASSURANCE,
    ADAPTIVE_HIGH_ASSURANCE,
    AdaptiveHighAssuranceConstruction,
)
from .adaptive_critical import (
    METADATA_CRITICAL,
    ADAPTIVE_CRITICAL,
    AdaptiveCriticalConstruction,
)
from .construction_engine import (
    CONSTRUCTION_ENGINE,
    ConstructionConstraintCheck,
    ConstructionDecision,
    ConstructionEngine,
)

__all__ = [
    # X25519
    "x25519_generate_keypair",
    "x25519_public_key_from_private_key",
    "x25519_derive_shared_secret",
    "X25519Error",
    # ML-KEM
    "mlkem_generate_keypair",
    "mlkem_public_key_from_private_key",
    "mlkem_encapsulate",
    "mlkem_decapsulate",
    "MLKEMError",
    # Ed25519
    "ed25519_generate_keypair",
    "ed25519_public_key_from_private_key",
    "ed25519_sign",
    "ed25519_verify",
    "Ed25519Error",
    # SLH-DSA
    "slhdsa_generate_keypair",
    "slhdsa_public_key_from_secret_key",
    "slhdsa_sign",
    "slhdsa_verify",
    "SLHDSAError",
    # HKDF
    "hkdf_extract",
    "hkdf_expand",
    "hkdf_derive",
    "HKDFError",
    # AES-GCM
    "aes_gcm_generate_key",
    "aes_gcm_generate_nonce",
    "aes_gcm_encrypt",
    "aes_gcm_decrypt",
    "AESGCMError",
    "AuthenticationTagError",
    # Adaptive Constructions Base
    "AdaptiveSession",
    "BaseAdaptiveConstruction",
    "ConstructionAuthenticationError",
    "ConstructionDowngradeError",
    "ConstructionError",
    "ConstructionMetadata",
    "ConstructionReplayError",
    "ConstructionSecurityLevel",
    # Specific Adaptive Constructions
    "AdaptiveStandardConstruction",
    "ADAPTIVE_STANDARD",
    "METADATA_STANDARD",
    "AdaptiveBalancedConstruction",
    "ADAPTIVE_BALANCED",
    "METADATA_BALANCED",
    "AdaptiveHighAssuranceConstruction",
    "ADAPTIVE_HIGH_ASSURANCE",
    "METADATA_HIGH_ASSURANCE",
    "AdaptiveCriticalConstruction",
    "ADAPTIVE_CRITICAL",
    "METADATA_CRITICAL",
    # Construction Selection Engine
    "ConstructionEngine",
    "ConstructionDecision",
    "ConstructionConstraintCheck",
    "CONSTRUCTION_ENGINE",
]


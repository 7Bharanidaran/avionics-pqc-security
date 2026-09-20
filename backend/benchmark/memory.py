"""Memory Overhead Measurement for Avionics PQC Security Lab.

Measures the in-memory object footprint of:
- Cryptographic key material (X25519, ML-KEM, Ed25519, SLH-DSA)
- Protocol sessions (SecureSession)
- Avionics messages and encrypted packet envelopes

Uses tracemalloc and sys.getsizeof for deterministic software memory profiling.
"""

from __future__ import annotations

import sys
import tracemalloc
from typing import Any

from backend.avionics import (
    EncryptedPacketEnvelope,
    FlightControlComputer,
    MessageType,
    NavigationComputer,
)
from backend.crypto import (
    aes_gcm_generate_key,
    ed25519_generate_keypair,
    mlkem_encapsulate,
    mlkem_generate_keypair,
    slhdsa_generate_keypair,
    x25519_generate_keypair,
)
from backend.protocol import HybridHandshake, SecureSession


def measure_memory_footprint() -> dict[str, Any]:
    """Measure memory footprint of key objects using sys.getsizeof and tracemalloc.

    Returns:
        dict[str, Any]: Memory statistics in bytes.
    """
    # 1. Measure Raw Keys and Encapsulated Secrets
    x_priv, x_pub = x25519_generate_keypair()
    ml_seed, ml_pub = mlkem_generate_keypair("ML-KEM-1024")
    _, ml_ct = mlkem_encapsulate(ml_pub, "ML-KEM-1024")
    ed_priv, ed_pub = ed25519_generate_keypair()
    slh_sec, slh_pub = slhdsa_generate_keypair("shake_128f")
    aes_key = aes_gcm_generate_key()

    raw_sizes = {
        "x25519_keypair_bytes": sys.getsizeof(x_priv) + sys.getsizeof(x_pub),
        "mlkem1024_keypair_bytes": sys.getsizeof(ml_seed) + sys.getsizeof(ml_pub),
        "mlkem1024_ciphertext_bytes": sys.getsizeof(ml_ct),
        "ed25519_keypair_bytes": sys.getsizeof(ed_priv) + sys.getsizeof(ed_pub),
        "slhdsa_keypair_bytes": sys.getsizeof(slh_sec) + sys.getsizeof(slh_pub),
        "aes256_key_bytes": sys.getsizeof(aes_key),
    }

    # 2. Measure Protocol Session Allocation via tracemalloc
    tracemalloc.start()
    fcc = FlightControlComputer()
    nav = NavigationComputer()
    handshake = HybridHandshake(fcc, nav, "ML-KEM-1024", "shake_128f")
    session_init, session_resp = handshake.run()
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # 3. Message Envelope Footprint
    msg = fcc.create_altitude_message(nav.component_id, altitude_ft=32000)
    envelope = fcc.encrypt_message(nav.component_id, msg)

    envelope_size = (
        sys.getsizeof(envelope)
        + sys.getsizeof(envelope.ciphertext)
        + sys.getsizeof(envelope.nonce)
        + (sys.getsizeof(envelope.associated_data) if envelope.associated_data else 0)
    )

    return {
        "raw_cryptographic_objects": raw_sizes,
        "handshake_execution_peak_memory_bytes": peak_mem,
        "handshake_active_memory_bytes": current_mem,
        "secure_session_object_bytes": sys.getsizeof(session_init),
        "encrypted_envelope_object_bytes": envelope_size,
        "methodology": "tracemalloc + sys.getsizeof in-memory heap profiling",
    }

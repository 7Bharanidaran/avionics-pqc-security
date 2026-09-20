"""Performance Benchmarking and Experimental Evaluation for Avionics PQC Security Lab.

Provides high-resolution micro-benchmarking using time.perf_counter_ns() for:
- Primitive Operations: X25519, ML-KEM-1024, Ed25519, SLH-DSA (shake_128f), HKDF-SHA256, AES-256-GCM
- Protocol Operations: Full Hybrid Handshake (FCC -> NAV), Secure Message Encrypt/Transport/Decrypt
- Comparative Analysis: Classical Baseline (X25519 + Ed25519 + AES) vs Hybrid PQC
- Serialization: Detailed size measurements for keys, ciphertexts, signatures, and overhead

DISCLAIMER: Measurements are environment-dependent software benchmarks executing on local test hardware.
"""

from __future__ import annotations

import csv
import io
import json
import math
import os
import platform
import statistics
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

import cryptography
import slhdsa

from backend.avionics import (
    FlightControlComputer,
    MessageType,
    NavigationComputer,
    SimulatedChannel,
)
from backend.crypto import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    aes_gcm_generate_key,
    aes_gcm_generate_nonce,
    ed25519_generate_keypair,
    ed25519_sign,
    ed25519_verify,
    hkdf_derive,
    mlkem_decapsulate,
    mlkem_encapsulate,
    mlkem_generate_keypair,
    slhdsa_generate_keypair,
    slhdsa_sign,
    slhdsa_verify,
    x25519_derive_shared_secret,
    x25519_generate_keypair,
)
from backend.protocol import HybridHandshake


# =====================================================================
# Data Models
# =====================================================================


@dataclass
class BenchmarkMetric:
    """Statistical summary of multiple iterations of a benchmarked operation."""

    name: str
    category: str
    iterations: int
    min_ns: float
    max_ns: float
    mean_ns: float
    median_ns: float
    stddev_ns: float
    p95_ns: float

    @property
    def median_us(self) -> float:
        """Median latency in microseconds (µs)."""
        return self.median_ns / 1_000.0

    @property
    def p95_us(self) -> float:
        """95th percentile latency in microseconds (µs)."""
        return self.p95_ns / 1_000.0

    @property
    def median_ms(self) -> float:
        """Median latency in milliseconds (ms)."""
        return self.median_ns / 1_000_000.0

    @property
    def p95_ms(self) -> float:
        """95th percentile latency in milliseconds (ms)."""
        return self.p95_ns / 1_000_000.0

    def to_dict(self) -> dict[str, Any]:
        """Convert metric to dictionary."""
        return {
            "name": self.name,
            "category": self.category,
            "iterations": self.iterations,
            "min_ns": self.min_ns,
            "max_ns": self.max_ns,
            "mean_ns": self.mean_ns,
            "median_ns": self.median_ns,
            "stddev_ns": self.stddev_ns,
            "p95_ns": self.p95_ns,
            "median_us": self.median_us,
            "p95_us": self.p95_us,
            "median_ms": self.median_ms,
            "p95_ms": self.p95_ms,
        }


@dataclass
class SizeMeasurement:
    """Byte size measurement of a cryptographic key, signature, ciphertext, or envelope."""

    item_name: str
    category: str
    size_bytes: int
    description: str

    def to_dict(self) -> dict[str, Any]:
        """Convert size measurement to dictionary."""
        return {
            "item_name": self.item_name,
            "category": self.category,
            "size_bytes": self.size_bytes,
            "description": self.description,
        }


@dataclass
class BenchmarkSuiteReport:
    """Complete aggregated benchmark report."""

    timestamp: str
    environment: dict[str, Any]
    metrics: list[BenchmarkMetric]
    sizes: list[SizeMeasurement]
    comparisons: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "timestamp": self.timestamp,
            "environment": self.environment,
            "metrics": [m.to_dict() for m in self.metrics],
            "sizes": [s.to_dict() for s in self.sizes],
            "comparisons": self.comparisons,
        }

    def to_json(self, indent: int = 2) -> str:
        """Export report to formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_csv(self) -> str:
        """Export metrics to CSV string."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Category",
            "Operation",
            "Iterations",
            "Median (us)",
            "P95 (us)",
            "Mean (us)",
            "Min (us)",
            "Max (us)",
            "StdDev (us)",
        ])
        for m in self.metrics:
            writer.writerow([
                m.category,
                m.name,
                m.iterations,
                f"{m.median_us:.2f}",
                f"{m.p95_us:.2f}",
                f"{m.mean_ns / 1000.0:.2f}",
                f"{m.min_ns / 1000.0:.2f}",
                f"{m.max_ns / 1000.0:.2f}",
                f"{m.stddev_ns / 1000.0:.2f}",
            ])
        return output.getvalue()


# =====================================================================
# Benchmark Execution Helpers
# =====================================================================


def get_benchmark_environment() -> dict[str, Any]:
    """Capture benchmark hardware and software environment details."""
    return {
        "python_version": sys.version.split()[0],
        "os_platform": platform.platform(),
        "processor": platform.processor() or "Unknown CPU",
        "cpu_count": os.cpu_count() or 1,
        "cryptography_version": getattr(cryptography, "__version__", "unknown"),
        "slhdsa_version": getattr(slhdsa, "__version__", "0.2.5"),
    }


def time_operation(
    func: Callable[[], Any],
    iterations: int = 50,
    warmup: int = 5,
    name: str = "Operation",
    category: str = "Primitive",
) -> BenchmarkMetric:
    """Execute and statistically evaluate an operation using time.perf_counter_ns().

    Args:
        func: Zero-argument callable to benchmark.
        iterations: Number of recorded iterations.
        warmup: Number of unrecorded warm-up iterations.
        name: Name of the operation.
        category: Benchmark category.

    Returns:
        BenchmarkMetric: Aggregated performance metrics.
    """
    # 1. Warm-up
    for _ in range(max(1, warmup)):
        func()

    # 2. Recorded executions
    durations_ns: list[int] = []
    for _ in range(max(1, iterations)):
        t0 = time.perf_counter_ns()
        func()
        t1 = time.perf_counter_ns()
        durations_ns.append(t1 - t0)

    durations_ns.sort()
    n = len(durations_ns)

    min_ns = float(durations_ns[0])
    max_ns = float(durations_ns[-1])
    mean_ns = float(statistics.mean(durations_ns))
    median_ns = float(statistics.median(durations_ns))
    stddev_ns = float(statistics.stdev(durations_ns)) if n > 1 else 0.0

    # P95 percentile
    p95_idx = min(n - 1, int(math.ceil(0.95 * n)) - 1)
    p95_ns = float(durations_ns[p95_idx])

    return BenchmarkMetric(
        name=name,
        category=category,
        iterations=iterations,
        min_ns=min_ns,
        max_ns=max_ns,
        mean_ns=mean_ns,
        median_ns=median_ns,
        stddev_ns=stddev_ns,
        p95_ns=p95_ns,
    )


# =====================================================================
# Benchmark Modules
# =====================================================================


def benchmark_x25519(iterations: int = 50) -> list[BenchmarkMetric]:
    """Benchmark X25519 Key Generation and Diffie-Hellman Shared Secret Derivation."""
    metrics = []

    # 1. Key Generation
    metric_keygen = time_operation(
        func=x25519_generate_keypair,
        iterations=iterations,
        warmup=5,
        name="X25519 Key Generation",
        category="Key Exchange",
    )
    metrics.append(metric_keygen)

    # 2. Shared Secret Derivation
    priv_a, pub_a = x25519_generate_keypair()
    priv_b, pub_b = x25519_generate_keypair()

    metric_dh = time_operation(
        func=lambda: x25519_derive_shared_secret(priv_a, pub_b),
        iterations=iterations,
        warmup=5,
        name="X25519 Shared Secret Derivation",
        category="Key Exchange",
    )
    metrics.append(metric_dh)

    return metrics


def benchmark_mlkem(iterations: int = 50) -> list[BenchmarkMetric]:
    """Benchmark ML-KEM-1024 Key Generation, Encapsulation, and Decapsulation."""
    metrics = []

    # 1. Key Generation
    metric_keygen = time_operation(
        func=lambda: mlkem_generate_keypair("ML-KEM-1024"),
        iterations=iterations,
        warmup=5,
        name="ML-KEM-1024 Key Generation",
        category="Key Encapsulation",
    )
    metrics.append(metric_keygen)

    # 2. Encapsulation
    seed, pub = mlkem_generate_keypair("ML-KEM-1024")
    metric_encap = time_operation(
        func=lambda: mlkem_encapsulate(pub, "ML-KEM-1024"),
        iterations=iterations,
        warmup=5,
        name="ML-KEM-1024 Encapsulation",
        category="Key Encapsulation",
    )
    metrics.append(metric_encap)

    # 3. Decapsulation
    _, ciphertext = mlkem_encapsulate(pub, "ML-KEM-1024")
    metric_decap = time_operation(
        func=lambda: mlkem_decapsulate(seed, ciphertext, "ML-KEM-1024"),
        iterations=iterations,
        warmup=5,
        name="ML-KEM-1024 Decapsulation",
        category="Key Encapsulation",
    )
    metrics.append(metric_decap)

    return metrics


def benchmark_ed25519(iterations: int = 50) -> list[BenchmarkMetric]:
    """Benchmark Ed25519 Key Generation, Signing, and Verification."""
    metrics = []
    message = b"AVIONICS_TELEMETRY:ALTITUDE=32000FT,HEADING=275DEG"

    # 1. Key Generation
    metric_keygen = time_operation(
        func=ed25519_generate_keypair,
        iterations=iterations,
        warmup=5,
        name="Ed25519 Key Generation",
        category="Digital Signature",
    )
    metrics.append(metric_keygen)

    # 2. Signing
    priv, pub = ed25519_generate_keypair()
    metric_sign = time_operation(
        func=lambda: ed25519_sign(priv, message),
        iterations=iterations,
        warmup=5,
        name="Ed25519 Signing",
        category="Digital Signature",
    )
    metrics.append(metric_sign)

    # 3. Verification
    sig = ed25519_sign(priv, message)
    metric_verify = time_operation(
        func=lambda: ed25519_verify(pub, message, sig),
        iterations=iterations,
        warmup=5,
        name="Ed25519 Verification",
        category="Digital Signature",
    )
    metrics.append(metric_verify)

    return metrics


def benchmark_slhdsa(iterations: int = 15) -> list[BenchmarkMetric]:
    """Benchmark SLH-DSA (shake_128f) Key Generation, Signing, and Verification.

    Note: SLH-DSA signing is computationally intensive (~0.1s per operation),
    so a lower iteration count (10-15) is used for responsiveness.
    """
    metrics = []
    message = b"AVIONICS_HANDSHAKE_TRANSCRIPT_HASH_32BYTES_LEN!"

    # 1. Key Generation
    metric_keygen = time_operation(
        func=lambda: slhdsa_generate_keypair("shake_128f"),
        iterations=iterations,
        warmup=2,
        name="SLH-DSA Key Generation",
        category="Digital Signature (PQC)",
    )
    metrics.append(metric_keygen)

    # 2. Signing
    sec, pub = slhdsa_generate_keypair("shake_128f")
    metric_sign = time_operation(
        func=lambda: slhdsa_sign(sec, message, "shake_128f"),
        iterations=iterations,
        warmup=2,
        name="SLH-DSA Signing",
        category="Digital Signature (PQC)",
    )
    metrics.append(metric_sign)

    # 3. Verification
    sig = slhdsa_sign(sec, message, "shake_128f")
    metric_verify = time_operation(
        func=lambda: slhdsa_verify(pub, message, sig, "shake_128f"),
        iterations=iterations,
        warmup=2,
        name="SLH-DSA Verification",
        category="Digital Signature (PQC)",
    )
    metrics.append(metric_verify)

    return metrics


def benchmark_hkdf(iterations: int = 50) -> list[BenchmarkMetric]:
    """Benchmark HKDF-SHA256 session key derivation from hybrid key material."""
    ikm = os.urandom(64)  # 32B X25519 + 32B ML-KEM
    salt = os.urandom(32)
    info = b"AVIONICS_HYBRID_PQC_SESSION_KEY_V1"

    metric = time_operation(
        func=lambda: hkdf_derive(ikm=ikm, salt=salt, info=info, length=32, hash_name="SHA256"),
        iterations=iterations,
        warmup=5,
        name="HKDF-SHA256 Key Derivation",
        category="Key Derivation",
    )
    return [metric]


def benchmark_aes_gcm(iterations: int = 50) -> list[BenchmarkMetric]:
    """Benchmark AES-256-GCM encryption and decryption across payload sizes: 64B, 256B, 1024B, 4096B."""
    metrics = []
    sizes = [64, 256, 1024, 4096]
    key = aes_gcm_generate_key()
    aad = b"SECURITY_HEADER:SRC=FCC,DST=NAV,SESSION=12345"

    for sz in sizes:
        payload = os.urandom(sz)

        # 1. Encryption
        metric_enc = time_operation(
            func=lambda: aes_gcm_encrypt(key=key, plaintext=payload, associated_data=aad),
            iterations=iterations,
            warmup=5,
            name=f"AES-256-GCM Encrypt ({sz} B)",
            category="Symmetric Encryption",
        )
        metrics.append(metric_enc)

        # 2. Decryption
        ct, nonce = aes_gcm_encrypt(key=key, plaintext=payload, associated_data=aad)
        metric_dec = time_operation(
            func=lambda: aes_gcm_decrypt(key=key, nonce=nonce, ciphertext=ct, associated_data=aad),
            iterations=iterations,
            warmup=5,
            name=f"AES-256-GCM Decrypt ({sz} B)",
            category="Symmetric Encryption",
        )
        metrics.append(metric_dec)

    return metrics


def measure_sizes() -> list[SizeMeasurement]:
    """Measure exact serialized byte lengths from live cryptographic objects."""
    # X25519
    x_priv, x_pub = x25519_generate_keypair()

    # ML-KEM-1024
    ml_seed, ml_pub = mlkem_generate_keypair("ML-KEM-1024")
    _, ml_ct = mlkem_encapsulate(ml_pub, "ML-KEM-1024")

    # Ed25519
    ed_priv, ed_pub = ed25519_generate_keypair()
    ed_sig = ed25519_sign(ed_priv, b"TEST_MESSAGE_BYTES")

    # SLH-DSA
    slh_sec, slh_pub = slhdsa_generate_keypair("shake_128f")
    slh_sig = slhdsa_sign(slh_sec, b"TEST_MESSAGE_BYTES", "shake_128f")

    # AES-GCM
    nonce = aes_gcm_generate_nonce()

    return [
        SizeMeasurement("X25519 Public Key", "Key Exchange (Classical)", len(x_pub), "Curve25519 raw public key"),
        SizeMeasurement("X25519 Private Key", "Key Exchange (Classical)", len(x_priv), "Curve25519 raw private scalar"),
        SizeMeasurement("ML-KEM-1024 Public Key", "Key Encapsulation (PQC)", len(ml_pub), "FIPS 203 public key (NIST Level 5)"),
        SizeMeasurement("ML-KEM-1024 Private Seed", "Key Encapsulation (PQC)", len(ml_seed), "FIPS 203 private key seed"),
        SizeMeasurement("ML-KEM-1024 Ciphertext", "Key Encapsulation (PQC)", len(ml_ct), "FIPS 203 encapsulated key ciphertext"),
        SizeMeasurement("Ed25519 Public Key", "Authentication (Classical)", len(ed_pub), "Ed25519 raw public key"),
        SizeMeasurement("Ed25519 Signature", "Authentication (Classical)", len(ed_sig), "Ed25519 detached signature"),
        SizeMeasurement("SLH-DSA Public Key", "Authentication (PQC)", len(slh_pub), "FIPS 205 (shake_128f) public key"),
        SizeMeasurement("SLH-DSA Signature", "Authentication (PQC)", len(slh_sig), "FIPS 205 (shake_128f) stateless hash signature"),
        SizeMeasurement("AES-GCM Nonce", "Symmetric Encryption", len(nonce), "Standard 96-bit initialization vector"),
        SizeMeasurement("AES-GCM Auth Tag", "Symmetric Encryption", 16, "128-bit authentication tag"),
    ]


def benchmark_hybrid_handshake(iterations: int = 15) -> list[BenchmarkMetric]:
    """Benchmark full Phase 4 Hybrid Handshake (FCC -> NAV)."""
    fcc = FlightControlComputer()
    nav = NavigationComputer()

    def _execute_handshake():
        handshake = HybridHandshake(
            initiator=fcc,
            responder=nav,
            mlkem_param="ML-KEM-1024",
            slhdsa_param="shake_128f",
        )
        return handshake.run()

    metric = time_operation(
        func=_execute_handshake,
        iterations=iterations,
        warmup=2,
        name="Total Hybrid Handshake Latency",
        category="Protocol Handshake",
    )
    return [metric]


def benchmark_secure_messaging(iterations: int = 50) -> list[BenchmarkMetric]:
    """Benchmark secure message flow (Encrypt, Simulated Transport, Decrypt) across payload sizes."""
    metrics = []
    sizes = [64, 256, 1024, 4096]

    fcc = FlightControlComputer()
    nav = NavigationComputer()
    channel = SimulatedChannel(name="BENCHMARK_LINK")
    fcc.establish_secure_session(nav)

    for sz in sizes:
        # Create message with payload of specific length
        payload_data = "X" * (sz // 2)
        msg = fcc.create_status_message(nav.component_id, status=payload_data)

        # 1. Encrypt
        metric_enc = time_operation(
            func=lambda: fcc.encrypt_message(nav.component_id, msg),
            iterations=iterations,
            warmup=5,
            name=f"Secure Message Encrypt ({sz} B)",
            category="Message Flow",
        )
        metrics.append(metric_enc)

        # 2. Simulated Transport
        env = fcc.encrypt_message(nav.component_id, msg)
        metric_tx = time_operation(
            func=lambda: channel.transmit(env),
            iterations=iterations,
            warmup=5,
            name=f"Simulated Datalink Transport ({sz} B)",
            category="Message Flow",
        )
        metrics.append(metric_tx)

        # 3. Decrypt (pre-generate unique envelopes with distinct nonces)
        total_runs = iterations + 10
        unique_envelopes = [fcc.encrypt_message(nav.component_id, msg) for _ in range(total_runs)]
        decap_idx = 0

        def _timed_decrypt():
            nonlocal decap_idx
            curr_env = unique_envelopes[decap_idx]
            decap_idx += 1
            return nav.decrypt_message(curr_env)

        metric_dec = time_operation(
            func=_timed_decrypt,
            iterations=iterations,
            warmup=5,
            name=f"Secure Message Decrypt ({sz} B)",
            category="Message Flow",
        )
        metrics.append(metric_dec)

    return metrics


def benchmark_classical_vs_hybrid(iterations: int = 15) -> dict[str, Any]:
    """Quantify overhead comparing Classical Baseline against Hybrid PQC Protocol."""
    # Classical Baseline Key Exchange + Auth:
    # (X25519 keygen + DH) + (Ed25519 keygen + sign + verify)
    def _classical_flow():
        # X25519
        priv_a, pub_a = x25519_generate_keypair()
        priv_b, pub_b = x25519_generate_keypair()
        ss_a = x25519_derive_shared_secret(priv_a, pub_b)
        ss_b = x25519_derive_shared_secret(priv_b, pub_a)
        # Ed25519 auth
        ed_priv, ed_pub = ed25519_generate_keypair()
        sig = ed25519_sign(ed_priv, ss_a)
        ed25519_verify(ed_pub, ss_a, sig)
        # AES-256 session key from single hash
        key = hkdf_derive(ss_a, length=32)
        return key

    # Hybrid PQC Flow (Full Hybrid Handshake):
    fcc = FlightControlComputer()
    nav = NavigationComputer()

    def _hybrid_flow():
        handshake = HybridHandshake(fcc, nav, "ML-KEM-1024", "shake_128f")
        return handshake.run()

    metric_classical = time_operation(_classical_flow, iterations=iterations, warmup=2, name="Classical Handshake", category="Comparison")
    metric_hybrid = time_operation(_hybrid_flow, iterations=iterations, warmup=2, name="Hybrid PQC Handshake", category="Comparison")

    # Size comparison
    classical_tx_size = 32 + 32 + 64  # X25519 pub A + X25519 pub B + Ed25519 sig
    hybrid_tx_size = 32 + 1568 + 32 + 1568 + 64 + 17088 + 64 + 17088  # Pubs + CT + Sigs

    return {
        "classical_baseline": {
            "name": "Classical Baseline (X25519 + Ed25519 + AES-256)",
            "median_ms": metric_classical.median_ms,
            "p95_ms": metric_classical.p95_ms,
            "handshake_data_bytes": classical_tx_size,
        },
        "hybrid_pqc": {
            "name": "Hybrid PQC Protocol (X25519 + ML-KEM-1024 + Ed25519 + SLH-DSA + HKDF + AES-256)",
            "median_ms": metric_hybrid.median_ms,
            "p95_ms": metric_hybrid.p95_ms,
            "handshake_data_bytes": hybrid_tx_size,
        },
        "overhead_factors": {
            "latency_overhead_multiplier": metric_hybrid.median_ms / max(0.001, metric_classical.median_ms),
            "data_overhead_multiplier": hybrid_tx_size / classical_tx_size,
            "additional_latency_ms": metric_hybrid.median_ms - metric_classical.median_ms,
            "additional_data_bytes": hybrid_tx_size - classical_tx_size,
        },
    }


# =====================================================================
# Full Suite Execution & Storage
# =====================================================================


def run_full_benchmark_suite(
    output_dir: str = "data/benchmarks",
    iterations_fast: int = 50,
    iterations_heavy: int = 15,
) -> BenchmarkSuiteReport:
    """Run all benchmark modules, calculate statistics, and save JSON + CSV files.

    Args:
        output_dir: Directory path where output files should be saved.
        iterations_fast: Iterations for fast operations.
        iterations_heavy: Iterations for SLH-DSA and handshake operations.

    Returns:
        BenchmarkSuiteReport: Aggregated report object.
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    timestamp_file = time.strftime("%Y%m%d_%H%M%S")
    env = get_benchmark_environment()

    all_metrics: list[BenchmarkMetric] = []

    # 1. Primitives
    all_metrics.extend(benchmark_x25519(iterations=iterations_fast))
    all_metrics.extend(benchmark_mlkem(iterations=iterations_fast))
    all_metrics.extend(benchmark_ed25519(iterations=iterations_fast))
    all_metrics.extend(benchmark_slhdsa(iterations=iterations_heavy))
    all_metrics.extend(benchmark_hkdf(iterations=iterations_fast))
    all_metrics.extend(benchmark_aes_gcm(iterations=iterations_fast))

    # 2. Handshake & Messaging
    all_metrics.extend(benchmark_hybrid_handshake(iterations=iterations_heavy))
    all_metrics.extend(benchmark_secure_messaging(iterations=iterations_fast))

    # 3. Sizes & Comparisons
    sizes = measure_sizes()
    comparisons = benchmark_classical_vs_hybrid(iterations=iterations_heavy)

    report = BenchmarkSuiteReport(
        timestamp=timestamp,
        environment=env,
        metrics=all_metrics,
        sizes=sizes,
        comparisons=comparisons,
    )

    # 4. Save to files
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    # Latest JSON
    latest_json = out_path / "latest.json"
    latest_json.write_text(report.to_json(), encoding="utf-8")

    # Timestamped JSON
    timestamped_json = out_path / f"benchmark_{timestamp_file}.json"
    timestamped_json.write_text(report.to_json(), encoding="utf-8")

    # Latest CSV
    latest_csv = out_path / "latest.csv"
    latest_csv.write_text(report.to_csv(), encoding="utf-8")

    return report

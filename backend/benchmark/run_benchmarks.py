"""CLI Benchmark Runner for Avionics PQC Security Lab.

Executes performance benchmarks, calculates statistics using high-resolution monotonic timer,
exports structured data to data/benchmarks/latest.json and latest.csv, and displays concise CLI summary.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Ensure UTF-8 output encoding on Windows console
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.benchmark.performance import (
    BenchmarkMetric,
    BenchmarkSuiteReport,
    run_full_benchmark_suite,
)


def find_metric(metrics: list[BenchmarkMetric], name: str) -> BenchmarkMetric | None:
    """Helper to find a metric by exact or partial name."""
    for m in metrics:
        if m.name == name or name in m.name:
            return m
    return None


def run_and_display_benchmarks() -> BenchmarkSuiteReport:
    """Run full benchmark suite and print formatted report."""
    output_dir = PROJECT_ROOT / "data" / "benchmarks"
    report = run_full_benchmark_suite(
        output_dir=str(output_dir),
        iterations_fast=50,
        iterations_heavy=15,
    )

    metrics = report.metrics
    env = report.environment

    print("==================================================")
    print("AVIONICS PQC SECURITY LAB")
    print("PHASE 6")
    print("PERFORMANCE BENCHMARK")
    print("==================================================")
    print()
    print("Environment:")
    print(f"Python: {env['python_version']} ({env['os_platform']})")
    print(f"Crypto library: cryptography {env['cryptography_version']} | SLH-DSA {env['slhdsa_version']}")
    print()
    print("--------------------------------------------------")
    print("CRYPTOGRAPHIC OPERATIONS")
    print("--------------------------------------------------")
    print()

    # X25519
    m_x_gen = find_metric(metrics, "X25519 Key Generation")
    if m_x_gen:
        print("X25519 Key Generation:")
        print(f"Median: {m_x_gen.median_us:.2f} µs")
        print(f"P95: {m_x_gen.p95_us:.2f} µs")
        print()

    m_x_dh = find_metric(metrics, "X25519 Shared Secret Derivation")
    if m_x_dh:
        print("X25519 Shared Secret:")
        print(f"Median: {m_x_dh.median_us:.2f} µs")
        print(f"P95: {m_x_dh.p95_us:.2f} µs")
        print()

    # ML-KEM
    m_ml_gen = find_metric(metrics, "ML-KEM-1024 Key Generation")
    if m_ml_gen:
        print("ML-KEM Key Generation:")
        print(f"Median: {m_ml_gen.median_us:.2f} µs")
        print(f"P95: {m_ml_gen.p95_us:.2f} µs")
        print()

    m_ml_enc = find_metric(metrics, "ML-KEM-1024 Encapsulation")
    if m_ml_enc:
        print("ML-KEM Encapsulation:")
        print(f"Median: {m_ml_enc.median_us:.2f} µs")
        print(f"P95: {m_ml_enc.p95_us:.2f} µs")
        print()

    m_ml_dec = find_metric(metrics, "ML-KEM-1024 Decapsulation")
    if m_ml_dec:
        print("ML-KEM Decapsulation:")
        print(f"Median: {m_ml_dec.median_us:.2f} µs")
        print(f"P95: {m_ml_dec.p95_us:.2f} µs")
        print()

    # Ed25519
    m_ed_sign = find_metric(metrics, "Ed25519 Signing")
    if m_ed_sign:
        print("Ed25519 Signing:")
        print(f"Median: {m_ed_sign.median_us:.2f} µs")
        print(f"P95: {m_ed_sign.p95_us:.2f} µs")
        print()

    m_ed_ver = find_metric(metrics, "Ed25519 Verification")
    if m_ed_ver:
        print("Ed25519 Verification:")
        print(f"Median: {m_ed_ver.median_us:.2f} µs")
        print(f"P95: {m_ed_ver.p95_us:.2f} µs")
        print()

    # SLH-DSA
    m_slh_sign = find_metric(metrics, "SLH-DSA Signing")
    if m_slh_sign:
        print("SLH-DSA Signing:")
        print(f"Median: {m_slh_sign.median_us:.2f} µs ({m_slh_sign.median_ms:.2f} ms)")
        print(f"P95: {m_slh_sign.p95_us:.2f} µs ({m_slh_sign.p95_ms:.2f} ms)")
        print()

    m_slh_ver = find_metric(metrics, "SLH-DSA Verification")
    if m_slh_ver:
        print("SLH-DSA Verification:")
        print(f"Median: {m_slh_ver.median_us:.2f} µs ({m_slh_ver.median_ms:.2f} ms)")
        print(f"P95: {m_slh_ver.p95_us:.2f} µs ({m_slh_ver.p95_ms:.2f} ms)")
        print()

    # HKDF
    m_hkdf = find_metric(metrics, "HKDF-SHA256 Key Derivation")
    if m_hkdf:
        print("HKDF:")
        print(f"Median: {m_hkdf.median_us:.2f} µs")
        print(f"P95: {m_hkdf.p95_us:.2f} µs")
        print()

    # Hybrid Handshake
    print("--------------------------------------------------")
    print("HYBRID HANDSHAKE")
    print("--------------------------------------------------")
    print()

    m_hs = find_metric(metrics, "Total Hybrid Handshake Latency")
    if m_hs:
        print("Total handshake latency:")
        print(f"Median: {m_hs.median_ms:.2f} ms")
        print()
        print("P95:")
        print(f"{m_hs.p95_ms:.2f} ms")
        print()

    # AES-256-GCM
    print("--------------------------------------------------")
    print("AES-256-GCM")
    print("--------------------------------------------------")
    print()

    sizes = [64, 256, 1024, 4096]
    for sz in sizes:
        enc = find_metric(metrics, f"AES-256-GCM Encrypt ({sz} B)")
        dec = find_metric(metrics, f"AES-256-GCM Decrypt ({sz} B)")
        enc_val = f"{enc.median_us:.2f} µs" if enc else "N/A"
        dec_val = f"{dec.median_us:.2f} µs" if dec else "N/A"
        print(f"{sz} B:")
        print(f"Encryption: {enc_val}")
        print(f"Decryption: {dec_val}")
        print()

    print("--------------------------------------------------")
    print("RESULT FILES")
    print("--------------------------------------------------")
    print()
    print("JSON:")
    print(str(output_dir / "latest.json"))
    print()
    print("CSV:")
    print(str(output_dir / "latest.csv"))
    print()
    print("==================================================")

    return report


if __name__ == "__main__":
    run_and_display_benchmarks()

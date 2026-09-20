"""Unit tests for performance benchmarking framework (Phase 6)."""

import json
import tempfile
from pathlib import Path
import pytest

from backend.benchmark import (
    BenchmarkMetric,
    BenchmarkSuiteReport,
    SizeMeasurement,
    benchmark_aes_gcm,
    benchmark_classical_vs_hybrid,
    benchmark_ed25519,
    benchmark_hkdf,
    benchmark_hybrid_handshake,
    benchmark_mlkem,
    benchmark_secure_messaging,
    benchmark_slhdsa,
    benchmark_x25519,
    get_benchmark_environment,
    measure_memory_footprint,
    measure_sizes,
    run_full_benchmark_suite,
    time_operation,
)


def test_get_benchmark_environment():
    """Test capture of environment metadata."""
    env = get_benchmark_environment()
    assert isinstance(env, dict)
    assert "python_version" in env
    assert "os_platform" in env
    assert "cryptography_version" in env
    assert "slhdsa_version" in env
    assert env["cpu_count"] >= 1


def test_time_operation_statistics():
    """Test that time_operation produces valid statistical distributions."""
    call_count = 0

    def dummy_op():
        nonlocal call_count
        call_count += 1
        _ = sum(i * i for i in range(100))

    metric = time_operation(dummy_op, iterations=10, warmup=2, name="Dummy Op", category="Test")

    assert isinstance(metric, BenchmarkMetric)
    assert metric.name == "Dummy Op"
    assert metric.category == "Test"
    assert metric.iterations == 10
    assert call_count == 12  # 10 + 2 warmup
    assert metric.min_ns >= 0
    assert metric.max_ns >= metric.min_ns
    assert metric.mean_ns >= metric.min_ns
    assert metric.median_ns >= metric.min_ns
    assert metric.p95_ns >= metric.median_ns
    assert metric.median_us >= 0
    assert metric.median_ms >= 0


def test_benchmark_x25519_execution():
    """Test X25519 benchmark execution."""
    metrics = benchmark_x25519(iterations=5)
    assert len(metrics) == 2
    names = {m.name for m in metrics}
    assert "X25519 Key Generation" in names
    assert "X25519 Shared Secret Derivation" in names
    for m in metrics:
        assert m.iterations == 5
        assert m.median_ns > 0


def test_benchmark_mlkem_execution():
    """Test ML-KEM benchmark execution."""
    metrics = benchmark_mlkem(iterations=5)
    assert len(metrics) == 3
    names = {m.name for m in metrics}
    assert "ML-KEM-1024 Key Generation" in names
    assert "ML-KEM-1024 Encapsulation" in names
    assert "ML-KEM-1024 Decapsulation" in names
    for m in metrics:
        assert m.iterations == 5
        assert m.median_ns > 0


def test_benchmark_ed25519_execution():
    """Test Ed25519 benchmark execution."""
    metrics = benchmark_ed25519(iterations=5)
    assert len(metrics) == 3
    names = {m.name for m in metrics}
    assert "Ed25519 Key Generation" in names
    assert "Ed25519 Signing" in names
    assert "Ed25519 Verification" in names
    for m in metrics:
        assert m.iterations == 5
        assert m.median_ns > 0


def test_benchmark_slhdsa_execution():
    """Test SLH-DSA benchmark execution."""
    metrics = benchmark_slhdsa(iterations=2)
    assert len(metrics) == 3
    names = {m.name for m in metrics}
    assert "SLH-DSA Key Generation" in names
    assert "SLH-DSA Signing" in names
    assert "SLH-DSA Verification" in names
    for m in metrics:
        assert m.iterations == 2
        assert m.median_ns > 0


def test_benchmark_hkdf_execution():
    """Test HKDF benchmark execution."""
    metrics = benchmark_hkdf(iterations=5)
    assert len(metrics) == 1
    assert metrics[0].name == "HKDF-SHA256 Key Derivation"
    assert metrics[0].median_ns > 0


def test_benchmark_aes_gcm_execution():
    """Test AES-256-GCM benchmark execution across multiple payload sizes."""
    metrics = benchmark_aes_gcm(iterations=5)
    assert len(metrics) == 8  # 4 sizes * 2 (enc/dec)
    for m in metrics:
        assert m.iterations == 5
        assert m.median_ns > 0


def test_measure_sizes_accuracy():
    """Test that size measurements match expected byte lengths of live objects."""
    sizes = measure_sizes()
    assert len(sizes) == 11

    size_map = {s.item_name: s.size_bytes for s in sizes}

    # Verify cryptographic byte lengths
    assert size_map["X25519 Public Key"] == 32
    assert size_map["X25519 Private Key"] == 32
    assert size_map["ML-KEM-1024 Public Key"] == 1568
    assert size_map["ML-KEM-1024 Private Seed"] == 64
    assert size_map["ML-KEM-1024 Ciphertext"] == 1568
    assert size_map["Ed25519 Public Key"] == 32
    assert size_map["Ed25519 Signature"] == 64
    assert size_map["SLH-DSA Public Key"] == 32
    assert size_map["SLH-DSA Signature"] == 17088
    assert size_map["AES-GCM Nonce"] == 12
    assert size_map["AES-GCM Auth Tag"] == 16


def test_benchmark_hybrid_handshake_execution():
    """Test full Hybrid Handshake benchmark execution."""
    metrics = benchmark_hybrid_handshake(iterations=2)
    assert len(metrics) == 1
    assert metrics[0].name == "Total Hybrid Handshake Latency"
    assert metrics[0].median_ms > 0


def test_benchmark_secure_messaging_execution():
    """Test secure messaging flow benchmark execution across sizes."""
    metrics = benchmark_secure_messaging(iterations=5)
    assert len(metrics) == 12  # 4 sizes * 3 operations (enc, transport, dec)
    for m in metrics:
        assert m.iterations == 5
        assert m.median_ns > 0


def test_benchmark_classical_vs_hybrid_comparison():
    """Test comparison between Classical Baseline and Hybrid PQC."""
    comp = benchmark_classical_vs_hybrid(iterations=2)
    assert "classical_baseline" in comp
    assert "hybrid_pqc" in comp
    assert "overhead_factors" in comp

    overhead = comp["overhead_factors"]
    assert overhead["data_overhead_multiplier"] > 1.0
    assert overhead["additional_data_bytes"] > 0
    assert overhead["latency_overhead_multiplier"] > 0


def test_measure_memory_footprint():
    """Test memory overhead profiling."""
    mem = measure_memory_footprint()
    assert isinstance(mem, dict)
    assert "raw_cryptographic_objects" in mem
    assert "handshake_execution_peak_memory_bytes" in mem
    assert mem["handshake_execution_peak_memory_bytes"] > 0


def test_full_benchmark_suite_json_and_csv_export():
    """Test complete benchmark suite execution and automated JSON and CSV export."""
    with tempfile.TemporaryDirectory() as tmpdir:
        report = run_full_benchmark_suite(
            output_dir=tmpdir,
            iterations_fast=5,
            iterations_heavy=2,
        )

        assert isinstance(report, BenchmarkSuiteReport)
        assert len(report.metrics) > 20
        assert len(report.sizes) == 11

        # Check JSON export
        json_file = Path(tmpdir) / "latest.json"
        assert json_file.exists()
        loaded_json = json.loads(json_file.read_text(encoding="utf-8"))
        assert "environment" in loaded_json
        assert "metrics" in loaded_json
        assert len(loaded_json["metrics"]) == len(report.metrics)

        # Check CSV export
        csv_file = Path(tmpdir) / "latest.csv"
        assert csv_file.exists()
        csv_content = csv_file.read_text(encoding="utf-8")
        assert "Category,Operation,Iterations,Median (us)" in csv_content

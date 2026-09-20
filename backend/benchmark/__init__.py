"""Performance Benchmarking Package for Avionics PQC Security Lab.

Provides micro-benchmarking, memory profiling, and comparative performance analysis
for hybrid post-quantum avionics communications.
"""

from __future__ import annotations

from .memory import measure_memory_footprint
from .performance import (
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
    measure_sizes,
    run_full_benchmark_suite,
    time_operation,
)

__all__ = [
    "BenchmarkMetric",
    "SizeMeasurement",
    "BenchmarkSuiteReport",
    "get_benchmark_environment",
    "time_operation",
    "benchmark_x25519",
    "benchmark_mlkem",
    "benchmark_ed25519",
    "benchmark_slhdsa",
    "benchmark_hkdf",
    "benchmark_aes_gcm",
    "measure_sizes",
    "benchmark_hybrid_handshake",
    "benchmark_secure_messaging",
    "benchmark_classical_vs_hybrid",
    "run_full_benchmark_suite",
    "measure_memory_footprint",
]

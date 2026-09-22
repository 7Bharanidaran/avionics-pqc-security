"""Master Experimental Evaluation and AI Dataset Generation Runner.

Executes comprehensive performance benchmarking across all 4 adaptive cryptographic constructions,
runs the full 40-scenario security attack matrix, performs criticality-threat policy sweeps,
generates a leakage-free AI threat prediction dataset, and exports structured JSON/CSV data to data/adaptive/.

Usage:
    python -m backend.experiments.adaptive_benchmark
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
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from backend.avionics.fcc import FlightControlComputer
from backend.avionics.ground_station import GroundControlStation
from backend.avionics.messages import AvionicsMessage, MessageType
from backend.crypto import (
    ADAPTIVE_CRITICAL,
    ADAPTIVE_HIGH_ASSURANCE,
    ADAPTIVE_BALANCED,
    ADAPTIVE_STANDARD,
    CONSTRUCTION_ENGINE,
    BaseAdaptiveConstruction,
)
from backend.experiments.security_evaluator import (
    ConstructionAttackResult,
    evaluate_construction_against_attacks,
    run_full_security_matrix,
)
from backend.experiments.threat_scenarios import (
    ThreatDatasetRecord,
    generate_threat_dataset,
)


@dataclass(frozen=True)
class LatencyStatistics:
    """Detailed statistical distribution of an operation across multiple iterations."""

    min_ms: float
    max_ms: float
    mean_ms: float
    median_ms: float
    stddev_ms: float
    p95_ms: float
    p99_ms: float

    def to_dict(self) -> dict[str, float]:
        return {
            "min_ms": self.min_ms,
            "max_ms": self.max_ms,
            "mean_ms": self.mean_ms,
            "median_ms": self.median_ms,
            "stddev_ms": self.stddev_ms,
            "p95_ms": self.p95_ms,
            "p99_ms": self.p99_ms,
        }


def _compute_stats(samples_ns: list[int]) -> LatencyStatistics:
    """Compute statistical distribution from raw nanosecond timing measurements."""
    if not samples_ns:
        return LatencyStatistics(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

    samples_ms = [ns / 1_000_000.0 for ns in samples_ns]
    sorted_ms = sorted(samples_ms)
    n = len(sorted_ms)

    min_val = round(sorted_ms[0], 4)
    max_val = round(sorted_ms[-1], 4)
    mean_val = round(statistics.mean(sorted_ms), 4)
    median_val = round(statistics.median(sorted_ms), 4)
    stddev_val = round(statistics.stdev(sorted_ms) if n > 1 else 0.0, 4)

    p95_idx = min(int(math.ceil(0.95 * n)) - 1, n - 1)
    p99_idx = min(int(math.ceil(0.99 * n)) - 1, n - 1)
    p95_val = round(sorted_ms[p95_idx], 4)
    p99_val = round(sorted_ms[p99_idx], 4)

    return LatencyStatistics(
        min_ms=min_val,
        max_ms=max_val,
        mean_ms=mean_val,
        median_ms=median_val,
        stddev_ms=stddev_val,
        p95_ms=p95_val,
        p99_ms=p99_val,
    )


@dataclass(frozen=True)
class ConstructionBenchmarkResult:
    """Complete experimental benchmark profile for an adaptive construction."""

    construction_id: str
    security_level: str
    iterations: int
    handshake_latency: LatencyStatistics
    encryption_latency: LatencyStatistics
    decryption_latency: LatencyStatistics
    total_roundtrip_latency: LatencyStatistics
    ciphertext_size_bytes: int
    nonce_size_bytes: int
    aad_size_bytes: int
    total_packet_overhead_bytes: int
    kex_algorithms: list[str]
    auth_algorithms: list[str]
    kdf_algorithm: str
    aead_algorithm: str
    success_rate_percent: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "construction_id": self.construction_id,
            "security_level": self.security_level,
            "iterations": self.iterations,
            "handshake_latency_ms": self.handshake_latency.to_dict(),
            "encryption_latency_ms": self.encryption_latency.to_dict(),
            "decryption_latency_ms": self.decryption_latency.to_dict(),
            "total_roundtrip_latency_ms": self.total_roundtrip_latency.to_dict(),
            "sizes_and_overhead": {
                "ciphertext_size_bytes": self.ciphertext_size_bytes,
                "nonce_size_bytes": self.nonce_size_bytes,
                "aad_size_bytes": self.aad_size_bytes,
                "total_packet_overhead_bytes": self.total_packet_overhead_bytes,
            },
            "primitives": {
                "key_agreement": self.kex_algorithms,
                "authentication": self.auth_algorithms,
                "kdf": self.kdf_algorithm,
                "aead": self.aead_algorithm,
            },
            "success_rate_percent": self.success_rate_percent,
        }


def benchmark_construction(
    construction: BaseAdaptiveConstruction,
    iterations: int = 30,
) -> ConstructionBenchmarkResult:
    """Benchmark a single adaptive construction across repeated real execution trials."""
    cid = construction.metadata.construction_id
    fcc = FlightControlComputer(component_id="AIRCRAFT-001-FCC", aircraft_id="AIRCRAFT-001")
    gcs = GroundControlStation(component_id="GROUND-STATION-001")

    handshake_times_ns: list[int] = []
    encryption_times_ns: list[int] = []
    decryption_times_ns: list[int] = []
    roundtrip_times_ns: list[int] = []
    successful_runs = 0

    last_envelope = None

    test_msg = AvionicsMessage(
        sender_id=fcc.component_id,
        receiver_id=gcs.component_id,
        message_type=MessageType.AIRCRAFT_STATUS,
        payload={
            "altitude_ft": 32000,
            "heading_deg": 180.0,
            "speed_kts": 450.0,
            "nav_mode": "AUTONOMOUS",
            "timestamp": time.time(),
        },
    )

    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        s_session, r_session = construction.establish_session(fcc, gcs)
        t_hs = time.perf_counter_ns() - t0
        handshake_times_ns.append(t_hs)

        t1 = time.perf_counter_ns()
        envelope = s_session.encrypt_message(test_msg)
        t_enc = time.perf_counter_ns() - t1
        encryption_times_ns.append(t_enc)

        t2 = time.perf_counter_ns()
        decrypted = r_session.decrypt_message(envelope)
        t_dec = time.perf_counter_ns() - t2
        decryption_times_ns.append(t_dec)

        roundtrip_times_ns.append(t_hs + t_enc + t_dec)

        if decrypted.message_id == test_msg.message_id:
            successful_runs += 1
        last_envelope = envelope

    hs_stats = _compute_stats(handshake_times_ns)
    enc_stats = _compute_stats(encryption_times_ns)
    dec_stats = _compute_stats(decryption_times_ns)
    rt_stats = _compute_stats(roundtrip_times_ns)

    c_size = len(last_envelope.ciphertext) if last_envelope else 0
    n_size = len(last_envelope.nonce) if last_envelope else 12
    aad_size = len(last_envelope.associated_data) if (last_envelope and last_envelope.associated_data) else 0
    overhead = last_envelope.size_bytes() if last_envelope else 0

    auth_algos = [construction.metadata.auth_classical]
    if construction.metadata.auth_pqc:
        auth_algos.append(construction.metadata.auth_pqc)

    return ConstructionBenchmarkResult(
        construction_id=cid,
        security_level=construction.metadata.security_level.value,
        iterations=iterations,
        handshake_latency=hs_stats,
        encryption_latency=enc_stats,
        decryption_latency=dec_stats,
        total_roundtrip_latency=rt_stats,
        ciphertext_size_bytes=c_size,
        nonce_size_bytes=n_size,
        aad_size_bytes=aad_size,
        total_packet_overhead_bytes=overhead,
        kex_algorithms=[construction.metadata.kex_classical, construction.metadata.kex_pqc],
        auth_algorithms=auth_algos,
        kdf_algorithm=construction.metadata.kdf_algorithm,
        aead_algorithm=construction.metadata.aead,
        success_rate_percent=round((successful_runs / iterations) * 100.0, 2),
    )


def run_criticality_sweep() -> list[dict[str, Any]]:
    """Evaluate construction selection across all combinations of criticality and threat levels."""
    criticalities = ["ROUTINE", "IMPORTANT", "CRITICAL", "SAFETY_CRITICAL"]
    threat_levels = ["NORMAL", "ELEVATED", "HIGH", "CRITICAL"]
    results: list[dict[str, Any]] = []

    for crit in criticalities:
        for threat in threat_levels:
            decision = CONSTRUCTION_ENGINE.select_construction(
                criticality=crit,
                threat_level=threat,
                latency_budget_ms=5000.0,
            )
            results.append({
                "criticality": crit,
                "threat_level": threat,
                "selected_construction_id": decision.selected_construction_id,
                "security_level": decision.security_level,
                "status": decision.status,
                "estimated_latency_ms": decision.estimated_latency_ms,
                "downgrade_blocked": decision.downgrade_blocked,
                "reason": decision.reason,
            })
    return results


def export_experiment_artifacts(
    benchmark_results: list[ConstructionBenchmarkResult],
    security_results: list[ConstructionAttackResult],
    ai_dataset: list[ThreatDatasetRecord],
    criticality_sweep: list[dict[str, Any]],
    output_dir: str = "data/adaptive",
) -> dict[str, str]:
    """Save all experimental results, security attack data, and AI dataset to data/adaptive/."""
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    exported_files: dict[str, str] = {}

    timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    # 1. Benchmark Results (JSON & CSV)
    bench_json_path = out_path / "adaptive_construction_benchmarks.json"
    bench_data = {
        "timestamp": timestamp_str,
        "environment": {
            "platform": platform.platform(),
            "python_version": sys.version.split()[0],
            "processor": platform.processor() or "x86_64",
        },
        "constructions": [b.to_dict() for b in benchmark_results],
        "criticality_policy_sweep": criticality_sweep,
    }
    with open(bench_json_path, "w", encoding="utf-8") as f:
        json.dump(bench_data, f, indent=2)
    exported_files["benchmarks_json"] = str(bench_json_path)

    bench_csv_path = out_path / "adaptive_construction_benchmarks.csv"
    with open(bench_csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "construction_id",
            "security_level",
            "iterations",
            "handshake_min_ms",
            "handshake_mean_ms",
            "handshake_median_ms",
            "handshake_p95_ms",
            "handshake_p99_ms",
            "encryption_median_ms",
            "decryption_median_ms",
            "total_roundtrip_median_ms",
            "ciphertext_bytes",
            "overhead_bytes",
            "success_rate_pct",
        ])
        for b in benchmark_results:
            writer.writerow([
                b.construction_id,
                b.security_level,
                b.iterations,
                b.handshake_latency.min_ms,
                b.handshake_latency.mean_ms,
                b.handshake_latency.median_ms,
                b.handshake_latency.p95_ms,
                b.handshake_latency.p99_ms,
                b.encryption_latency.median_ms,
                b.decryption_latency.median_ms,
                b.total_roundtrip_latency.median_ms,
                b.ciphertext_size_bytes,
                b.total_packet_overhead_bytes,
                b.success_rate_percent,
            ])
    exported_files["benchmarks_csv"] = str(bench_csv_path)

    # 2. Security Attack Evaluation (JSON & CSV)
    sec_json_path = out_path / "security_evaluation.json"
    sec_data = {
        "timestamp": timestamp_str,
        "total_scenarios_evaluated": len(security_results),
        "total_detected": sum(1 for r in security_results if r.detected),
        "results": [r.to_dict() for r in security_results],
    }
    with open(sec_json_path, "w", encoding="utf-8") as f:
        json.dump(sec_data, f, indent=2)
    exported_files["security_json"] = str(sec_json_path)

    sec_csv_path = out_path / "security_evaluation.csv"
    with open(sec_csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "construction_id",
            "attack_id",
            "attack_name",
            "target",
            "detected",
            "accepted",
            "detection_mechanism",
            "security_control",
            "exception_type",
            "execution_time_ms",
        ])
        for r in security_results:
            writer.writerow([
                r.construction_id,
                r.attack_id,
                r.attack_name,
                r.target,
                r.detected,
                r.accepted,
                r.detection_mechanism,
                r.security_control,
                r.exception_type or "None",
                round(r.execution_time_ms, 4),
            ])
    exported_files["security_csv"] = str(sec_csv_path)

    # 3. AI Training Dataset (JSON & CSV)
    ai_json_path = out_path / "ai_training_dataset.json"
    ai_data = {
        "timestamp": timestamp_str,
        "dataset_name": "Avionics PQC Threat Prediction Dataset",
        "dataset_version": "1.0",
        "total_samples": len(ai_dataset),
        "feature_count": 14,
        "target_count": 5,
        "samples": [rec.to_dict() for rec in ai_dataset],
    }
    with open(ai_json_path, "w", encoding="utf-8") as f:
        json.dump(ai_data, f, indent=2)
    exported_files["ai_dataset_json"] = str(ai_json_path)

    ai_csv_path = out_path / "ai_training_dataset.csv"
    if ai_dataset:
        with open(ai_csv_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(asdict(ai_dataset[0]).keys()))
            writer.writeheader()
            for rec in ai_dataset:
                writer.writerow(asdict(rec))
    exported_files["ai_dataset_csv"] = str(ai_csv_path)

    # 4. Experiment Metadata
    meta_path = out_path / "experiment_metadata.json"
    threat_distribution = {}
    for rec in ai_dataset:
        threat_distribution[rec.threat_level] = threat_distribution.get(rec.threat_level, 0) + 1

    metadata = {
        "timestamp": timestamp_str,
        "framework": "Avionics PQC Security Lab (Phase 10B)",
        "reproducibility_command": "python -m backend.experiments.adaptive_benchmark",
        "benchmark_iterations_per_construction": benchmark_results[0].iterations if benchmark_results else 0,
        "total_security_attacks_evaluated": len(security_results),
        "ai_dataset_size": len(ai_dataset),
        "ai_threat_distribution": threat_distribution,
        "exported_files": {k: str(Path(v).name) for k, v in exported_files.items()},
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    exported_files["metadata_json"] = str(meta_path)

    return exported_files


def run_all_experiments(iterations: int = 30) -> dict[str, Any]:
    """Execute complete experimental pipeline across all 4 constructions."""
    print("=" * 78)
    print("  PHASE 10B: ADAPTIVE CONSTRUCTION COMPARATIVE EVALUATION & AI DATASET")
    print("=" * 78)

    constructions = [
        ADAPTIVE_STANDARD,
        ADAPTIVE_BALANCED,
        ADAPTIVE_HIGH_ASSURANCE,
        ADAPTIVE_CRITICAL,
    ]

    # Step 1: Performance Benchmarking
    print(f"\n[1/4] Running performance benchmarks ({iterations} trials per construction)...")
    benchmarks: list[ConstructionBenchmarkResult] = []
    for c in constructions:
        print(f"  -> Benchmarking {c.metadata.construction_id} ({c.metadata.security_level.value})...")
        res = benchmark_construction(c, iterations=iterations)
        benchmarks.append(res)

    # Step 2: Security Attack Suite Execution
    print("\n[2/4] Executing 40-scenario security attack matrix (4 constructions × 10 attacks)...")
    sec_results = run_full_security_matrix()
    detected_count = sum(1 for r in sec_results if r.detected and r.attack_id != "ATK-00")
    total_attacks = sum(1 for r in sec_results if r.attack_id != "ATK-00")
    print(f"  -> Security validation: {detected_count}/{total_attacks} attack attempts detected and rejected.")

    # Step 3: Criticality & Policy Sweep
    print("\n[3/4] Performing Criticality × Threat Level deterministic policy sweep...")
    crit_sweep = run_criticality_sweep()

    # Step 4: AI Threat Prediction Dataset Generation
    print("\n[4/4] Generating leakage-free AI threat prediction training dataset...")
    ai_dataset = generate_threat_dataset(num_samples_per_category=60, seed=42)
    print(f"  -> Generated {len(ai_dataset)} structured samples across 10 operational threat scenarios.")

    # Step 5: Exporting Files
    print("\n[Export] Saving structured benchmarks, attack evaluation, and AI dataset to data/adaptive/...")
    exported = export_experiment_artifacts(
        benchmark_results=benchmarks,
        security_results=sec_results,
        ai_dataset=ai_dataset,
        criticality_sweep=crit_sweep,
    )

    # Print Summary Tables
    print("\n" + "=" * 78)
    print("  EXPERIMENTAL BENCHMARK SUMMARY")
    print("=" * 78)
    print(f"{'Construction':<28} | {'Handshake (Median)':<18} | {'Enc/Dec':<14} | {'Overhead':<10}")
    print("-" * 78)
    for b in benchmarks:
        hs_str = f"{b.handshake_latency.median_ms:.3f} ms"
        enc_dec_str = f"{b.encryption_latency.median_ms:.3f}/{b.decryption_latency.median_ms:.3f} ms"
        ovh_str = f"{b.total_packet_overhead_bytes} B"
        print(f"{b.construction_id:<28} | {hs_str:<18} | {enc_dec_str:<14} | {ovh_str:<10}")

    print("-" * 78)
    print(f"AI Dataset exported: {len(ai_dataset)} samples -> data/adaptive/ai_training_dataset.csv")
    print("=" * 78 + "\n")

    return {
        "benchmarks": [b.to_dict() for b in benchmarks],
        "security_results": [r.to_dict() for r in sec_results],
        "ai_dataset_size": len(ai_dataset),
        "exported_files": exported,
    }


if __name__ == "__main__":
    run_all_experiments(iterations=30)

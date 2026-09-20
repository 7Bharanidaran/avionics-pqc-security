"""Benchmark results API routes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from fastapi import APIRouter, HTTPException

from backend.api.schemas import BenchmarkSummaryResponse

router = APIRouter(prefix="/benchmarks", tags=["Benchmarks"])

# Benchmark data path relative to project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
BENCHMARK_FILE = PROJECT_ROOT / "data" / "benchmarks" / "latest.json"


def load_benchmark_data() -> dict[str, Any]:
    """Load latest benchmark results from JSON storage."""
    if not BENCHMARK_FILE.exists():
        raise HTTPException(
            status_code=404,
            detail="Benchmark data not found. Please run benchmarks suite first.",
        )
    try:
        with open(BENCHMARK_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to read benchmark results: {exc}",
        )


@router.get("/latest")
def get_latest_benchmarks() -> dict[str, Any]:
    """Retrieve raw latest benchmark execution dataset."""
    return load_benchmark_data()


@router.get("/summary", response_model=BenchmarkSummaryResponse)
def get_benchmark_summary() -> BenchmarkSummaryResponse:
    """Retrieve structured summary of cryptographic benchmarks for UI dashboards."""
    raw = load_benchmark_data()

    metrics = raw.get("metrics", [])
    sizes = raw.get("sizes", [])
    comparisons = raw.get("comparisons", {})
    environment = raw.get("environment", {})
    timestamp = raw.get("timestamp", "")

    # Group metrics for dashboard consumption
    crypto_ops = [
        m for m in metrics
        if m.get("category") in ("Key Exchange", "Key Encapsulation", "Digital Signature", "Digital Signature (PQC)", "Key Derivation")
    ]

    handshake_metric = next(
        (m for m in metrics if m.get("name") == "Total Hybrid Handshake Latency"),
        {},
    )

    symmetric_ops = [
        m for m in metrics
        if m.get("category") in ("Symmetric Encryption", "Message Flow")
    ]

    return BenchmarkSummaryResponse(
        timestamp=timestamp,
        environment=environment,
        cryptographic_operations=crypto_ops,
        handshake_latency=handshake_metric,
        symmetric_encryption=symmetric_ops,
        size_measurements=sizes,
        classical_vs_hybrid=comparisons,
    )

"""Read measured Phase 6 data without invoking or changing benchmark execution."""
from __future__ import annotations

import json
from pathlib import Path


class BenchmarkDataError(RuntimeError):
    pass


class BenchmarkProvider:
    def __init__(self, benchmark_file: Path | None = None) -> None:
        root = Path(__file__).resolve().parent.parent.parent
        self.benchmark_file = benchmark_file or root / "data" / "benchmarks" / "latest.json"

    def handshake_latency_ms(self) -> float:
        try:
            document = json.loads(self.benchmark_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise BenchmarkDataError(f"Measured benchmark data is unavailable: {exc}") from exc
        metric = next((item for item in document.get("metrics", []) if item.get("name") == "Total Hybrid Handshake Latency"), None)
        if not metric or not isinstance(metric.get("median_ms"), (int, float)) or metric["median_ms"] <= 0:
            raise BenchmarkDataError("Measured Total Hybrid Handshake Latency is unavailable.")
        return float(metric["median_ms"])

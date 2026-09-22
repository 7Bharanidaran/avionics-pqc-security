"""Unit and integration tests for Phase 10B Adaptive Evaluation and AI Dataset Generation."""

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.api.app import app
from backend.crypto import (
    ADAPTIVE_CRITICAL,
    ADAPTIVE_HIGH_ASSURANCE,
    ADAPTIVE_BALANCED,
    ADAPTIVE_STANDARD,
)
from backend.experiments.adaptive_benchmark import (
    benchmark_construction,
    export_experiment_artifacts,
    run_criticality_sweep,
)
from backend.experiments.security_evaluator import (
    evaluate_construction_against_attacks,
    run_full_security_matrix,
)
from backend.experiments.threat_scenarios import (
    ThreatDatasetRecord,
    generate_threat_dataset,
)

client = TestClient(app)


class TestAdaptiveExperiments:
    """Test suite for adaptive construction benchmarking, attack matrix, and dataset generation."""

    def test_benchmark_all_four_constructions(self):
        """Verify performance benchmarking executes and produces valid statistical metrics for all 4 constructions."""
        constructions = [
            ADAPTIVE_STANDARD,
            ADAPTIVE_BALANCED,
            ADAPTIVE_HIGH_ASSURANCE,
            ADAPTIVE_CRITICAL,
        ]

        for c in constructions:
            res = benchmark_construction(c, iterations=2)
            assert res.construction_id == c.metadata.construction_id
            assert res.iterations == 2
            assert res.success_rate_percent == 100.0
            assert res.handshake_latency.mean_ms > 0.0
            assert res.encryption_latency.mean_ms > 0.0
            assert res.decryption_latency.mean_ms > 0.0
            assert res.ciphertext_size_bytes > 0
            assert res.total_packet_overhead_bytes > 0

    def test_security_attack_evaluation_matrix(self):
        """Verify the 40-scenario security attack matrix executes properly and detects attacks."""
        matrix = run_full_security_matrix()
        assert len(matrix) == 40  # 4 constructions * 10 attack vectors

        # Verify all attacks (excluding baseline ATK-00) are detected and fail closed
        baseline_results = [r for r in matrix if r.attack_id == "ATK-00"]
        attack_results = [r for r in matrix if r.attack_id != "ATK-00"]

        assert len(baseline_results) == 4
        assert all(r.accepted is True for r in baseline_results)
        assert all(r.detected is False for r in baseline_results)

        assert len(attack_results) == 36
        assert all(r.detected is True for r in attack_results)
        assert all(r.accepted is False for r in attack_results)

    def test_criticality_policy_sweep(self):
        """Verify criticality × threat level sweep covers all 16 policy combinations."""
        sweep = run_criticality_sweep()
        assert len(sweep) == 16
        for item in sweep:
            assert item["selected_construction_id"] in [
                "ADAPTIVE-STANDARD-V1",
                "ADAPTIVE-BALANCED-V1",
                "ADAPTIVE-HIGH-ASSURANCE-V1",
                "ADAPTIVE-CRITICAL-V1",
            ]

    def test_threat_dataset_generation_and_leakage_prevention(self):
        """Verify AI training dataset schema, balance, and feature isolation (no data leakage)."""
        dataset = generate_threat_dataset(num_samples_per_category=10, seed=123)
        assert len(dataset) == 100  # 10 categories * 10 samples

        # Check distribution
        threat_levels = set(d.threat_level for d in dataset)
        assert threat_levels == {"NORMAL", "ELEVATED", "HIGH", "CRITICAL"}

        # Verify feature schema
        for rec in dataset:
            features = rec.to_input_features_dict()
            targets = rec.to_target_dict()

            # Input features must NOT contain target labels or post-decision execution results
            assert "threat_level" not in features
            assert "threat_score" not in features
            assert "recommended_min_assurance" not in features
            assert "selected_construction" not in features
            assert "handshake_time_ms" not in features

            # Target labels must contain ground truth
            assert "threat_level" in targets
            assert "threat_score" in targets
            assert targets["threat_score"] >= 0.0

    def test_no_secret_material_in_exports(self, tmp_path):
        """Security Invariant: Verify that exported files never contain private keys, secret keys, or raw keys."""
        bench = [benchmark_construction(ADAPTIVE_STANDARD, iterations=1)]
        sec = evaluate_construction_against_attacks(ADAPTIVE_STANDARD)
        ai_data = generate_threat_dataset(num_samples_per_category=2, seed=42)
        crit_sweep = run_criticality_sweep()

        exported = export_experiment_artifacts(
            benchmark_results=bench,
            security_results=sec,
            ai_dataset=ai_data,
            criticality_sweep=crit_sweep,
            output_dir=str(tmp_path),
        )

        for file_key, file_path_str in exported.items():
            content = Path(file_path_str).read_text(encoding="utf-8")
            assert "private_key" not in content.lower()
            assert "secret_key" not in content.lower()
            assert "raw_session_key" not in content.lower()
            assert "plaintext_secret" not in content.lower()

    def test_api_adaptive_experiments_endpoints(self):
        """Verify API endpoints for adaptive experiments."""
        # 1. GET /api/experiments/adaptive/summary
        resp_sum = client.get("/api/experiments/adaptive/summary")
        assert resp_sum.status_code == 200
        data_sum = resp_sum.json()
        assert data_sum["status"] in ["SUCCESS", "INITIALIZING"]
        assert len(data_sum["constructions"]) == 4

        # 2. GET /api/experiments/adaptive/latest
        resp_latest = client.get("/api/experiments/adaptive/latest")
        assert resp_latest.status_code == 200
        data_latest = resp_latest.json()
        assert data_latest["status"] in ["SUCCESS", "INITIALIZING"]

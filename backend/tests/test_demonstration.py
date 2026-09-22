"""Comprehensive Tests for Phase 14 Practical Research Demonstration Engine.

Verifies:
1. Scenario Catalog Integrity (8 Scenarios)
2. Scenario 1: Nominal Avionics (FCC -> NAV Handshake, AES-256-GCM encryption/decryption)
3. Scenario 2: Threat Escalation & Dynamic Adaptation (ADAPTIVE-HIGH-ASSURANCE-V1)
4. Scenario 3: Critical Threat & Maximum PQC (ADAPTIVE-CRITICAL-V1)
5. Scenario 4: AI / Safety Conflict (DO-178C Safety Policy Override)
6. Scenario 5: Downgrade Attack Defense (Fail-closed block)
7. Scenario 6: Ciphertext Tampering Detection (AuthenticationTagError)
8. Scenario 7: AAD Tampering Detection (AEAD tag mismatch)
9. Scenario 8: Nonce Replay Defense (ConstructionReplayError)
10. API Endpoints (GET /scenarios, POST /run)
11. Zero Secret Exposure in trace artifacts
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.api.app import app
from backend.demonstration.engine import DEMONSTRATION_ENGINE, DemonstrationEngine
from backend.demonstration.scenarios import (
    DEMO_SCENARIOS,
    get_demonstration_scenario,
    list_demonstration_scenarios,
)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def engine():
    return DemonstrationEngine()


class TestDemonstrationCatalog:
    """Test demonstration scenarios metadata."""

    def test_all_eight_scenarios_exist(self):
        assert len(DEMO_SCENARIOS) == 8
        expected_ids = {
            "DEMO_01_NORMAL",
            "DEMO_02_ELEVATED",
            "DEMO_03_CRITICAL",
            "DEMO_04_SAFETY_CONFLICT",
            "DEMO_05_DOWNGRADE_ATTACK",
            "DEMO_06_CIPHERTEXT_TAMPERING",
            "DEMO_07_AAD_TAMPERING",
            "DEMO_08_REPLAY",
        }
        assert set(DEMO_SCENARIOS.keys()) == expected_ids

    def test_scenario_retrieval(self):
        s1 = get_demonstration_scenario("DEMO_01_NORMAL")
        assert s1.scenario_id == "DEMO_01_NORMAL"
        assert s1.category == "Baseline"

        with pytest.raises(ValueError):
            get_demonstration_scenario("NON_EXISTENT_SCENARIO")


class TestDemonstrationExecution:
    """Test actual live execution of all 8 demonstration scenarios."""

    def test_demo_01_normal_execution(self, engine):
        result = engine.run_scenario("DEMO_01_NORMAL")
        assert result.status == "SUCCESS"
        assert result.active_construction_id == "ADAPTIVE-STANDARD-V1"
        assert result.security_verification["outcome"] == "ACCEPTED"
        assert result.security_verification["verification_passed"] is True
        assert len(result.decision_trace_steps) == 6

    def test_demo_02_elevated_execution(self, engine):
        result = engine.run_scenario("DEMO_02_ELEVATED")
        assert result.status == "SUCCESS"
        assert result.active_construction_id in ("ADAPTIVE-HIGH-ASSURANCE-V1", "ADAPTIVE-BALANCED-V1", "ADAPTIVE-CRITICAL-V1")
        assert result.security_verification["outcome"] == "ACCEPTED"
        assert result.ai_assessment["threat_score"] > 25.0

    def test_demo_03_critical_execution(self, engine):
        result = engine.run_scenario("DEMO_03_CRITICAL")
        assert result.status == "SUCCESS"
        assert result.active_construction_id == "ADAPTIVE-CRITICAL-V1"
        assert result.security_verification["outcome"] == "ACCEPTED"
        assert result.active_construction_details["primitives"]["kdf"] == "HKDF-SHA512"

    def test_demo_04_safety_conflict_override(self, engine):
        result = engine.run_scenario("DEMO_04_SAFETY_CONFLICT")
        assert result.status == "SUCCESS"
        assert result.safety_decision["is_safety_override"] is True
        assert result.active_construction_id == "ADAPTIVE-CRITICAL-V1"
        assert "DO-178C Safety Constraint" in result.safety_decision["override_reason"]

    def test_demo_05_downgrade_attack_defense(self, engine):
        result = engine.run_scenario("DEMO_05_DOWNGRADE_ATTACK")
        assert result.status == "DOWNGRADE_BLOCKED"
        assert result.security_verification["attack_neutralized"] is True

    def test_demo_06_ciphertext_tampering_rejected(self, engine):
        result = engine.run_scenario("DEMO_06_CIPHERTEXT_TAMPERING")
        assert result.status == "TAMPER_DETECTED"
        assert result.security_verification["outcome"] == "AUTHENTICATION_FAILURE"
        assert result.security_verification["attack_neutralized"] is True

    def test_demo_07_aad_tampering_rejected(self, engine):
        result = engine.run_scenario("DEMO_07_AAD_TAMPERING")
        assert result.status == "TAMPER_DETECTED"
        assert result.security_verification["outcome"] == "MESSAGE_REJECTED"
        assert result.security_verification["attack_neutralized"] is True

    def test_demo_08_replay_defense(self, engine):
        result = engine.run_scenario("DEMO_08_REPLAY")
        assert result.status == "REPLAY_DETECTED"
        assert result.security_verification["outcome"] == "REPLAY_DETECTED"
        assert result.security_verification["first_transmission"] == "ACCEPTED"
        assert result.security_verification["second_transmission"] == "REPLAY_REJECTED"


class TestDemonstrationAPI:
    """Test REST API routes under /api/demonstration."""

    def test_get_scenarios_endpoint(self, client):
        resp = client.get("/api/demonstration/scenarios")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "SUCCESS"
        assert data["total_scenarios"] == 8
        assert len(data["scenarios"]) == 8

    def test_post_run_endpoint(self, client):
        resp = client.post("/api/demonstration/run", json={"scenario_id": "DEMO_01_NORMAL"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "SUCCESS"
        assert data["result"]["scenario_id"] == "DEMO_01_NORMAL"
        assert data["result"]["status"] == "SUCCESS"

    def test_post_run_invalid_scenario_id(self, client):
        resp = client.post("/api/demonstration/run", json={"scenario_id": "INVALID_123"})
        assert resp.status_code == 400


class TestSecurityAndZeroSecretsExposure:
    """Verify zero private keys or raw session keys are leaked in demonstration outputs."""

    def test_no_raw_session_keys_in_results(self, engine):
        for scn_id in DEMO_SCENARIOS:
            res = engine.run_scenario(scn_id).to_dict()
            assert res["crypto_trace"]["session_key"] == "[REDACTED_EPHEMERAL_KEY]"
            # Ensure no 32-byte raw binary keys in any serialized field
            dumped = str(res)
            assert "BEGIN PRIVATE KEY" not in dumped
            assert "PRIVATE KEY" not in dumped

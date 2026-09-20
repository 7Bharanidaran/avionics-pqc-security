"""Integration and unit tests for FastAPI REST API endpoints."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.api.app import app

client = TestClient(app)


# =====================================================================
# Root and Health Check Tests
# =====================================================================


def test_root_endpoint():
    """Verify root endpoint responds with metadata and docs links."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "Avionics PQC Security Lab API"
    assert data["version"] == "1.0.0"
    assert data["docs"] == "/docs"
    assert data["health"] == "/api/health"


def test_health_check():
    """Verify /api/health endpoint returns healthy status."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "Avionics PQC Security Lab"
    assert data["api_version"] == "1.0"


def test_openapi_json():
    """Verify OpenAPI JSON specification is generated properly."""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    data = response.json()
    assert "paths" in data
    assert "/api/health" in data["paths"]
    assert "/api/avionics" in data["paths"]
    assert "/api/protocol/handshake" in data["paths"]
    assert "/api/protocol/message" in data["paths"]
    assert "/api/security/attacks" in data["paths"]
    assert "/api/benchmarks/summary" in data["paths"]


# =====================================================================
# Avionics Endpoints Tests
# =====================================================================


def test_list_avionics_entities():
    """Verify listing all avionics entities returns FCC, NAV, and GCS."""
    response = client.get("/api/avionics")
    assert response.status_code == 200
    data = response.json()
    assert "entities" in data
    assert len(data["entities"]) == 3

    ids = {e["id"] for e in data["entities"]}
    assert "AIRCRAFT-001-FCC" in ids
    assert "AIRCRAFT-001-NAV" in ids
    assert "GROUND-STATION-001" in ids

    # Ensure no secret keys are leaked
    for entity in data["entities"]:
        assert "private_key" not in entity
        assert "secret_key" not in entity
        assert "public_keys" in entity
        assert "ed25519" in entity["public_keys"]
        assert "slhdsa" in entity["public_keys"]


def test_get_fcc_entity():
    """Verify /api/avionics/fcc returns FCC metadata."""
    response = client.get("/api/avionics/fcc")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "AIRCRAFT-001-FCC"
    assert data["component_type"] == "FLIGHT_CONTROL_COMPUTER"
    assert data["aircraft_id"] == "AIRCRAFT-001"
    assert data["status"] == "ACTIVE"


def test_get_nav_entity():
    """Verify /api/avionics/nav returns NAV metadata."""
    response = client.get("/api/avionics/nav")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "AIRCRAFT-001-NAV"
    assert data["component_type"] == "NAVIGATION_COMPUTER"
    assert data["aircraft_id"] == "AIRCRAFT-001"


def test_get_gcs_entity():
    """Verify /api/avionics/gcs returns GCS metadata."""
    response = client.get("/api/avionics/gcs")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "GROUND-STATION-001"
    assert data["component_type"] == "GROUND_CONTROL_STATION"
    assert data["aircraft_id"] is None


def test_get_entity_by_id_and_alias():
    """Verify resolving entities by full ID and aliases."""
    # Full ID
    res1 = client.get("/api/avionics/AIRCRAFT-001-FCC")
    assert res1.status_code == 200
    assert res1.json()["id"] == "AIRCRAFT-001-FCC"

    # Alias
    res2 = client.get("/api/avionics/nav")
    assert res2.status_code == 200
    assert res2.json()["id"] == "AIRCRAFT-001-NAV"

    # Non-existent ID -> 404
    res3 = client.get("/api/avionics/NON_EXISTENT_NODE")
    assert res3.status_code == 404
    assert "not found" in res3.json()["detail"].lower()


# =====================================================================
# Protocol & Handshake Tests
# =====================================================================


def test_handshake_success():
    """Verify executing a hybrid secure handshake via API."""
    payload = {
        "initiator": "FCC",
        "responder": "NAV",
        "mlkem_param": "ML-KEM-1024",
        "slhdsa_param": "shake_128f",
    }
    response = client.post("/api/protocol/handshake", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "established"
    assert data["initiator"] == "AIRCRAFT-001-FCC"
    assert data["responder"] == "AIRCRAFT-001-NAV"
    assert len(data["session_id"]) == 64  # SHA-256 hex string
    assert "X25519" in data["key_exchange"]
    assert "ML-KEM-1024" in data["key_exchange"]
    assert "Ed25519" in data["authentication"]
    assert "SLH-DSA-SHAKE_128F" in data["authentication"]
    assert data["key_derivation"] == "HKDF-SHA256"
    assert data["encryption"] == "AES-256-GCM"
    assert data["established_at"] > 0


def test_handshake_invalid_initiator():
    """Verify handshake fails with 404 on unknown initiator."""
    payload = {
        "initiator": "UNKNOWN_NODE",
        "responder": "NAV",
    }
    response = client.post("/api/protocol/handshake", json=payload)
    assert response.status_code == 404
    assert "Initiator entity" in response.json()["detail"]


def test_handshake_invalid_responder():
    """Verify handshake fails with 404 on unknown responder."""
    payload = {
        "initiator": "FCC",
        "responder": "UNKNOWN_NODE",
    }
    response = client.post("/api/protocol/handshake", json=payload)
    assert response.status_code == 404
    assert "Responder entity" in response.json()["detail"]


def test_handshake_same_entity():
    """Verify handshake fails when initiator and responder are identical."""
    payload = {
        "initiator": "FCC",
        "responder": "AIRCRAFT-001-FCC",
    }
    response = client.post("/api/protocol/handshake", json=payload)
    assert response.status_code == 400
    assert "cannot be the same entity" in response.json()["detail"]


def test_send_secure_message_success():
    """Verify sending encrypted message from FCC to NAV."""
    msg_payload = {
        "sender": "FCC",
        "receiver": "NAV",
        "message_type": "ALTITUDE",
        "payload": {"altitude_ft": 35000},
    }
    response = client.post("/api/protocol/message", json=msg_payload)
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "accepted"
    assert data["sender"] == "AIRCRAFT-001-FCC"
    assert data["receiver"] == "AIRCRAFT-001-NAV"
    assert data["secure"] is True
    assert data["message_type"] == "ALTITUDE"
    assert data["payload"]["altitude_ft"] == 35000
    assert "ALTITUDE" in data["display_text"]


def test_send_secure_message_invalid_type():
    """Verify sending message with invalid message type returns 400."""
    msg_payload = {
        "sender": "FCC",
        "receiver": "NAV",
        "message_type": "INVALID_TYPE",
        "payload": {},
    }
    response = client.post("/api/protocol/message", json=msg_payload)
    assert response.status_code == 400
    assert "Invalid message_type" in response.json()["detail"]


def test_send_secure_message_unknown_sender():
    """Verify sending message with unknown sender returns 404."""
    msg_payload = {
        "sender": "UNKNOWN",
        "receiver": "NAV",
        "message_type": "ALTITUDE",
    }
    response = client.post("/api/protocol/message", json=msg_payload)
    assert response.status_code == 404


def test_send_secure_message_same_sender_receiver():
    """Verify sending message to oneself returns 400."""
    msg_payload = {
        "sender": "FCC",
        "receiver": "FCC",
        "message_type": "ALTITUDE",
    }
    response = client.post("/api/protocol/message", json=msg_payload)
    assert response.status_code == 400


# =====================================================================
# Security & Attack Simulation Tests
# =====================================================================


def test_get_all_attacks():
    """Verify /api/security/attacks executes all simulations and returns report."""
    response = client.get("/api/security/attacks")
    assert response.status_code == 200
    data = response.json()

    assert data["overall_status"] == "PASS"
    assert data["baseline_passed"] is True
    assert data["total_attacks"] == 9
    assert data["attacks_detected"] == 9
    assert data["attacks_not_detected"] == 0
    assert len(data["attacks"]) == 10  # 1 baseline + 9 attacks


def test_simulate_individual_attacks():
    """Verify /api/security/simulate triggers individual attacks correctly."""
    # 1. Ciphertext tampering
    r1 = client.post("/api/security/simulate", json={"attack": "ciphertext_tampering"})
    assert r1.status_code == 200
    d1 = r1.json()
    assert d1["attack_id"] == "ATK-01"
    assert d1["detected"] is True
    assert d1["status"] == "DETECTED"

    # 2. Replay attack
    r2 = client.post("/api/security/simulate", json={"attack": "replay"})
    assert r2.status_code == 200
    d2 = r2.json()
    assert d2["attack_id"] == "ATK-09"
    assert d2["detected"] is True

    # 3. Baseline
    r3 = client.post("/api/security/simulate", json={"attack": "baseline"})
    assert r3.status_code == 200
    d3 = r3.json()
    assert d3["attack_id"] == "ATK-00"
    assert d3["status"] == "DETECTED"

    # 4. Unknown attack -> 400
    r4 = client.post("/api/security/simulate", json={"attack": "unknown_attack"})
    assert r4.status_code == 400
    assert "Unknown attack identifier" in r4.json()["detail"]


# =====================================================================
# Benchmark Endpoints Tests
# =====================================================================


def test_get_latest_benchmarks():
    """Verify /api/benchmarks/latest returns raw benchmark dataset."""
    response = client.get("/api/benchmarks/latest")
    assert response.status_code == 200
    data = response.json()
    assert "timestamp" in data
    assert "environment" in data
    assert "metrics" in data
    assert "sizes" in data
    assert "comparisons" in data


def test_get_benchmark_summary():
    """Verify /api/benchmarks/summary returns formatted summary."""
    response = client.get("/api/benchmarks/summary")
    assert response.status_code == 200
    data = response.json()

    assert "timestamp" in data
    assert "environment" in data
    assert "cryptographic_operations" in data
    assert len(data["cryptographic_operations"]) > 0
    assert "handshake_latency" in data
    assert "symmetric_encryption" in data
    assert "size_measurements" in data
    assert "classical_vs_hybrid" in data

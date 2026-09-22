"""Integration tests for Adaptive Cryptographic Constructions API endpoints."""

import pytest
from fastapi.testclient import TestClient

from backend.api.app import app

client = TestClient(app)


def test_api_get_constructions():
    """Verify listing all 4 adaptive cryptographic constructions."""
    response = client.get("/api/crypto/constructions")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 4

    ids = [c["construction_id"] for c in data]
    assert "ADAPTIVE-STANDARD-V1" in ids
    assert "ADAPTIVE-BALANCED-V1" in ids
    assert "ADAPTIVE-HIGH-ASSURANCE-V1" in ids
    assert "ADAPTIVE-CRITICAL-V1" in ids

    # Check structure of standard
    std = next(c for c in data if c["construction_id"] == "ADAPTIVE-STANDARD-V1")
    assert std["security_level"] == "STANDARD"
    assert std["primitives"]["kdf"] == "HKDF-SHA256"
    assert std["primitives"]["key_agreement"] == ["X25519", "ML-KEM-768"]


def test_api_get_single_construction():
    """Verify fetching metadata for a specific construction."""
    response = client.get("/api/crypto/constructions/ADAPTIVE-HIGH-ASSURANCE-V1")
    assert response.status_code == 200
    data = response.json()
    assert data["construction_id"] == "ADAPTIVE-HIGH-ASSURANCE-V1"
    assert data["security_level"] == "HIGH_ASSURANCE"
    assert "SLH-DSA-SHAKE_128F" in data["primitives"]["authentication"]

    # 404 on invalid ID
    err_resp = client.get("/api/crypto/constructions/NONEXISTENT-V1")
    assert err_resp.status_code == 404


def test_api_select_construction():
    """Verify deterministic construction selection endpoint."""
    # Routine + Normal -> STANDARD
    resp1 = client.post(
        "/api/crypto/select",
        json={
            "criticality": "ROUTINE",
            "threat_level": "NORMAL",
            "threat_score": 10.0,
            "latency_budget_ms": 5000.0,
        },
    )
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert data1["status"] == "APPROVED"
    assert data1["selected_construction_id"] == "ADAPTIVE-STANDARD-V1"

    # Critical + High -> HIGH_ASSURANCE
    resp2 = client.post(
        "/api/crypto/select",
        json={
            "criticality": "CRITICAL",
            "threat_level": "HIGH",
            "threat_score": 60.0,
            "latency_budget_ms": 5000.0,
        },
    )
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["status"] == "APPROVED"
    assert data2["selected_construction_id"] == "ADAPTIVE-HIGH-ASSURANCE-V1"

    # Latency constraint conflict
    resp3 = client.post(
        "/api/crypto/select",
        json={
            "criticality": "SAFETY_CRITICAL",
            "threat_level": "CRITICAL",
            "threat_score": 95.0,
            "latency_budget_ms": 5.0,
        },
    )
    assert resp3.status_code == 200
    data3 = resp3.json()
    assert data3["status"] == "CONSTRAINT_CONFLICT"
    assert data3["selected_construction_id"] == "ADAPTIVE-CRITICAL-V1"
    assert data3["downgrade_blocked"] is True


def test_api_adaptive_handshake_and_messaging():
    """Verify executing adaptive handshake and transmitting encrypted messages."""
    # 1. Execute handshake
    handshake_resp = client.post(
        "/api/crypto/handshake",
        json={
            "initiator": "FCC",
            "responder": "GCS",
            "criticality": "IMPORTANT",
            "threat_level": "ELEVATED",
            "threat_score": 40.0,
            "latency_budget_ms": 5000.0,
        },
    )
    assert handshake_resp.status_code == 200
    h_data = handshake_resp.json()
    assert h_data["status"] == "SUCCESS"
    assert h_data["construction_id"] == "ADAPTIVE-BALANCED-V1"
    session_id = h_data["session_id"]
    assert len(session_id) > 0
    assert len(h_data["trace"]) > 0

    # 2. Send authenticated message over established session
    msg_resp = client.post(
        "/api/crypto/message",
        json={
            "sender": "FCC",
            "receiver": "GCS",
            "session_id": session_id,
            "construction_id": "ADAPTIVE-BALANCED-V1",
            "message_type": "AIRCRAFT_STATUS",
            "payload": {
                "altitude": 32000.0,
                "heading": 180.0,
                "speed": 450.0,
                "mode": "AUTOPILOT",
            },
        },
    )
    assert msg_resp.status_code == 200
    m_data = msg_resp.json()
    assert m_data["status"] == "SUCCESS"
    assert m_data["decrypted_payload"]["altitude"] == 32000.0
    assert m_data["decrypted_payload"]["mode"] == "AUTOPILOT"
    assert m_data["encryption_time_ms"] >= 0.0
    assert m_data["decryption_time_ms"] >= 0.0

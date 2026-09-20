# Avionics PQC Security Lab — REST API Specification (Phase 7)

## Overview

The **Avionics PQC Security Lab REST API** provides programmatic access to the simulated avionics network, hybrid post-quantum cryptographic handshake, secure authenticated message exchange, security attack simulation engine, and experimental benchmark datasets.

All endpoints are hosted via **FastAPI** with auto-generated OpenAPI 3.1 documentation, strict Pydantic v2 data validation, CORS middleware for frontend integrations, and comprehensive error handling.

---

## Server Execution

Start the local API development server with Uvicorn:

```bash
# From the repository root:
uvicorn backend.api.app:app --reload --host 127.0.0.1 --port 8000
```

- **Interactive Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc Interactive Documentation**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
- **OpenAPI JSON Schema**: [http://127.0.0.1:8000/openapi.json](http://127.0.0.1:8000/openapi.json)

---

## REST Endpoints Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | API root metadata and documentation pointers |
| `GET` | `/api/health` | Health check endpoint |
| `GET` | `/api/avionics` | List all simulated avionics entities & public keys |
| `GET` | `/api/avionics/fcc` | Get Flight Control Computer metadata & public keys |
| `GET` | `/api/avionics/nav` | Get Navigation Computer metadata & public keys |
| `GET` | `/api/avionics/gcs` | Get Ground Control Station metadata & public keys |
| `GET` | `/api/avionics/{component_id}` | Get specific entity metadata by ID or alias |
| `POST` | `/api/protocol/handshake` | Execute hybrid PQC handshake between nodes |
| `POST` | `/api/protocol/message` | Encrypt, transmit, and decrypt an avionics message |
| `GET` | `/api/security/attacks` | Run full security attack suite & return validation report |
| `POST` | `/api/security/simulate` | Execute an individual attack simulation by name |
| `GET` | `/api/benchmarks/latest` | Retrieve raw latest benchmark execution dataset |
| `GET` | `/api/benchmarks/summary` | Retrieve dashboard-ready cryptographic performance metrics |

---

## Endpoint Details & Examples

### 1. Health Check
`GET /api/health`

**Response (`200 OK`)**:
```json
{
  "status": "healthy",
  "service": "Avionics PQC Security Lab",
  "api_version": "1.0"
}
```

---

### 2. List Avionics Entities
`GET /api/avionics`

**Response (`200 OK`)**:
```json
{
  "entities": [
    {
      "id": "AIRCRAFT-001-FCC",
      "name": "Flight Control Computer (FCC)",
      "role": "Primary flight control and telemetry coordinator",
      "component_type": "FLIGHT_CONTROL_COMPUTER",
      "aircraft_id": "AIRCRAFT-001",
      "status": "ACTIVE",
      "public_keys": {
        "ed25519": "e7b0...",
        "slhdsa": "3a4f...",
        "slhdsa_param": "shake_128f"
      }
    },
    ...
  ]
}
```

> [!IMPORTANT]
> Long-term public identity keys are exposed in standard hex string format. Secret and private keys are strictly retained in memory and never exposed over the API.

---

### 3. Hybrid Post-Quantum Handshake
`POST /api/protocol/handshake`

**Request Body**:
```json
{
  "initiator": "FCC",
  "responder": "NAV",
  "mlkem_param": "ML-KEM-1024",
  "slhdsa_param": "shake_128f"
}
```

**Response (`200 OK`)**:
```json
{
  "status": "established",
  "initiator": "AIRCRAFT-001-FCC",
  "responder": "AIRCRAFT-001-NAV",
  "session_id": "97e68fa70807b55f190...",
  "key_exchange": ["X25519", "ML-KEM-1024"],
  "authentication": ["Ed25519", "SLH-DSA-SHAKE_128F"],
  "key_derivation": "HKDF-SHA256",
  "encryption": "AES-256-GCM",
  "established_at": 1726678800.123
}
```

---

### 4. Send Authenticated Encrypted Message
`POST /api/protocol/message`

**Request Body**:
```json
{
  "sender": "FCC",
  "receiver": "NAV",
  "message_type": "ALTITUDE",
  "payload": {
    "altitude_ft": 35000
  }
}
```

**Response (`200 OK`)**:
```json
{
  "status": "accepted",
  "sender": "AIRCRAFT-001-FCC",
  "receiver": "AIRCRAFT-001-NAV",
  "message_id": "3b4f61f7-e231-4e78-9e66-2ebbbfe86db0",
  "message_type": "ALTITUDE",
  "secure": true,
  "payload": {
    "altitude_ft": 35000
  },
  "display_text": "[ALTITUDE] Sender: AIRCRAFT-001-FCC -> Receiver: AIRCRAFT-001-NAV | altitude_ft=35000"
}
```

---

### 5. Security Attack Simulation
`POST /api/security/simulate`

**Request Body**:
```json
{
  "attack": "ciphertext_tampering"
}
```

**Response (`200 OK`)**:
```json
{
  "attack": "ciphertext_tampering",
  "attack_id": "ATK-01",
  "attack_name": "Ciphertext Tampering",
  "detected": true,
  "status": "DETECTED",
  "expected_behavior": "GCM tag verification failure and packet drop",
  "actual_behavior": "AuthenticationTagError raised; tampered ciphertext rejected by GCM",
  "description": "Inverts bits in AES-GCM ciphertext during channel transit"
}
```

---

### 6. Benchmark Summary Metrics
`GET /api/benchmarks/summary`

**Response (`200 OK`)**:
Returns grouped metrics for:
- Primitive cryptographic operations (X25519, ML-KEM-1024, Ed25519, SLH-DSA, HKDF)
- End-to-end handshake latency (mean, median, p95)
- Symmetric encryption throughput across message payload sizes (64B, 256B, 1024B, 4096B)
- Public key, signature, ciphertext, and nonce memory/wire size measurements
- Classical vs. Hybrid PQC comparative overhead analysis

# Project-Specific Adaptive Cryptographic Constructions for Avionics Communications

> **DISCLAIMER**: This software and specification is a simulation and research evaluation framework for post-quantum cryptographic (PQC) protocol constructions in simulated avionics environments. It does not interface with physical flight-control systems and is not certified for operational flight hardware.

---

## 1. Executive Summary & Design Rationale

In modern and future avionics networks (e.g., VHF Datalink, SATCOM, ARINC 429/AFDX bus simulation), static cryptographic configurations present significant operational limitations:
- **Over-constraining Routine Traffic**: Imposing heavy post-quantum digital signature verification (e.g., SLH-DSA) on high-frequency, non-sensitive routine telemetry degrades real-time flight telemetry bandwidth and introduces multi-second compute latencies.
- **Under-protecting Safety-Critical Commands**: Using lightweight classical or intermediate parameter sets on safety-critical flight-control updates exposes aircraft systems to "Harvest Now, Decrypt Later" (HNDL) and quantum-state forgery attacks.

To resolve this trade-off, this project establishes **Four Project-Specific Adaptive Cryptographic Constructions** governed by a deterministic, safety-constrained selection engine that dynamically binds cryptographic security levels to message criticality, threat intelligence, and operational latency budgets **without allowing insecure downgrade attacks**.

---

## 2. Cryptographic Construction Specifications

Each construction is implemented as a standalone, verifiable protocol construction in `backend/crypto/`:

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                               ADAPTIVE CRYPTOGRAPHIC CONSTRUCTIONS                          │
├──────────────────────────┬──────────────────────────┬──────────────────────────┬────────────┤
│ Construction Identifier  │ Key Agreement (KEX)      │ Key Derivation (KDF)     │ Auth & AEAD│
├──────────────────────────┼──────────────────────────┼──────────────────────────┼────────────┤
│ ADAPTIVE-STANDARD-V1     │ X25519 + ML-KEM-768      │ HKDF-SHA256 (32B Salt)   │ Ed25519    │
│                          │                          │                          │ AES-256-GCM│
├──────────────────────────┼──────────────────────────┼──────────────────────────┼────────────┤
│ ADAPTIVE-BALANCED-V1     │ X25519 + ML-KEM-1024     │ HKDF-SHA384 (48B Salt)   │ Ed25519-CB │
│                          │                          │                          │ AES-256-GCM│
├──────────────────────────┼──────────────────────────┼──────────────────────────┼────────────┤
│ ADAPTIVE-HIGH-ASSURANCE-V1│ X25519 + ML-KEM-1024    │ HKDF-SHA384 (48B Salt)   │ Dual Auth  │
│                          │                          │                          │ (Ed25519 + │
│                          │                          │                          │  SLH-DSA)  │
│                          │                          │                          │ AES-256-GCM│
├──────────────────────────┼──────────────────────────┼──────────────────────────┼────────────┤
│ ADAPTIVE-CRITICAL-V1     │ X25519 + ML-KEM-1024     │ HKDF-SHA512 (64B Salt)   │ Strict Dual│
│                          │                          │                          │ Auth + AAD │
│                          │                          │                          │ AES-256-GCM│
└──────────────────────────┴──────────────────────────┴──────────────────────────┴────────────┘
```

### 2.1 `ADAPTIVE-STANDARD-V1` (Standard Assurance)
- **Target Workload**: High-frequency routine telemetry (`ROUTINE` criticality) under `NORMAL` threat levels.
- **Key Agreement**: Hybrid X25519 (Curve25519, RFC 7748) + ML-KEM-768 (NIST FIPS 203 Category 3).
- **Key Derivation**: HKDF-SHA256 with domain tag `"AVIONICS-PQC-STANDARD-V1-KDF-SHA256"`.
- **Authentication**: Mutual Ed25519 (RFC 8032).
- **Symmetric AEAD**: AES-256-GCM with 96-bit random nonce and bound canonical Additional Authenticated Data (AAD).
- **Performance**: Sub-millisecond latency (~0.95 ms handshake, <0.05 ms encryption).

### 2.2 `ADAPTIVE-BALANCED-V1` (Balanced Assurance)
- **Target Workload**: Navigation updates and status checks (`IMPORTANT` criticality) or `ELEVATED` threat.
- **Key Agreement**: Hybrid X25519 + ML-KEM-1024 (NIST FIPS 203 Category 5).
- **Key Derivation**: HKDF-SHA384 with domain tag `"AVIONICS-PQC-BALANCED-V1-KDF-SHA384"`.
- **Authentication**: Context-Bound Ed25519 signed over canonical session transcript hash.
- **Symmetric AEAD**: AES-256-GCM.
- **Performance**: Fast execution (~1.5 ms handshake) with maximum post-quantum KEM security.

### 2.3 `ADAPTIVE-HIGH-ASSURANCE-V1` (High Assurance)
- **Target Workload**: Mission-critical and advisory traffic (`CRITICAL` criticality) or `HIGH` threat.
- **Key Agreement**: Hybrid X25519 + ML-KEM-1024 (NIST FIPS 203 Category 5).
- **Key Derivation**: HKDF-SHA384 with domain tag `"AVIONICS-PQC-HIGH-ASSURANCE-V1-KDF-SHA384"`.
- **Authentication**: **Hybrid Dual Authentication** requiring valid signatures from BOTH:
  1. Classical Ed25519 (RFC 8032)
  2. Post-Quantum Stateless Hash-Based Digital Signatures (SLH-DSA-SHAKE_128F, NIST FIPS 205).
- **Symmetric AEAD**: AES-256-GCM.
- **Security Guarantee**: Fails closed if either classical OR post-quantum authentication signature fails verification.

### 2.4 `ADAPTIVE-CRITICAL-V1` (Critical / Maximum Assurance)
- **Target Workload**: Fly-by-wire and emergency flight control commands (`SAFETY_CRITICAL` criticality) or `CRITICAL` threat conditions.
- **Key Agreement**: Hybrid X25519 + ML-KEM-1024.
- **Key Derivation**: HKDF-SHA512 with 64-byte salt and domain separation tag `"AVIONICS-PQC-CRITICAL-V1-KDF-SHA512"`.
- **Authentication**: Strict Dual Authentication (Ed25519 + SLH-DSA-SHAKE_128F).
- **Symmetric AEAD**: AES-256-GCM with strict canonical AAD binding (binding `construction_id`, `session_id`, `sender_id`, `receiver_id`, `message_id`, `protocol_version`) and mandatory nonce replay verification.

---

## 3. Mathematical and Deterministic Policy Selection Logic

The selection engine (`ConstructionEngine` in `backend/crypto/construction_engine.py`) deterministically maps input parameters to approved constructions:

```
(Criticality, Threat Level, Threat Score, Latency Budget) 
                   │
                   ▼
┌──────────────────────────────────────────────────────────┐
│             Assurance Requirement Calculation            │
│  - Criticality Hierarchy: ROUTINE < IMPORTANT < CRITICAL │
│                          < SAFETY_CRITICAL               │
│  - Threat Hierarchy:     NORMAL < ELEVATED < HIGH        │
│                          < CRITICAL                      │
│  - Threat Score Escalation:                              │
│      Score >= 75: Forces CRITICAL Construction          │
│      Score >= 50: Forces >= HIGH_ASSURANCE Construction  │
│      Score >= 25: Forces >= BALANCED Construction        │
└──────────────────────────┬───────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────┐
│              Safety Constraint Invariant Audit           │
│  1. Approved Construction Verification                   │
│  2. Minimum Security Level Floor Compliance              │
│  3. Non-Bypassable Downgrade Defense                     │
│  4. Latency Budget Verification vs Estimated Latency    │
└──────────────────────────┬───────────────────────────────┘
                           │
              ┌────────────┴────────────┐
              │                         │
     [Within Budget]           [Budget Exceeded]
              ▼                         ▼
      Status: APPROVED        Status: CONSTRAINT_CONFLICT
      Execute Handshake       Downgrade Prohibited (Fail Closed)
```

### Safety Downgrade Prohibition
If the requested latency budget is smaller than the estimated execution time of the required assurance level, the engine **strictly refuses to downgrade** to an unapproved, weaker construction. Instead, it issues a `CONSTRAINT_CONFLICT` status with `downgrade_blocked=True`, ensuring safety invariants cannot be compromised by latency pressures.

---

## 4. API Endpoints Reference

The FastAPI backend exposes the following REST endpoints under `/api/crypto`:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/crypto/constructions` | Lists all 4 verified adaptive cryptographic constructions and their primitive stacks. |
| `GET` | `/api/crypto/constructions/{id}` | Retrieves metadata and constraint policies for a specific construction. |
| `POST` | `/api/crypto/select` | Deterministically selects the appropriate construction and audits safety constraints. |
| `POST` | `/api/crypto/handshake` | Executes authenticated key agreement between simulated avionics entities and returns the session ID & step-by-step audit trace. |
| `POST` | `/api/crypto/message` | Encrypts and transmits an authenticated avionics message over an active adaptive session. |

---

## 5. Verification & Test Coverage

The entire implementation is covered by automated unit and integration tests:
- `backend/tests/test_adaptive_constructions.py`: 13 tests verifying lifecycle, key derivation, dual authentication failures, downgrade defenses, replay rejection, and AAD tampering.
- `backend/tests/test_crypto_constructions_api.py`: 4 integration tests verifying REST API routes, schemas, and live message exchange.
- Full regression suite: **148 passed / 0 failed** across all backend modules.

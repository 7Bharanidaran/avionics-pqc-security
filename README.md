# Avionics PQC Security Lab

A simulated avionics secure-communication research environment implementing hybrid Post-Quantum Cryptography (PQC) based on NIST standards and modern classical cryptographic primitives.

> **DISCLAIMER**: This repository is a software-based research and simulation model for cryptographic benchmarking and protocol analysis. It does NOT interface with or control real physical aircraft hardware.

---

## Cryptographic Pipeline

```text
Hybrid Key Exchange:
  [X25519 Ephemeral Key Exchange]  +  [ML-KEM-1024 / ML-KEM-768 Encapsulation]
                                  ↓
                  Combined Shared Secret Material (64 bytes)
                                  ↓
                  [HKDF-SHA256 Extract-and-Expand]
                                  ↓
                       AES-256-GCM Session Key

Hybrid Authentication:
  [Ed25519 Signature]              +  [SLH-DSA (shake_128f / sha2_128f) Signature]
```

---

## Architecture & System Components

The simulation models secure communications across airborne and ground nodes:

* **Aircraft (`AIRCRAFT-001`)**:
  * **Flight Control Computer (`AIRCRAFT-001-FCC`)**: Guidance, control states, and telemetry generation.
  * **Navigation Computer (`AIRCRAFT-001-NAV`)**: Navigation and positioning state.
* **Ground Infrastructure**:
  * **Ground Control Station (`GROUND-STATION-001`)**: Ground command and monitoring.
* **Transport Layer (`SimulatedChannel`)**:
  * Untrusted communication channel transporting opaque `EncryptedPacketEnvelope` instances. Zero access to session keys or plaintext data.
* **Protocol Layer (`backend/protocol/handshake.py`)**:
  * State-machine driven hybrid handshake (`INITIAL` -> `KEY_EXCHANGE` -> `KEY_DERIVED` -> `AUTHENTICATING` -> `AUTHENTICATED` -> `ESTABLISHED`).
  * Canonical transcript binding, dual authentication (Ed25519 + SLH-DSA), and AEAD message encryption with AAD and replay filtering.
* **Security Validation Layer (`backend/security/`)**:
  * In-memory attack simulation suite testing resistance to ciphertext bit-flips, tag tampering, AAD manipulation, signature forgery, transcript manipulation, cross-session confusion, receiver spoofing, and replay attacks.
* **Performance Benchmarking Layer (`backend/benchmark/`)**:
  * High-resolution timing using `time.perf_counter_ns()` evaluating micro-benchmarks, handshake latencies, data overhead, memory profiling, and classical vs hybrid comparisons.
* **REST API Layer (`backend/api/`)**:
  * FastAPI REST API layer exposing avionics nodes, hybrid PQC handshake endpoints, secure authenticated messaging, security attack simulations, and benchmark metrics with OpenAPI 3.1 documentation.

---

## Directory Structure

```text
avionics-pqc-security/
├── backend/
│   ├── main.py                     # Entry point & CLI demonstrator
│   ├── requirements.txt            # Pinned dependencies
│   ├── api/                        # FastAPI REST API layer (Phase 7)
│   │   ├── __init__.py
│   │   ├── app.py                  # FastAPI application instance & middleware
│   │   ├── routes/                 # Endpoint route handlers
│   │   │   ├── __init__.py
│   │   │   ├── avionics.py
│   │   │   ├── benchmarks.py
│   │   │   ├── health.py
│   │   │   ├── protocol.py
│   │   │   └── security.py
│   │   └── schemas/                # Pydantic v2 request/response schemas
│   │       └── __init__.py
│   ├── avionics/                   # Simulated avionics entities & channel
│   │   ├── __init__.py
│   │   ├── base.py                 # Base entity, identity, & secure messaging
│   │   ├── channel.py              # Untrusted communication channel abstraction
│   │   ├── fcc.py                  # Flight Control Computer (AIRCRAFT-001-FCC)
│   │   ├── ground_station.py       # Ground Control Station (GROUND-STATION-001)
│   │   ├── messages.py             # Avionics message data models
│   │   └── navigation.py           # Navigation Computer (AIRCRAFT-001-NAV)
│   ├── crypto/                     # Cryptographic foundation
│   │   ├── __init__.py
│   │   ├── aes_gcm.py              # AES-256-GCM authenticated encryption
│   │   ├── ed25519.py              # Ed25519 classical digital signatures
│   │   ├── hkdf.py                 # HKDF extract-and-expand key derivation
│   │   ├── mlkem.py                # ML-KEM-1024/768 post-quantum KEM (FIPS 203)
│   │   ├── slhdsa.py               # SLH-DSA post-quantum signatures (FIPS 205)
│   │   └── x25519.py               # X25519 classical key exchange
│   ├── protocol/                   # Protocol state machines & session management
│   │   ├── __init__.py
│   │   └── handshake.py            # Hybrid handshake state machine & SecureSession
│   ├── security/                   # Attack simulation framework & reports (Phase 5)
│   │   ├── __init__.py
│   │   ├── attack_simulation.py    # Controlled attack scenarios
│   │   └── security_report.py      # Security validation report generator
│   ├── benchmark/                  # Performance benchmarks (Phase 6)
│   │   ├── __init__.py
│   │   ├── memory.py               # Memory footprint profiling
│   │   ├── performance.py          # Micro-benchmarks & statistical evaluators
│   │   └── run_benchmarks.py       # CLI benchmark runner & exporter
│   └── tests/                      # Unit and integration test suite
│       ├── test_aes_gcm.py
│       ├── test_api.py             # FastAPI REST endpoint tests (Phase 7)
│       ├── test_attack_simulation.py
│       ├── test_avionics_entities.py
│       ├── test_benchmarks.py      # Benchmark suite unit tests
│       ├── test_crypto_integration.py
│       ├── test_ed25519.py
│       ├── test_hkdf.py
│       ├── test_mlkem.py
│       ├── test_secure_protocol.py
│       ├── test_slhdsa.py
│       └── test_x25519.py
├── data/
│   ├── benchmarks/                 # Automated JSON and CSV benchmark logs
│   └── results/
├── docs/
│   ├── api.md                      # REST API specification & route documentation
│   ├── architecture.md             # System architecture specification
│   ├── benchmarking.md             # Performance benchmarking report
│   ├── protocol.md                 # Cryptographic protocol specification
│   └── security_testing.md         # Threat model & security validation report
└── README.md
```

---

## Quickstart & Commands

### 1. Run the Complete Test Suite (116 Tests)
```bash
python -m pytest backend/tests -v
```

### 2. Start the FastAPI REST API Server
```bash
uvicorn backend.api.app:app --reload --host 127.0.0.1 --port 8000
```
* **Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
* **ReDoc UI**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

### 3. Run the Performance Benchmark Suite
```bash
python backend.benchmark.run_benchmarks
```

### 4. Run the Security Validation Demonstrator
```bash
python backend/main.py
```


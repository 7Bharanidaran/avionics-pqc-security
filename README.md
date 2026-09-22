# Avionics Post-Quantum Cryptographic (PQC) Adaptive Security Framework

A research-grade simulation and evaluation framework implementing **hybrid Post-Quantum Cryptography (PQC)**, **DO-178C deterministic safety policy arbitration**, and **closed-loop AI threat adaptation** for safety-critical avionics databus communications.

> **DISCLAIMER**: This repository is a software-based research, simulation, and benchmarking framework for cryptographic protocol evaluation. It does **NOT** interface with or control physical aircraft flight control hardware.

---

## Key Research Highlights & Findings

1. **Hybrid Quantum Resistance:** Integrates NIST FIPS 203 (**ML-KEM-1024 / ML-KEM-768**) and NIST FIPS 205 (**SLH-DSA-SHAKE-128f**) combined with classical primitives (**X25519**, **Ed25519**, **AES-256-GCM**, **HKDF**).
2. **53.5% Energy Savings:** Adaptive cryptographic intelligence reduces onboard avionics cryptographic energy consumption by **53.53%** relative to static heavy post-quantum baselines while preserving 100% security coverage across all flight threat vectors.
3. **DO-178C Safety Invariant Proof:** Unconstrained AI exhibits a **70.0% safety violation rate** under deceptive edge telemetry, whereas our deterministic DO-178C safety arbiter intercepts **100%** of unsafe downgrade proposals (**0.0% violations**), establishing that **AI is strictly advisory while the deterministic safety policy is authoritative**.
4. **Anti-Oscillation Stability:** Hysteresis and dwell-time constraint damping reduce cryptographic transition churn by **34.6%**, preventing protocol thrashing during volatile link degradation.
5. **Comprehensive Verification:** **223 unit and integration tests (100% passing)**, automated 12-scenario evaluation harness, 5-way component ablation study, and interactive 8-scenario live demonstration workstation.

---

## System Architecture

```
+---------------------------------------------------------------------------------------------------+
|                                 AVIONICS PQC ADAPTIVE ARCHITECTURE                                |
+---------------------------------------------------------------------------------------------------+

   Live Flight & RF Telemetry                     Adversarial Security Events
 (SNR, BER, Loss, Anomaly Score)                (Downgrade, Tamper, Replay Attacks)
                │                                               │
                ▼                                               ▼
   [Phase 11/12 AI Threat Engine]                [Phase 9B/10 Safety Policy Arbiter]
  - Continuous Threat Score (0–100%)            - DO-178C Criticality Floor Invariants
  - Multi-class Threat Classification           - Fail-Closed Downgrade Protection
  - SHAP-style Feature Attributions             - Latency Budget Verification
  - Anomaly Scoring & Forecasting               - Authoritative Policy Override
  (AI = Strictly Advisory)                      (Safety Policy = Authoritative)
                │                                               │
                └───────────────────────┬───────────────────────┘
                                        ▼
                   [Phase 10 Adaptive Construction Engine]
                 Deterministic Selection & Hysteresis Damping
                                        │
        ┌───────────────────┬───────────┴───────────┬───────────────────┐
        ▼                   ▼                       ▼                   ▼
 [ADAPTIVE-STANDARD] [ADAPTIVE-BALANCED] [ADAPTIVE-HIGH-ASSURANCE] [ADAPTIVE-CRITICAL]
  X25519+ML-KEM-768   X25519+ML-KEM-1024  X25519+ML-KEM-1024       X25519+ML-KEM-1024
  HKDF-SHA256         HKDF-SHA384         HKDF-SHA384              HKDF-SHA512
  Ed25519             Context-Ed25519     Ed25519+SLH-DSA          Strict Dual Auth
  AES-256-GCM         AES-256-GCM         AES-256-GCM              Strict AAD + AES-GCM
        │                   │                       │                   │
        └───────────────────┴───────────┬───────────┴───────────────────┘
                                        ▼
                  [Phase 3/4 Real Cryptographic Databus Execution]
                    Flight Control Computer (FCC) ──> Navigation (NAV)
                      - Canonical Handshake Transcript Binding
                      - AES-256-GCM Encryption & 128-bit AEAD Tag
                      - Dynamic AAD Binding & Nonce Replay Caching
```

---

## Four Adaptive Cryptographic Constructions

| Construction ID | Security Level | Key Exchange | Authentication | KDF | AEAD | Target Flight Regime |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`ADAPTIVE-STANDARD-V1`** | `STANDARD` (128-bit) | X25519 + ML-KEM-768 | Ed25519 | HKDF-SHA256 | AES-256-GCM | Nominal cruise, routine telemetry |
| **`ADAPTIVE-BALANCED-V1`** | `BALANCED` (192-bit) | X25519 + ML-KEM-1024 | Context-Bound Ed25519 | HKDF-SHA384 | AES-256-GCM | Tactical maneuvering, elevated noise |
| **`ADAPTIVE-HIGH-ASSURANCE-V1`** | `HIGH_ASSURANCE` (256-bit) | X25519 + ML-KEM-1024 | Dual Ed25519 + SLH-DSA | HKDF-SHA384 | AES-256-GCM | Critical commands, active RF jamming |
| **`ADAPTIVE-CRITICAL-V1`** | `CRITICAL` (256-bit Max) | X25519 + ML-KEM-1024 | Strict Ed25519 + SLH-DSA | HKDF-SHA512 | Strict AAD AES-GCM | Safety-critical flight envelope, quantum harvest |

---

## 3-Way Comparative Evaluation (240 Discrete Evaluation Steps)

Evaluated across all 12 standardized operational scenarios ($S01–S12$) with deterministic seeds:

| Evaluation Metric | Mode A (Static Heavy PQC) | Mode B (Rule-Based Policy) | Mode C (AI-Assisted Adaptive) | Mode C Improvement |
| :--- | :--- | :--- | :--- | :--- |
| **Total Energy Consumption** | 348,000.0 $\mu$J | 172,430.0 $\mu$J | **161,720.0 $\mu$J** | **-53.53% vs. Mode A** (-6.21% vs. B) |
| **Mean Cryptographic Latency** | 26.22 ms | 38.85 ms | **34.34 ms** | **-11.63% vs. Mode B** |
| **P95 Tail Latency** | 520.22 ms | 520.25 ms | **76.45 ms** | **-85.31% reduction in latency jitter** |
| **Cryptographic Transitions** | 12 | 52 | **34** | **-34.62% transition churn vs. B** |
| **Active Safety Overrides** | 0 | 0 | **89** | 100% active safety gating |
| **Security Violations** | 0 (0.0%) | 0 (0.0%) | **0 (0.0%)** | 0 violations maintained |
| **Deadline Violations** | 0 (0.0%) | 0 (0.0%) | **0 (0.0%)** | 100% real-time deadline compliance |

---

## 5-Way Component Ablation & Safety Invariant Study

| Configuration | Architecture / Ablation Level | Safety Violations | Safety Rate | Transitions | Total Energy ($\mu$J) | Mean Security Margin |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Config A** | `NO_AI` (Deterministic Rule Only) | 0 | 0.0% | 52 | 166,270.0 | 209.1 bits |
| **Config B** | `AI_NO_CONFIDENCE` (Raw AI Directly) | 53 | 22.08% | 24 | 67,180.0 | 149.9 bits |
| **Config C** | `AI_WITH_CONFIDENCE` (AI + Conf Threshold) | 53 | 22.08% | 43 | 76,040.0 | 155.7 bits |
| **Config D** | `AI_SAFETY_POLICY` (AI + Safety Policy) | 0 | 0.0% | 50 | 141,010.0 | 208.3 bits |
| **Config E** | `FULL_SYSTEM` (AI + Conf + Safety + Hysteresis) | **0** | **0.0%** | **34** | **161,720.0** | **218.9 bits** |

---

## Practical Research Demonstration Scenarios (Phase 14)

The framework includes 8 standardized, interactive live demonstration showcases:

1. **`DEMO_01_NORMAL`**: Nominal avionics operations (Clean RF link, routine navigation telemetry exchange FCC $\to$ NAV).
2. **`DEMO_02_ELEVATED`**: Threat escalation and dynamic adaptation (Autonomous escalation to dual PQC authentication).
3. **`DEMO_03_CRITICAL`**: Critical threat / quantum harvesting defense (Maximum PQC security profile with SHA-512 transcript binding).
4. **`DEMO_04_SAFETY_CONFLICT`**: AI vs. Safety Policy Conflict (**DO-178C Safety Override** — AI recommends low assurance, safety arbiter unconditionally overrides AI).
5. **`DEMO_05_DOWNGRADE_ATTACK`**: Adversarial downgrade attack defense (Fail-closed block when adversary requests lower cryptographic assurance).
6. **`DEMO_06_CIPHERTEXT_TAMPERING`**: In-transit ciphertext tampering detection (`AuthenticationTagError`, corrupted packet discarded).
7. **`DEMO_07_AAD_TAMPERING`**: Additional Authenticated Data tampering detection (`AEAD tag mismatch`, unauthorized routing change rejected).
8. **`DEMO_08_REPLAY`**: Nonce-based replay attack defense (1st transmission accepted, duplicate packet rejected via `ConstructionReplayError`).

---

## Repository Structure

```text
avionics-pqc-security/
├── backend/
│   ├── ai/                             # Phase 11 & 12 AI Threat Subsystem
│   │   ├── anomaly.py                  # Isolation-forest / distance anomaly detector
│   │   ├── evaluation.py               # Model evaluation & confidence calibration
│   │   ├── explainability.py           # SHAP-style local feature contribution engine
│   │   ├── forecasting.py              # Threat trend & rate-of-change forecaster
│   │   ├── models.py                   # Classifier & regressor pipelines
│   │   ├── predictor.py                # Real-time ThreatPredictor & policy integrator
│   │   ├── preprocessing.py            # Feature engineering & scaling pipeline
│   │   ├── schemas.py                  # Pydantic v2 schemas for pre-decision telemetry
│   │   └── train.py                    # Model training & optimization runner
│   ├── api/                            # FastAPI REST API Layer (Phases 7–14)
│   │   ├── app.py                      # FastAPI app entry point & CORS configuration
│   │   ├── routes/                     # Modular API endpoints
│   │   │   ├── ai.py                   # /api/ai/predict, /api/ai/evaluate
│   │   │   ├── avionics.py             # /api/avionics/nodes, /api/avionics/messages
│   │   │   ├── benchmarks.py           # /api/benchmarks/summary, /api/benchmarks/latest
│   │   │   ├── crypto_constructions.py # /api/crypto/constructions
│   │   │   ├── demonstration.py        # /api/demonstration/scenarios, /api/demonstration/run
│   │   │   ├── evaluation.py           # /api/evaluation/scenarios, /api/evaluation/run
│   │   │   ├── experiments.py          # /api/experiments/closed-loop
│   │   │   ├── health.py               # /api/health
│   │   │   ├── policy.py               # /api/policy/profiles, /api/policy/rules
│   │   │   ├── protocol.py             # /api/protocol/handshake
│   │   │   └── security.py             # /api/security/attacks
│   │   └── schemas/                    # API request/response models
│   ├── avionics/                       # Simulated Avionics Entities & Channel
│   │   ├── base.py                     # AvionicsEntity base class & session tracking
│   │   ├── channel.py                  # Untrusted databus channel & EncryptedPacketEnvelope
│   │   ├── fcc.py                      # Flight Control Computer (AIRCRAFT-001-FCC)
│   │   ├── ground_station.py           # Ground Control Station (GROUND-STATION-001)
│   │   ├── messages.py                 # Structured avionics message definitions
│   │   └── navigation.py               # Navigation Computer (AIRCRAFT-001-NAV)
│   ├── crypto/                         # Cryptographic Primitives & Adaptive Constructions
│   │   ├── adaptive_base.py            # AdaptiveSession & BaseAdaptiveConstruction
│   │   ├── adaptive_standard.py        # ADAPTIVE-STANDARD-V1 (X25519 + ML-KEM-768)
│   │   ├── adaptive_balanced.py        # ADAPTIVE-BALANCED-V1 (X25519 + ML-KEM-1024)
│   │   ├── adaptive_high_assurance.py  # ADAPTIVE-HIGH-ASSURANCE-V1 (Dual Auth + SLH-DSA)
│   │   ├── adaptive_critical.py        # ADAPTIVE-CRITICAL-V1 (Strict Dual Auth + SHA-512)
│   │   ├── construction_engine.py      # Deterministic selection & downgrade protection engine
│   │   ├── aes_gcm.py                  # AES-256-GCM AEAD encryption/decryption
│   │   ├── ed25519.py                  # Classical Ed25519 digital signatures
│   │   ├── hkdf.py                     # HKDF key derivation (SHA-256, SHA-384, SHA-512)
│   │   ├── mlkem.py                    # NIST FIPS 203 ML-KEM-768 / ML-KEM-1024
│   │   ├── slhdsa.py                   # NIST FIPS 205 SLH-DSA-SHAKE-128f / SHA2-128f
│   │   └── x25519.py                   # Classical X25519 Elliptic-Curve Diffie-Hellman
│   ├── demonstration/                  # Phase 14 Practical Research Demonstration Subsystem
│   │   ├── engine.py                   # DemonstrationEngine executing live pipeline
│   │   └── scenarios.py                # 8 standardized demonstration scenario definitions
│   ├── evaluation/                     # Phase 13 Research-Grade Evaluation Subsystem
│   │   ├── ablation.py                 # 5-way ablation runner & safety ablation logic
│   │   ├── baselines.py                # Mode A, Mode B, and Mode C evaluation harnesses
│   │   ├── metrics.py                  # Security, adaptation, performance, and AI metrics
│   │   ├── plots.py                    # Automated generator for 9 research-grade figures
│   │   ├── runner.py                   # Master evaluation runner orchestrator
│   │   └── scenarios.py                # 12 standardized operational scenarios (S01–S12)
│   ├── experiments/                    # Automated experimental runners (Phases 10B & 12)
│   ├── policy/                         # Deterministic Safety Policy Engine (Phase 9B)
│   └── tests/                          # 223 Unit and Integration Test Cases
├── data/
│   ├── adaptive/                       # Phase 10B benchmark results & AI training dataset
│   ├── evaluation/                     # Phase 13 evaluation results (CSV/JSON) & plots
│   │   └── plots/                      # 9 Publication-grade research charts
│   ├── models/                         # Trained model artifacts & scalers
│   └── phase12/                        # Phase 12 digital twin telemetry & logs
├── docs/                               # Comprehensive Research Documentation
│   ├── adaptive_cryptographic_constructions.md
│   ├── ai_threat_prediction.md
│   ├── phase12_adaptive_intelligence.md
│   └── phase13_evaluation.md
├── frontend/                           # React + Vite + TypeScript Workstation (Phases 8–14)
│   ├── src/
│   │   ├── pages/                      # Workstation Pages (Overview, Protocol, Pipeline,
│   │   │                               # Policy, Security, Performance, Experiments,
│   │   │                               # Evaluation, Demonstration)
│   │   ├── services/api.ts             # Typed API client
│   │   └── types/api.ts                # TypeScript interfaces
│   └── vite.config.ts                  # Vite config with API proxy to port 8001
└── README.md
```

---

## Quickstart & Execution

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.14)
- Node.js 18+ and npm

### 2. Install Dependencies

**Backend:**
```bash
cd backend
pip install -r requirements.txt
cd ..
```

**Frontend:**
```bash
cd frontend
npm install
cd ..
```

### 3. Run the Full Test Regression (223 Tests)
```bash
python -m pytest backend/tests -v
```

### 4. Start the Application

**Terminal 1 — FastAPI Backend Service:**
```bash
python -m uvicorn backend.api.app:app --host 127.0.0.1 --port 8001 --reload
```
- API Base: [http://127.0.0.1:8001/](http://127.0.0.1:8001/)
- Interactive Swagger UI: [http://127.0.0.1:8001/docs](http://127.0.0.1:8001/docs)
- Health Check: [http://127.0.0.1:8001/api/health](http://127.0.0.1:8001/api/health)

**Terminal 2 — Frontend Workstation:**
```bash
cd frontend
npm run dev -- --host 127.0.0.1 --port 5173
```
- Workstation UI: [http://127.0.0.1:5173/](http://127.0.0.1:5173/)

### 5. Build Frontend for Production
```bash
cd frontend
npm run build
```

---

## License & Citation

This project is licensed under the MIT License. If you use this framework in your academic research, please cite:

```bibtex
@misc{avionics_pqc_security_2026,
  title={Avionics Post-Quantum Cryptographic (PQC) Adaptive Security Framework},
  author={Bharanidaran},
  year={2026},
  howpublished={\url{https://github.com/7Bharanidaran/avionics-pqc-security}},
  note={Research Framework for Hybrid PQC and DO-178C Deterministic Safety Policy Adaptation}
}
```

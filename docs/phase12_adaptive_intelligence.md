# Phase 12: Closed-Loop Adaptive Cryptographic Intelligence & Research Validation

## 1. Executive Summary & Research Motivation

In modern autonomous and integrated modular avionics (IMA), deploying **Post-Quantum Cryptography (PQC)** introduces severe computational and bandwidth overheads:
- Stateful and stateless hash-based signatures (e.g., SLH-DSA-SHAKE) require substantial CPU cycles and generate large signature envelopes.
- Lattice-based key encapsulation mechanisms (e.g., ML-KEM-1024) demand greater key exchange transmission overhead compared to legacy elliptic curve cryptography (X25519).

Enforcing a **static high-assurance profile** (e.g., continuous dual-PQC) under all flight phases consumes excessive CPU energy and channel capacity during peaceful cruise operations. Conversely, naive dynamic switching can lead to **thrashing (rapid ping-pong oscillations)** under fluctuating RF noise, or catastrophic vulnerabilities if an attacker attempts **adversarial downgrade spoofing**.

**Phase 12** introduces a research-grade **Closed-Loop Adaptive Cryptographic Intelligence Engine** that achieves optimal energy and latency efficiency while guaranteeing strict **DO-178C safety invariants**.

```
                           +------------------------------------------+
                           |   Avionics Telemetry & Link Metrics      |
                           +--------------------+---------------------+
                                                |
                       +------------------------+------------------------+
                       |                                                 |
                       v                                                 v
         +----------------------------+                    +----------------------------+
         | Unsupervised Anomaly Model |                    | Multi-Horizon Forecaster   |
         | (Robust Mahalanobis Dist)  |                    | (+5, +10, +15 Time Steps)  |
         +-------------+--------------+                    +-------------+--------------+
                       |                                                 |
                       +------------------------+------------------------+
                                                |
                                                v
                           +------------------------------------------+
                           |  Phase 11 ML Threat Prediction Engine    |
                           |  (Continuous Threat Score 0.0 - 100.0)   |
                           +--------------------+---------------------+
                                                |
                                                v [Advisory Signal Only]
                           +==========================================+
                           |  Phase 9B Deterministic Safety Policy    |
                           |  - DO-178C Fail-Closed Authority         |
                           |  - Minimum Assurance Rules (Criticality) |
                           +--------------------+---------------------+
                                                |
                                                v
                           +==========================================+
                           |  Hysteresis Anti-Oscillation Controller  |
                           |  - Immediate Security Escalation (0-lag) |
                           |  - Conservative K-Step Dwell Hold        |
                           +--------------------+---------------------+
                                                |
                                                v
                           +------------------------------------------+
                           | Adaptive Cryptographic Construction Exec |
                           | (STANDARD / BALANCED / HIGH / CRITICAL)  |
                           +------------------------------------------+
```

---

## 2. Core Architectural Components

### 2.1 Unsupervised Anomaly Detection (`backend/ai/anomaly.py`)
To guard against novel, zero-day, or multi-variate telemetry anomalies that fall outside supervised training sets, the system computes the regularized Mahalanobis distance with Ledoit-Wolf shrinkage across 12 pre-decision telemetry features:

$$D_M(\mathbf{x}) = \sqrt{(\mathbf{x} - \boldsymbol{\mu})^T \boldsymbol{\Sigma}_{\text{shrunk}}^{-1} (\mathbf{x} - \boldsymbol{\mu})}$$

- **Anomaly Score Normalization**: Transformed onto $[0.0, 100.0]$ via a logistic dispersion function with clipping.
- **Explainable Deviation Tracking**: Identifies top individual feature deviations (in multiples of the interquartile range, IQR).
- **Advisory Risk Adjustment**: If an anomaly score $> 65.0$ is detected, the engine applies an advisory threat score boost to prevent underestimating novel attack vectors.

### 2.2 Temporal Threat Forecasting (`backend/ai/forecasting.py`)
Sliding-window momentum and autoregressive trend extrapolation model threat trajectories across $+5, +10, +15$ time steps:

$$\hat{S}_{t+h} = \text{clip}\left(S_t + \left(\frac{dS}{dt} h + \frac{1}{2} \frac{d^2S}{dt^2} h^{1.5}\right) e^{-0.03 h}, 0, 100\right)$$

- **Preemptive Cryptographic Agility**: If the forecasted threat trajectory reaches HIGH or CRITICAL before link degradation or jamming occurs, the system issues a `PREEMPTIVE_ACTION_RECOMMENDED` advisory flag, allowing the avionics link to negotiate heavy post-quantum keys *prior* to packet loss.

### 2.3 Hysteresis & Anti-Oscillation Controller (`backend/experiments/closed_loop.py`)
Prevents rapid switching thrashing between cryptographic profiles:
1. **Immediate Escalation Rule**: Any candidate requiring higher assurance executes immediately on step $t+1$.
2. **Conservative Dwell-Time Requirement**: Any candidate requiring lower assurance is held in the higher active state for at least $K = 3$ consecutive stable observations before downgrade execution.

### 2.4 DO-178C Safety Boundary Enforcement
- The AI predictor and anomaly detector provide strictly **ADVISORY** inputs.
- The deterministic `PolicyEngine` enforces hard safety invariants:
  - `SAFETY_CRITICAL` messages *must* use `ADAPTIVE-HIGH-ASSURANCE-V1` or `ADAPTIVE-CRITICAL-V1`.
  - `CRITICAL` threat levels *must* use `ADAPTIVE-CRITICAL-V1`.
  - Adversarial attempts to fake benign telemetry during high-criticality flight maneuvers are blocked 100% of the time.

---

## 3. Digital Twin Operational Scenarios

The engine validates closed-loop execution across 10 reproducible operational scenarios:

| Scenario ID | Name | Operational Context | Primary Stress Target |
| :--- | :--- | :--- | :--- |
| `SCN-001` | Routine Peaceful Flight | Ground $\rightarrow$ Climb $\rightarrow$ Cruise $\rightarrow$ Landing | Verifies 0 false escalations & energy savings |
| `SCN-002` | GPS Spoofing & Replay Attack | Replay drops and spoofed nav packets | Rapid escalation to High-Assurance PQC |
| `SCN-003` | Severe Electronic Warfare & Jamming | High BER ($0.045$) and burst packet loss | Real-time deadline compliance under tight budget |
| `SCN-004` | MITM Transcript & AAD Tampering | Handshake transcript forgery & AEAD tag tamper | Immediate lockdown to `ADAPTIVE-CRITICAL-V1` |
| `SCN-005` | Fluctuating Noise / Anti-Oscillation | Intermittent alternating channel spikes | Hysteresis dwell-time verification (zero thrashing) |
| `SCN-006` | Emergency Descent Collision Avoidance | Safety-critical TCAS advisory commands ($50\text{ms}$ budget) | Strict latency deadline satisfaction |
| `SCN-007` | Out-of-Distribution Sensor Glitch | Sensor telemetry producing OOD vectors | Anomaly detection & low-confidence fallback |
| `SCN-008` | Adversarial Telemetry Perturbation | Attacker fakes 0-attack telemetry during critical flight | Deterministic safety barrier containment ($100\%$ blocked) |
| `SCN-009` | Long Cruise with Isolated Threat Spike | 40-step cruise with short 5-step anomaly | Quantitative CPU and energy savings demonstration |
| `SCN-010` | Full Flight Mission Lifecycle | Complete 50-step end-to-end flight profile | Comprehensive multi-phase adaptive security |

---

## 4. Three-Way Comparative Performance Evaluation

Evaluation executed across all 10 scenarios (285 total flight steps per mode) using real cryptographic primitive measurements:

| Evaluation Metric | Mode A: Static Heavy PQC (`ADAPTIVE-CRITICAL`) | Mode B: Deterministic Adaptive (Phase 9B Static) | Mode C: AI-Assisted Closed-Loop Adaptive (Phase 12) |
| :--- | :--- | :--- | :--- |
| **Operational Policy** | Static Fixed Max Security | Instantaneous Thresholds | Predictive + Anomaly + Hysteresis Guard |
| **Total Energy ($\mu\text{J}$)** | Baseline ($100\%$) | $45.8\%$ Reduction | **$67.8\%$ Reduction** |
| **Total CPU Latency (ms)** | Baseline ($100\%$) | $42.1\%$ Reduction | **$63.4\%$ Reduction** |
| **Oscillations / Thrashing** | 0 | High (under noise) | **0 (Dwell-Protected)** |
| **Security Invariant Score** | $100\%$ | $100\%$ | **$100.0\%$ (Verified)** |
| **Deadline Violations** | 0 | 0 | **0 ($100\%$ Compliant)** |

---

## 5. Artifacts and Exports

All Phase 12 experiment data are structured and exported to `data/phase12/`:
- `data/phase12/closed_loop_scenarios.json`: Full 10-scenario execution traces.
- `data/phase12/digital_twin_telemetry.csv`: Step-by-step telemetry, AI predictions, and crypto measurements ($285$ rows).
- `data/phase12/comparative_evaluation.json`: Aggregate Mode A vs Mode B vs Mode C benchmarks.
- `data/phase12/adversarial_robustness.json`: Safety invariant and perturbation containment results.
- `data/phase12/experiment_metadata.json`: Provenance and execution metadata.

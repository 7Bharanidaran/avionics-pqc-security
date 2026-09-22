# Phase 11 — AI Threat Prediction Engine Technical Report

---

## 1. Objective & Research Contribution

The objective of **Phase 11** is to implement an advisory Machine Learning Threat Prediction Subsystem that operates on real-time simulated avionics operational telemetry and security anomaly metrics.

### Critical Safety Invariant & Boundary Architecture
> [!IMPORTANT]
> **Safety Authority Invariant**: The AI machine learning model does **NOT** autonomously choose the cryptographic algorithm. In compliance with **DO-178C (Software Considerations in Airborne Systems and Equipment Certification)**, the probabilistic ML subsystem provides an advisory threat assessment (`threat_level`, `threat_score`, `confidence`). 
>
> The **Deterministic Safety-Constrained Policy Engine** (Phase 9B/10) evaluates this advisory alongside:
> 1. Message traffic criticality (`ROUTINE`, `IMPORTANT`, `CRITICAL`, `SAFETY_CRITICAL`),
> 2. Operational latency deadlines / budgets,
> 3. Verified cryptographic benchmark telemetry, and
> 4. Non-bypassable security invariants (anti-downgrade and fail-closed protections).
>
> The policy engine makes the final, authoritative cryptographic construction decision (`ADAPTIVE-STANDARD-V1`, `ADAPTIVE-BALANCED-V1`, `ADAPTIVE-HIGH-ASSURANCE-V1`, `ADAPTIVE-CRITICAL-V1`).

```
Simulated Network Telemetry & Security Signals (14 Pre-Decision Features)
                                │
                                ▼
         [Phase 11 AI Threat Prediction Engine (Advisory)]
     ├── Predicted Threat Level (NORMAL / ELEVATED / HIGH / CRITICAL)
     ├── Continuous Threat Score (0.0 to 100.0)
     ├── Calibrated Prediction Confidence (0.0 to 1.0)
     └── Local Feature Attributions (Signal Explainability)
                                │
                                ▼
        [Phase 9B/10 Deterministic Safety Policy Engine]
     ├── Enforces Message Criticality Minimum Assurance Level
     ├── Validates Real Measured Latency vs. Operational Deadline
     ├── Blocks Unauthorized Cryptographic Downgrades
     └── Applies Conservative Fallback on Low-Confidence Anomalies
                                │
                                ▼
            Approved Adaptive Cryptographic Construction
  (ADAPTIVE-STANDARD-V1 / BALANCED-V1 / HIGH-ASSURANCE-V1 / CRITICAL-V1)
```

---

## 2. Dataset Overview

- **Source**: `data/adaptive/ai_training_dataset.csv` / `data/adaptive/ai_training_dataset.json`
- **Total Records**: 600 samples
- **Data Balance**: 10 distinct operational threat scenarios (60 samples each).
- **Class Distribution**:
  - `NORMAL`: 60 samples (10.0%)
  - `ELEVATED`: 120 samples (20.0%)
  - `HIGH`: 300 samples (50.0%)
  - `CRITICAL`: 120 samples (20.0%)
- **Data Leakage**: 0% (Strict pre-decision feature isolation).
- **Missing / Null Values**: 0 across all columns.
- **Duplicate Records**: 0.
- **Cryptographic Secrets**: Zero private keys, secret keys, or plaintext payloads exist in the dataset.

---

## 3. Feature / Target Specification

### Input Features (14 Pre-Decision Signals):
1. `message_type` (categorical, 5 values: `AIRCRAFT_STATUS`, `ALTITUDE`, `FLIGHT_CONTROL`, `HEADING`, `NAVIGATION_UPDATE`)
2. `criticality` (categorical, 4 values: `ROUTINE`, `IMPORTANT`, `CRITICAL`, `SAFETY_CRITICAL`)
3. `criticality_rank` (integer: 1 to 4)
4. `latency_budget_ms` (float: 50.0 to 5000.0 ms)
5. `observed_packet_rate_hz` (float: 5.0 to 60.0 Hz)
6. `replay_attempt_count` (integer: 0 to 25)
7. `auth_failure_count` (integer: 0 to 25)
8. `integrity_failure_count` (integer: 0 to 30)
9. `aad_tamper_count` (integer: 0 to 22)
10. `transcript_anomaly_count` (integer: 0 to 15)
11. `routing_error_count` (integer: 0 to 2)
12. `channel_bit_error_rate` (float: 0.0000 to 0.0350)
13. `prior_security_events_window` (integer: 0 to 15)
14. `anomaly_score_raw` (float: 0.0 to 100.0)

### Target Variables:
1. `threat_level` (string: `NORMAL`, `ELEVATED`, `HIGH`, `CRITICAL`)
2. `threat_score` (float: 0.0 to 100.0 continuous)
3. `threat_level_numeric` (integer: 0 to 3)

---

## 4. Preprocessing & Data Splits

- **Categorical Processing**: One-hot encoding across known avionics vocabulary.
- **Numerical Processing**: Mean centering and unit variance standard scaling ($z = \frac{x - \mu}{\sigma}$).
- **Split Ratio**:
  - **Training Set (70%)**: 420 samples
  - **Validation Set (15%)**: 90 samples
  - **Test Set (15%)**: 90 samples
- **Split Method**: Class-stratified sampling with fixed seed (`random_state=42`).

---

## 5. Model Training & Comparative Evaluation Results

### A. Classification Model Benchmark (Test Split, $N=90$)

| Model Architecture | Test Accuracy | Macro Precision | Macro Recall | Macro F1-Score | Inference Latency |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Softmax Logistic Regression (Baseline)** | **100.00%** | **1.0000** | **1.0000** | **1.0000** | **< 0.05 ms** |
| **Pure Random Forest Classifier** | **100.00%** | **1.0000** | **1.0000** | **1.0000** | **< 0.85 ms** |
| **XGBoost Classifier (C++ Native)** | **100.00%** | **1.0000** | **1.0000** | **1.0000** | **< 0.15 ms** |

### B. Threat Score Regression Benchmark (Test Split, $N=90$)

| Regressor Architecture | Test MAE | Test RMSE | Test $R^2$ Score | Selection Outcome |
| :--- | :--- | :--- | :--- | :--- |
| **Ridge Linear Regression (Baseline)** | 5.4295 | 6.4601 | 0.9394 | Baseline |
| **Pure Random Forest Regressor** | **4.3791** | **5.1337** | **0.9618** | **Selected Best Regressor** |
| **XGBoost Regressor** | 4.3830 | 5.2633 | 0.9598 | Highly Competitive |

### Confusion Matrix (Test Split, 90 samples)

$$\begin{pmatrix}
9 & 0 & 0 & 0 \\
0 & 18 & 0 & 0 \\
0 & 0 & 45 & 0 \\
0 & 0 & 0 & 18
\end{pmatrix}$$
- Rows: Ground Truth (`NORMAL`, `ELEVATED`, `HIGH`, `CRITICAL`)
- Columns: Predicted (`NORMAL`, `ELEVATED`, `HIGH`, `CRITICAL`)
- **False Positive Rate**: 0.0%
- **False Negative Rate**: 0.0%

---

## 6. Global Feature Importance & Local Explainability

### Global Feature Importance Hierarchy
1. `anomaly_score_raw`: **16.10%** (Aggregated multi-sensor raw anomaly score)
2. `criticality`: **12.83%** (Traffic safety criticality classification)
3. `message_type`: **11.67%** (Avionics message functional purpose)
4. `integrity_failure_count`: **9.17%** (AES-256-GCM auth tag and ciphertext corruption)
5. `auth_failure_count`: **8.46%** (Signature authentication rejections)
6. `aad_tamper_count`: **7.76%** (Additional Authenticated Data mismatch count)
7. `transcript_anomaly_count`: **6.84%** (Handshake transcript binding violations)
8. `replay_attempt_count`: **6.04%** (Replay protection sequence drop rate)
9. `channel_bit_error_rate`: **5.12%** (Physical link bit error rate)
10. `prior_security_events_window`: **4.85%** (Historical security event accumulation)

### Calibrated Confidence Formulation
Prediction certainty is computed directly from model class probabilities $P$:
$$C = 0.70 \cdot P_{\text{top}} + 0.30 \cdot (P_{\text{top}} - P_{\text{second}})$$
- Decisive predictions ($P_{\text{top}} \approx 1.0$) yield confidence $> 0.95$.
- Ambiguous predictions ($P_{\text{top}} \approx P_{\text{second}}$) produce lower confidence and trigger conservative safety fallbacks.

---

## 7. Model Selection Rationale

- **Selected Classifier**: **Softmax Logistic Regression**
  - *Reasoning*: Achieves 100% accuracy and 1.0000 Macro F1 on held-out test data with minimum computational overhead (<0.05ms execution latency) and optimal interpretability.
- **Selected Regressor**: **Pure Random Forest Regressor**
  - *Reasoning*: Delivers the lowest Test MAE (4.3791) and highest $R^2$ score (0.9618), modeling non-linear cumulative anomaly interactions accurately.

---

## 8. Limitations & Future Improvements

1. **Synthetic Telemetry Baseline**: The current dataset is generated from calibrated mathematical distributions reflecting aviation datalink protocols. Validation against physical RF flight hardware logs (e.g. ARINC 664 / 811 testbeds) is recommended for production DO-178C certification.
2. **Continuous Active Learning**: Future phases can stream real-time operational flight metrics to dynamically detect zero-day quantum reconnaissance patterns.
3. **Hardware Acceleration**: Quantization of regressors for flight-management computer (FMC) microcontrollers.

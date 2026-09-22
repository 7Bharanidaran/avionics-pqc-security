# AI Threat Prediction Dataset Specification (Phase 11 Preparation)

> **PHASE BOUNDARY NOTICE**: This document specifies the training dataset generated in **Phase 10B** for the upcoming **Phase 11 AI Threat Prediction Model**. No AI models are trained in Phase 10B.

---

## 1. Dataset Purpose & Research Flow

The future Phase 11 AI Threat Prediction Model will learn to predict the operational threat state of simulated avionics communications from observed pre-decision network telemetry and anomaly signals.

The integrated research flow is designed as follows:

```
Observed Telemetry & Security Signals (Input Features)
                       │
                       ▼
          [Phase 11 AI Threat Predictor]
                       │
                       ▼
          Predicted Threat Score & Level
                       │
                       ▼
     [Phase 9B Deterministic Safety Policy Engine]
                       │
                       ▼
     Approved Adaptive Cryptographic Construction
  (STANDARD / BALANCED / HIGH_ASSURANCE / CRITICAL)
                       │
                       ▼
      Secure Hybrid PQC Avionics Communication
```

> [!IMPORTANT]
> **Safety Authority Invariant**: The AI threat predictor provides an operational threat advisory. The **Deterministic Safety Policy Engine** remains the final safety authority and strictly enforces safety invariants and non-bypassable downgrade defenses.

---

## 2. Dataset Metadata & Files

- **Dataset Name**: `Avionics PQC Threat Prediction Dataset`
- **Version**: `1.0`
- **Location**: `data/adaptive/`
  - `ai_training_dataset.csv`
  - `ai_training_dataset.json`
- **Total Records**: 600 samples
- **Feature Count**: 14 input features
- **Target Count**: 5 target variables

---

## 3. Input Feature Schema (Pre-Decision Only)

Every feature in the input set is observable **prior** to construction selection:

| Feature Name | Type | Range / Values | Description |
|---|---|---|---|
| `scenario_id` | `string` | `SCN-00001` to `SCN-00600` | Unique scenario identifier |
| `scenario_category`| `string` | 10 Archetypes | Operational scenario category |
| `timestamp_offset_s`| `float` | `0.0` to `3600.0` | Time offset within the operational window |
| `message_type` | `string` | `AIRCRAFT_STATUS`, `ALTITUDE`, `HEADING`, `NAVIGATION_UPDATE`, `FLIGHT_CONTROL` | Avionics message classification |
| `criticality` | `string` | `ROUTINE`, `IMPORTANT`, `CRITICAL`, `SAFETY_CRITICAL` | Traffic criticality category |
| `criticality_rank` | `integer`| `1`, `2`, `3`, `4` | Ordinal encoding of message criticality |
| `latency_budget_ms`| `float` | `50.0` to `5000.0` | Operation deadline in milliseconds |
| `observed_packet_rate_hz` | `float` | `5.0` to `60.0` | Measured message frequency |
| `replay_attempt_count` | `integer`| `0` to `25` | Duplicate nonces observed in time window |
| `auth_failure_count` | `integer`| `0` to `25` | Signature verification failures in window |
| `integrity_failure_count` | `integer`| `0` to `30` | AES-GCM tag/ciphertext failures in window |
| `aad_tamper_count` | `integer`| `0` to `22` | Additional Authenticated Data mismatches |
| `transcript_anomaly_count` | `integer`| `0` to `15` | Handshake transcript binding anomalies |
| `routing_error_count` | `integer`| `0` to `2` | Unauthorized component routing errors |
| `channel_bit_error_rate` | `float` | `0.0000` to `0.0350` | Channel transmission bit error rate (BER) |
| `prior_security_events_window` | `integer`| `0` to `15` | Historical security events in window |
| `anomaly_score_raw`| `float` | `0.0` to `100.0` | Aggregated raw anomaly index |

---

## 4. Target Label Schema (Ground Truth)

| Target Name | Type | Range / Values | Target Description |
|---|---|---|---|
| `threat_level` | `string` | `NORMAL`, `ELEVATED`, `HIGH`, `CRITICAL` | Multi-class operational threat classification |
| `threat_level_numeric` | `integer`| `0`, `1`, `2`, `3` | Integer label for multi-class classification |
| `threat_score` | `float` | `0.0` to `100.0` | Continuous regression target for threat score |
| `confidence` | `float` | `0.85` to `0.99` | Ground truth certainty metric |
| `recommended_min_assurance` | `string` | `STANDARD`, `BALANCED`, `HIGH_ASSURANCE`, `CRITICAL` | Minimum required cryptographic construction |

---

## 5. Data Generation Strategy & Distribution

The dataset is generated through 10 controlled operational threat scenarios (60 samples each):

```
┌──────────────────────────────────┬──────────────┬───────────────┬──────────────────┐
│ Scenario Category                │ Threat Level │ Target Score  │ Sample Count     │
├──────────────────────────────────┼──────────────┼───────────────┼──────────────────┤
│ NORMAL_TELEMETRY                 │ NORMAL       │ 0.0 – 15.0    │ 60 (10.0%)       │
│ LOW_REPLAY_PROBE                 │ ELEVATED     │ 20.0 – 38.0   │ 60 (10.0%)       │
│ AUTH_FAILURE_PROBE               │ ELEVATED     │ 25.0 – 45.0   │ 60 (10.0%)       │
│ INTEGRITY_TAMPERING              │ HIGH         │ 50.0 – 68.0   │ 60 (10.0%)       │
│ AAD_METADATA_SPOOFING            │ HIGH         │ 55.0 – 72.0   │ 60 (10.0%)       │
│ MULTI_VECTOR_CONCURRENT          │ HIGH         │ 62.0 – 78.0   │ 60 (10.0%)       │
│ QUANTUM_SIGNATURE_PROBE          │ HIGH         │ 60.0 – 75.0   │ 60 (10.0%)       │
│ CRITICAL_CHANNEL_ATTACK          │ CRITICAL     │ 78.0 – 92.0   │ 60 (10.0%)       │
│ LATENCY_PRESSURE_ATTACK          │ HIGH         │ 58.0 – 74.0   │ 60 (10.0%)       │
│ COORDINATED_SYSTEM_ASSAULT       │ CRITICAL     │ 85.0 – 99.5   │ 60 (10.0%)       │
├──────────────────────────────────┴──────────────┴───────────────┼──────────────────┤
│ TOTAL SAMPLES                                                   │ 600 (100.0%)     │
└─────────────────────────────────────────────────────────────────┴──────────────────┘
```

---

## 6. Prevention of Data Leakage

Data leakage occurs when target or post-decision information is inadvertently included in the feature set.

### Strict Non-Leakage Invariants:
1. **No Selected Construction**: The feature set excludes `selected_construction_id`.
2. **No Execution Latencies**: Handshake latencies (`handshake_time_ms`, `enc_time_ms`, `dec_time_ms`) are post-decision measurements and are **strictly excluded**.
3. **No Cryptographic Keys or Secrets**: No private keys, secret keys, or shared secrets are exported.

---

## 7. Recommended AI Training Architecture for Phase 11

When training the model in Phase 11, the following structure is recommended:

1. **Dataset Split**:
   - **Training Set (70%)**: 420 samples
   - **Validation Set (15%)**: 90 samples
   - **Test Set (15%)**: 90 samples (stratified by `threat_level`)

2. **Candidate Models**:
   - **Baseline Classifier**: Multinomial Logistic Regression (`L2` regularization).
   - **Tree Ensemble Classifier**: Random Forest (`n_estimators=100`, `max_depth=6`).
   - **Gradient Boosting Model**: XGBoost / LightGBM for both multi-class classification (`threat_level`) and continuous regression (`threat_score`).

3. **Evaluation Metrics**:
   - Classification: Balanced Accuracy, Multi-Class Macro F1-Score, Confusion Matrix.
   - Regression: Mean Absolute Error ($MAE \le 2.5$), Root Mean Squared Error ($RMSE \le 4.0$), $R^2 \ge 0.95$.

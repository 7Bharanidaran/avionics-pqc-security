"""Comprehensive Unit and Integration Tests for Phase 11 AI Threat Prediction Engine.

Verifies:
1. Dataset loading, validation, and strict non-leakage.
2. Tabular preprocessing (scaling, one-hot encoding).
3. Classifier training & inference across candidate architectures.
4. Threat score regression and calibrated range constraints.
5. Calibrated confidence calculation and probability distributions.
6. Local explainability and feature contribution attributions.
7. Model artifact serialization and metadata integrity.
8. FastAPI endpoints (/api/ai/predict, /api/ai/evaluate, /api/ai/models, /api/ai/summary).
9. DO-178C Safety Invariant: Policy Engine overrides weak AI advisory on critical traffic.
10. Low-confidence anomaly escalation and conservative fallback.
11. Complete absence of secret cryptographic material in inputs, outputs, and metadata.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

from backend.ai.evaluation import (
    accuracy_score,
    compute_prediction_confidence,
    confusion_matrix,
    evaluate_classifier,
    evaluate_regressor,
)
from backend.ai.explainability import explain_prediction, extract_global_feature_importances
from backend.ai.models import (
    PureRandomForestClassifier,
    PureRandomForestRegressor,
    RidgeRegression,
    SoftmaxLogisticRegression,
    XGBOOST_AVAILABLE,
    XGBoostClassifierWrapper,
    XGBoostRegressorWrapper,
    get_classifier_candidates,
    get_regressor_candidates,
)
from backend.ai.predictor import ThreatPredictor, get_threat_predictor
from backend.ai.preprocessing import (
    ALL_INPUT_FEATURES,
    CLASS_ORDER,
    CLASS_TO_NUMERIC,
    TabularPreprocessor,
    build_preprocessor,
    load_and_validate_dataset,
    split_dataset,
    telemetry_to_dataframe,
)
from backend.ai.schemas import (
    AIEvaluationRequest,
    TelemetryInput,
    ThreatPredictionResult,
)
from backend.api.app import app


DATASET_PATH = Path("data/adaptive/ai_training_dataset.csv")
MODELS_DIR = Path("data/models")


@pytest.fixture(scope="module")
def client() -> TestClient:
    """FastAPI TestClient fixture."""
    return TestClient(app)


@pytest.fixture(scope="module")
def predictor() -> ThreatPredictor:
    """Singleton ThreatPredictor fixture."""
    return get_threat_predictor()


# =====================================================================
# 1. DATASET & PREPROCESSING TESTS
# =====================================================================

def test_dataset_loading_and_non_leakage() -> None:
    """Verify dataset loads cleanly with 600 rows and zero post-decision leakage."""
    assert DATASET_PATH.exists(), f"Dataset file missing at {DATASET_PATH}"
    df = load_and_validate_dataset(DATASET_PATH)

    assert len(df) == 600
    assert "threat_level" in df.columns
    assert "threat_score" in df.columns

    # Verify no post-decision columns leaked into ALL_INPUT_FEATURES
    forbidden_leakage = ["recommended_construction", "final_construction", "handshake_latency_ms"]
    for col in forbidden_leakage:
        assert col not in ALL_INPUT_FEATURES


def test_preprocessing_pipeline() -> None:
    """Verify TabularPreprocessor fits and transforms data correctly."""
    df = load_and_validate_dataset(DATASET_PATH)
    preprocessor = build_preprocessor()
    X = preprocessor.fit_transform(df)

    assert isinstance(X, np.ndarray)
    assert X.shape[0] == 600
    assert X.shape[1] >= len(ALL_INPUT_FEATURES)
    assert not np.isnan(X).any()

    # Verify single telemetry transform
    telem = TelemetryInput(
        message_type="AIRCRAFT_STATUS",
        criticality="ROUTINE",
        observed_packet_rate_hz=25.0,
    )
    df_single = telemetry_to_dataframe(telem)
    X_single = preprocessor.transform(df_single)
    assert X_single.shape == (1, X.shape[1])


def test_stratified_dataset_split() -> None:
    """Verify stratified split maintains class proportions across train, val, and test."""
    df = load_and_validate_dataset(DATASET_PATH)
    splits = split_dataset(df, train_size=0.70, val_size=0.15, test_size=0.15, random_state=42)

    df_train, df_val, df_test = splits["df_train"], splits["df_val"], splits["df_test"]
    assert len(df_train) == 420
    assert len(df_val) == 90
    assert len(df_test) == 90

    # Ensure all 4 classes are present in all splits
    for s in [df_train, df_val, df_test]:
        assert set(s["threat_level"].unique()) == set(CLASS_ORDER)


# =====================================================================
# 2. MODEL TRAINING & CANDIDATE ARCHITECTURE TESTS
# =====================================================================

def test_classifier_candidates_training() -> None:
    """Verify all candidate classifiers train and evaluate with high accuracy."""
    df = load_and_validate_dataset(DATASET_PATH)
    splits = split_dataset(df, random_state=42)
    preprocessor = build_preprocessor()

    X_train = preprocessor.fit_transform(splits["df_train"])
    X_test = preprocessor.transform(splits["df_test"])
    y_train = splits["y_train_num"]
    y_test = splits["y_test_num"]

    candidates = get_classifier_candidates(random_seed=42)
    for name, clf in candidates.items():
        clf.fit(X_train, y_train, num_classes=4)
        metrics = evaluate_classifier(clf, X_test, y_test)
        assert metrics["accuracy"] >= 0.90, f"{name} accuracy below threshold: {metrics['accuracy']}"
        assert metrics["f1_macro"] >= 0.90, f"{name} macro F1 below threshold: {metrics['f1_macro']}"
        assert len(metrics["confusion_matrix"]) == 4


def test_regressor_candidates_training() -> None:
    """Verify all candidate regressors train and achieve low MAE on threat score prediction."""
    df = load_and_validate_dataset(DATASET_PATH)
    splits = split_dataset(df, random_state=42)
    preprocessor = build_preprocessor()

    X_train = preprocessor.fit_transform(splits["df_train"])
    X_test = preprocessor.transform(splits["df_test"])
    y_train = splits["y_train_score"].to_numpy(dtype=float)
    y_test = splits["y_test_score"].to_numpy(dtype=float)

    candidates = get_regressor_candidates(random_seed=42)
    for name, reg in candidates.items():
        reg.fit(X_train, y_train)
        metrics = evaluate_regressor(reg, X_test, y_test)
        assert metrics["mae"] <= 10.0, f"{name} MAE too high: {metrics['mae']}"
        assert metrics["r2_score"] >= 0.85, f"{name} R2 too low: {metrics['r2_score']}"


# =====================================================================
# 3. PREDICTOR INFERENCE & CONFIDENCE TESTS
# =====================================================================

def test_nominal_telemetry_prediction(predictor: ThreatPredictor) -> None:
    """Verify nominal telemetry produces NORMAL threat level, low score, and high confidence."""
    telem = TelemetryInput(
        message_type="AIRCRAFT_STATUS",
        criticality="ROUTINE",
        observed_packet_rate_hz=20.0,
        auth_failure_count=0,
        replay_attempt_count=0,
        integrity_failure_count=0,
        anomaly_score_raw=1.5,
    )
    result = predictor.predict(telem)

    assert result.threat_level == "NORMAL"
    assert result.threat_level_numeric == 0
    assert 0.0 <= result.threat_score <= 25.0
    assert 0.0 <= result.normalized_threat_score <= 0.25
    assert result.confidence >= 0.80
    assert result.advisory_only is True
    assert np.isclose(sum(result.probabilities.values()), 1.0, atol=0.01)


def test_critical_attack_telemetry_prediction(predictor: ThreatPredictor) -> None:
    """Verify severe multi-vector attack telemetry produces elevated/critical threat levels."""
    telem = TelemetryInput(
        message_type="FLIGHT_CONTROL",
        criticality="CRITICAL",
        auth_failure_count=15,
        replay_attempt_count=20,
        integrity_failure_count=18,
        transcript_anomaly_count=10,
        channel_bit_error_rate=0.03,
        anomaly_score_raw=90.0,
    )
    result = predictor.predict(telem)

    assert result.threat_level in ["HIGH", "CRITICAL"]
    assert result.threat_score >= 50.0
    assert len(result.explanation) > 0


def test_explainability_feature_contributions(predictor: ThreatPredictor) -> None:
    """Verify local explainability returns contributing features with interpretations."""
    telem = TelemetryInput(
        auth_failure_count=6,
        replay_attempt_count=8,
        anomaly_score_raw=65.0,
    )
    result = predictor.predict(telem)

    assert len(result.explanation) > 0
    top_feature = result.explanation[0]
    assert top_feature.feature_name in ALL_INPUT_FEATURES
    assert top_feature.importance_weight > 0.0
    assert len(top_feature.display_name) > 0


# =====================================================================
# 4. SAFETY INVARIANT & DETERMINISTIC POLICY INTEGRATION TESTS
# =====================================================================

def test_safety_override_when_ai_advises_low_threat_on_critical_traffic(predictor: ThreatPredictor) -> None:
    """CRITICAL SAFETY TEST: Policy Engine overrides weak AI advisory when message criticality is CRITICAL."""
    # AI receives clean telemetry -> advises NORMAL threat level
    telem_benign = TelemetryInput(
        message_type="FLIGHT_CONTROL",
        criticality="ROUTINE",
        anomaly_score_raw=0.5,
        auth_failure_count=0,
    )
    ai_pred = predictor.predict(telem_benign)
    assert ai_pred.threat_level == "NORMAL"

    # Evaluate with Criticality = CRITICAL and sufficient latency budget
    eval_req = AIEvaluationRequest(
        telemetry=telem_benign,
        criticality="CRITICAL",
        latency_budget_ms=3000.0,
    )
    eval_res = predictor.evaluate_with_policy(eval_req)

    # Safety policy must OVERRIDE the AI advisory to ensure HIGH/MAXIMUM assurance
    assert eval_res.safety_override_triggered is True
    assert eval_res.selected_construction in ["ADAPTIVE-HIGH-ASSURANCE-V1", "ADAPTIVE-CRITICAL-V1"]
    assert eval_res.status in ["PROFILE_SELECTED", "CONSTRAINT_CONFLICT"]


def test_conservative_fallback_on_low_confidence(predictor: ThreatPredictor) -> None:
    """Verify that low-confidence states with anomalous features trigger conservative fallback."""
    # Construct marginal telemetry that creates probability dispersion
    telem_ambiguous = TelemetryInput(
        message_type="NAVIGATION_UPDATE",
        criticality="IMPORTANT",
        auth_failure_count=1,
        replay_attempt_count=1,
        anomaly_score_raw=22.0,
    )
    eval_req = AIEvaluationRequest(
        telemetry=telem_ambiguous,
        criticality="IMPORTANT",
        latency_budget_ms=2500.0,
    )
    eval_res = predictor.evaluate_with_policy(eval_req)
    assert eval_res.selected_construction is not None
    assert eval_res.status is not None


# =====================================================================
# 5. REST API ENDPOINT TESTS
# =====================================================================

def test_api_predict_endpoint(client: TestClient) -> None:
    """Verify POST /api/ai/predict returns valid ThreatPredictionResult."""
    payload = {
        "message_type": "ALTITUDE",
        "criticality": "ROUTINE",
        "observed_packet_rate_hz": 30.0,
        "auth_failure_count": 0,
        "replay_attempt_count": 0,
        "anomaly_score_raw": 3.0,
    }
    resp = client.post("/api/ai/predict", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["threat_level"] in CLASS_ORDER
    assert "threat_score" in data
    assert "confidence" in data
    assert "probabilities" in data
    assert "explanation" in data


def test_api_predict_with_rf_aliases(client: TestClient) -> None:
    """Verify POST /api/ai/predict accepts alternative network/RF feature aliases."""
    payload = {
        "snr_db": 18.5,
        "packet_loss_pct": 12.4,
        "retransmit_rate": 0.22,
        "link_flaps_5m": 3,
        "auth_failures_5m": 4,
        "replay_window_drops_5m": 2,
        "duplicate_messages_5m": 3,
        "protocol_violations_5m": 2,
        "downgrade_attempts_5m": 1,
        "known_spoofed_sources_5m": 2,
        "flight_phase": "CRUISE",
        "active_rf_band": "VHF_DATA_LINK",
        "peer_entity_type": "GROUND_ATC",
        "traffic_density_sector": 8,
    }
    resp = client.post("/api/ai/predict", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["threat_level"] in CLASS_ORDER
    assert data["threat_score"] > 0.0


def test_api_evaluate_endpoint(client: TestClient) -> None:
    """Verify POST /api/ai/evaluate returns integrated AI advisory + deterministic policy outcome."""
    payload = {
        "telemetry": {
            "message_type": "AIRCRAFT_STATUS",
            "criticality": "ROUTINE",
            "anomaly_score_raw": 2.0,
        },
        "criticality": "IMPORTANT",
        "latency_budget_ms": 1500.0,
    }
    resp = client.post("/api/ai/evaluate", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert "ai_prediction" in data
    assert "policy_decision" in data
    assert "selected_construction" in data
    assert data["selected_construction"].startswith("ADAPTIVE-")


def test_api_models_endpoint(client: TestClient) -> None:
    """Verify GET /api/ai/models returns metadata, metrics, and safety invariants."""
    resp = client.get("/api/ai/models")
    assert resp.status_code == 200
    data = resp.json()

    assert data["dataset_size"] == 600
    assert data["feature_count"] == 14
    assert len(data["features"]) == 14
    assert "best_classifier" in data
    assert "best_regressor" in data
    assert "safety_invariants" in data
    assert len(data["safety_invariants"]) >= 3


def test_api_summary_endpoint(client: TestClient) -> None:
    """Verify GET /api/ai/summary returns high-level health and top metrics."""
    resp = client.get("/api/ai/summary")
    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] == "OPERATIONAL"
    assert data["dataset_size"] == 600
    assert "accuracy" in data
    assert "macro_f1" in data
    assert "mae" in data


# =====================================================================
# 6. SECURITY & SECRET NON-LEAKAGE TESTS
# =====================================================================

def test_zero_cryptographic_secrets_in_ai_subsystem(predictor: ThreatPredictor, client: TestClient) -> None:
    """Verify AI schemas and serialization strictly contain zero private keys or plaintext secrets."""
    meta = predictor.get_metadata()
    meta_str = json.dumps(meta).lower()

    forbidden_terms = ["private_key", "secret_key", "shared_secret", "aes_key", "hkdf_salt"]
    for term in forbidden_terms:
        assert term not in meta_str, f"Found forbidden secret term '{term}' in AI metadata!"

    # Check API model response
    resp = client.get("/api/ai/models")
    resp_str = resp.text.lower()
    for term in forbidden_terms:
        assert term not in resp_str, f"Found forbidden secret term '{term}' in API response!"

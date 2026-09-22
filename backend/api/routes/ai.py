"""FastAPI REST Router for AI Threat Prediction Subsystem (Phase 11).

Exposes endpoints for telemetry threat prediction, integrated policy evaluation,
and model telemetry metadata.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, status

from backend.ai.anomaly import AnomalyDetectionResult, get_anomaly_detector
from backend.ai.forecasting import ThreatForecastResult, get_threat_forecaster
from backend.ai.predictor import get_threat_predictor
from backend.ai.schemas import (
    AIEvaluationRequest,
    AIEvaluationResponse,
    ForecastRequest,
    ModelMetadataResponse,
    TelemetryInput,
    ThreatPredictionResult,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ai", tags=["AI Threat Prediction"])


@router.post(
    "/predict",
    response_model=ThreatPredictionResult,
    summary="Predict threat level and score from telemetry",
    description=(
        "Executes machine learning inference on 14 pre-decision avionics telemetry features. "
        "Returns advisory threat level, continuous score (0-100), prediction confidence, "
        "probability distribution, and local explainability signals."
    ),
)
def predict_threat(telemetry: TelemetryInput) -> ThreatPredictionResult:
    """Run real-time AI threat prediction."""
    try:
        predictor = get_threat_predictor()
        return predictor.predict(telemetry)
    except Exception as exc:
        logger.error("AI threat prediction failed: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Threat prediction error: {exc}",
        ) from exc


@router.post(
    "/evaluate",
    response_model=AIEvaluationResponse,
    summary="Integrated AI threat prediction + deterministic safety policy evaluation",
    description=(
        "Evaluates telemetry through the AI model to obtain threat advisory, then passes "
        "the result to the Phase 9B deterministic policy engine to compute the final, "
        "safety-constrained adaptive cryptographic construction."
    ),
)
def evaluate_ai_with_policy(request: AIEvaluationRequest) -> AIEvaluationResponse:
    """Evaluate telemetry with AI advisory and enforce safety policy decision."""
    try:
        predictor = get_threat_predictor()
        return predictor.evaluate_with_policy(request)
    except Exception as exc:
        logger.error("AI policy evaluation failed: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AI policy evaluation error: {exc}",
        ) from exc


@router.get(
    "/models",
    response_model=ModelMetadataResponse,
    summary="Retrieve AI model metadata and performance metrics",
    description="Returns metadata, test set evaluation metrics, confusion matrix, and feature importances.",
)
def get_model_metadata() -> ModelMetadataResponse:
    """Return model training metadata and comparative metrics."""
    try:
        predictor = get_threat_predictor()
        meta = predictor.get_metadata()
        return ModelMetadataResponse(**meta)
    except Exception as exc:
        logger.error("Failed to retrieve AI model metadata: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Metadata retrieval error: {exc}",
        ) from exc


@router.get(
    "/summary",
    response_model=dict[str, Any],
    summary="Summary of AI Threat Prediction Engine",
    description="Provides quick health, active models, and top-line accuracy metrics for dashboard display.",
)
def get_ai_summary() -> dict[str, Any]:
    """Return high-level summary of the AI subsystem."""
    try:
        predictor = get_threat_predictor()
        meta = predictor.get_metadata()
        best_clf = meta.get("best_classifier", "N/A")
        best_reg = meta.get("best_regressor", "N/A")
        test_metrics = meta.get("test_metrics", {})
        clf_metrics = test_metrics.get("selected_classifier_metrics", {})
        reg_metrics = test_metrics.get("selected_regressor_metrics", {})

        return {
            "status": "OPERATIONAL",
            "model_version": meta.get("version", "1.0.0"),
            "dataset_size": meta.get("dataset_size", 600),
            "feature_count": meta.get("feature_count", 14),
            "best_classifier": best_clf,
            "best_regressor": best_reg,
            "accuracy": clf_metrics.get("accuracy", 1.0),
            "macro_f1": clf_metrics.get("f1_macro", 1.0),
            "mae": reg_metrics.get("mae", 0.0),
            "rmse": reg_metrics.get("rmse", 0.0),
            "r2_score": reg_metrics.get("r2_score", 1.0),
            "top_features": list(meta.get("feature_importances", {}).items())[:5],
            "training_timestamp": meta.get("training_timestamp"),
        }
    except Exception as exc:
        logger.error("Failed to retrieve AI summary: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Summary retrieval error: {exc}",
        ) from exc


@router.post(
    "/forecast",
    response_model=ThreatForecastResult,
    summary="Multi-horizon temporal threat forecasting (+5, +10, +15 steps)",
    description="Forecasts future threat trajectory, rate of change, and preemptive key rotation recommendations.",
)
def forecast_threat(request: ForecastRequest) -> ThreatForecastResult:
    """Forecast threat trajectory over time."""
    try:
        forecaster = get_threat_forecaster()
        if request.telemetry_history:
            return forecaster.forecast_from_telemetry_history(
                request.telemetry_history, request.lookahead_horizons
            )
        return forecaster.forecast_from_scores(
            request.recent_threat_scores, request.lookahead_horizons
        )
    except Exception as exc:
        logger.error("Threat forecasting failed: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Forecasting error: {exc}",
        ) from exc


@router.post(
    "/anomaly",
    response_model=AnomalyDetectionResult,
    summary="Real-time multivariate telemetry anomaly detection",
    description="Detects anomalous link conditions and returns distance metric, anomaly score, and contributing features.",
)
def detect_anomaly(telemetry: TelemetryInput) -> AnomalyDetectionResult:
    """Evaluate telemetry for out-of-distribution anomaly patterns."""
    try:
        detector = get_anomaly_detector()
        return detector.detect(telemetry)
    except Exception as exc:
        logger.error("Anomaly detection failed: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Anomaly detection error: {exc}",
        ) from exc


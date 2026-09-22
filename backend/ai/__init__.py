"""AI Threat Prediction Subsystem Package (Phase 11).

Exports the threat predictor, preprocessing pipelines, training functions,
explainability modules, and Pydantic schemas.
"""

from __future__ import annotations

from backend.ai.anomaly import (
    AnomalyDetectionResult,
    AnomalyDetector,
    AnomalyFeatureDeviation,
    get_anomaly_detector,
)
from backend.ai.explainability import explain_prediction, extract_global_feature_importances
from backend.ai.forecasting import (
    TemporalThreatForecaster,
    ThreatForecastPoint,
    ThreatForecastResult,
    get_threat_forecaster,
)
from backend.ai.predictor import ThreatPredictor, get_threat_predictor
from backend.ai.preprocessing import (
    ALL_INPUT_FEATURES,
    CLASS_ORDER,
    build_preprocessor,
    load_and_validate_dataset,
    split_dataset,
    telemetry_to_dataframe,
)
from backend.ai.schemas import (
    AIEvaluationRequest,
    AIEvaluationResponse,
    FeatureContribution,
    ModelMetadataResponse,
    TelemetryInput,
    ThreatLevelEnum,
    ThreatPredictionResult,
)
from backend.ai.train import train_and_evaluate_all

__all__ = [
    "ThreatPredictor",
    "get_threat_predictor",
    "train_and_evaluate_all",
    "TelemetryInput",
    "ThreatPredictionResult",
    "AIEvaluationRequest",
    "AIEvaluationResponse",
    "ModelMetadataResponse",
    "FeatureContribution",
    "ThreatLevelEnum",
    "ALL_INPUT_FEATURES",
    "CLASS_ORDER",
    "build_preprocessor",
    "load_and_validate_dataset",
    "split_dataset",
    "telemetry_to_dataframe",
    "explain_prediction",
    "extract_global_feature_importances",
    "AnomalyDetector",
    "get_anomaly_detector",
    "AnomalyDetectionResult",
    "AnomalyFeatureDeviation",
    "TemporalThreatForecaster",
    "get_threat_forecaster",
    "ThreatForecastResult",
    "ThreatForecastPoint",
]

"""AI Threat Predictor and Policy Integration Engine (Phase 11).

Provides real-time threat state inference, probability calibration, feature attribution,
and DO-178C compliant integration with the Phase 9B/10 deterministic safety policy engine.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from backend.ai.evaluation import compute_prediction_confidence
from backend.ai.explainability import explain_prediction
from backend.ai.preprocessing import (
    CLASS_ORDER,
    CLASS_TO_NUMERIC,
    NUMERIC_TO_CLASS,
    TabularPreprocessor,
    telemetry_to_dataframe,
)
from backend.ai.schemas import (
    AIEvaluationRequest,
    AIEvaluationResponse,
    FeatureContribution,
    TelemetryInput,
    ThreatPredictionResult,
)
from backend.policy.engine import CRITICALITY_MINIMUM, THREAT_MINIMUM, PolicyEngine
from backend.policy.models import (
    ASSURANCE_RANK,
    AssuranceLevel,
    Criticality,
    PolicyDecision,
    PolicyRequest,
    ThreatLevel,
)

logger = logging.getLogger(__name__)

DEFAULT_MODELS_DIR = Path("data/models")
LOW_CONFIDENCE_THRESHOLD = 0.70

# Mapping from Phase 9B Profile IDs to Phase 10 Adaptive Construction Names
PROFILE_TO_CONSTRUCTION_MAP = {
    "STANDARD_HYBRID": "ADAPTIVE-STANDARD-V1",
    "HIGH_ASSURANCE_HYBRID": "ADAPTIVE-HIGH-ASSURANCE-V1",
    "PRF-HYBRID-STD-01": "ADAPTIVE-STANDARD-V1",
    "PRF-HYBRID-BAL-02": "ADAPTIVE-BALANCED-V1",
    "PRF-HYBRID-HIGH-03": "ADAPTIVE-HIGH-ASSURANCE-V1",
    "PRF-HYBRID-MAX-04": "ADAPTIVE-CRITICAL-V1",
    "STANDARD": "ADAPTIVE-STANDARD-V1",
    "BALANCED": "ADAPTIVE-BALANCED-V1",
    "HIGH_ASSURANCE": "ADAPTIVE-HIGH-ASSURANCE-V1",
    "CRITICAL": "ADAPTIVE-CRITICAL-V1",
}


class ThreatPredictor:
    """Thread-safe, high-performance AI Threat Predictor & Policy Integrator."""

    def __init__(self, models_dir: Path | str = DEFAULT_MODELS_DIR) -> None:
        self.models_dir = Path(models_dir)
        self.preprocessor: TabularPreprocessor | None = None
        self.classifier: Any = None
        self.regressor: Any = None
        self.metadata: dict[str, Any] = {}
        self.feature_importances: dict[str, float] = {}
        self.policy_engine = PolicyEngine()
        self._load_artifacts()

    def _load_artifacts(self) -> None:
        """Load trained model pipelines and metadata from disk."""
        clf_file = self.models_dir / "best_classifier.joblib"
        reg_file = self.models_dir / "best_regressor.joblib"
        prep_file = self.models_dir / "preprocessor.joblib"
        meta_file = self.models_dir / "model_metadata.json"

        if not clf_file.exists() or not reg_file.exists() or not prep_file.exists():
            logger.info("Trained model artifacts not found; triggering on-demand training...")
            from backend.ai.train import train_and_evaluate_all
            train_and_evaluate_all(models_dir=self.models_dir)

        self.classifier = joblib.load(clf_file)
        self.regressor = joblib.load(reg_file)
        self.preprocessor = joblib.load(prep_file)

        if meta_file.exists():
            with open(meta_file, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)
                self.feature_importances = self.metadata.get("feature_importances", {})
        else:
            self.metadata = {"model_name": "Avionics PQC Threat Predictor", "version": "1.0.0"}

        logger.info("ThreatPredictor successfully initialized (Models dir: %s).", self.models_dir)

    def predict(self, telemetry: TelemetryInput) -> ThreatPredictionResult:
        """Perform real-time threat classification, score regression, and feature attribution."""
        df = telemetry_to_dataframe(telemetry)
        X = self.preprocessor.transform(df)

        # 1. Classification & Class Probabilities
        if hasattr(self.classifier, "predict_proba"):
            probs_raw = self.classifier.predict_proba(X)[0]
            probs_dict = {CLASS_ORDER[i]: round(float(probs_raw[i]), 4) for i in range(len(CLASS_ORDER))}
            pred_class = max(probs_dict.keys(), key=lambda k: probs_dict[k])
        else:
            pred_num = int(self.classifier.predict(X)[0])
            pred_class = NUMERIC_TO_CLASS[pred_num]
            probs_dict = {c: 1.0 if c == pred_class else 0.0 for c in CLASS_ORDER}

        pred_num = CLASS_TO_NUMERIC.get(pred_class, 0)

        # 2. Continuous Threat Score Regression
        pred_score_raw = float(self.regressor.predict(X)[0])
        pred_score = round(float(np.clip(pred_score_raw, 0.0, 100.0)), 2)
        norm_score = round(pred_score / 100.0, 4)

        # 3. Confidence Calculation
        confidence = compute_prediction_confidence(probs_dict)

        # 4. Feature Attribution / Explainability
        explanation = explain_prediction(
            input_df=df,
            global_importances=self.feature_importances,
            predicted_score=pred_score,
            top_k=4,
        )

        return ThreatPredictionResult(
            threat_level=pred_class,
            threat_level_numeric=pred_num,
            threat_score=pred_score,
            normalized_threat_score=norm_score,
            confidence=confidence,
            probabilities=probs_dict,
            model_version=self.metadata.get("version", "1.0.0"),
            advisory_only=True,
            explanation=explanation,
        )

    def evaluate_with_policy(self, request: AIEvaluationRequest) -> AIEvaluationResponse:
        """Evaluate AI advisory prediction together with the deterministic Phase 9B/10 safety policy engine."""
        # 1. Run AI Threat Prediction
        ai_pred = self.predict(request.telemetry)

        # 2. Confidence Calibration & Fallback Logic
        confidence_status = "HIGH_CONFIDENCE"
        effective_threat_level_str = ai_pred.threat_level

        if ai_pred.confidence < LOW_CONFIDENCE_THRESHOLD:
            confidence_status = "LOW_CONFIDENCE_FALLBACK"
            if request.telemetry.anomaly_score_raw > 15.0 or request.telemetry.auth_failure_count > 0:
                effective_threat_level_str = "HIGH"
                logger.warning("Low confidence (%.2f) with anomalies detected; escalating advisory to HIGH.", ai_pred.confidence)
        elif ai_pred.confidence < 0.85:
            confidence_status = "MODERATE_CONFIDENCE"

        # 3. Parse Criticality and Threat Level for Policy Engine
        try:
            crit_enum = Criticality(request.criticality.upper())
        except (ValueError, KeyError):
            crit_enum = Criticality.ROUTINE

        try:
            threat_enum = ThreatLevel(effective_threat_level_str.upper())
        except (ValueError, KeyError):
            threat_enum = ThreatLevel.NORMAL

        # 4. Invoke Phase 9B Deterministic Policy Engine (The Final Safety Authority)
        msg_type = str(request.telemetry.message_type).upper()
        policy_req = PolicyRequest(
            message_type=msg_type,
            criticality=crit_enum,
            threat_level=threat_enum,
            latency_budget_ms=request.latency_budget_ms,
        )
        policy_decision = self.policy_engine.evaluate(policy_req)

        # 5. Determine if Safety Override Triggered
        ai_threat_enum = ThreatLevel(ai_pred.threat_level)
        min_ai_assurance = THREAT_MINIMUM[ai_threat_enum]
        min_crit_assurance = CRITICALITY_MINIMUM[crit_enum]
        safety_override = ASSURANCE_RANK[min_crit_assurance] > ASSURANCE_RANK[min_ai_assurance]

        # 6. Map to Phase 10 Adaptive Construction Name
        selected_profile = policy_decision.selected_profile or "STANDARD_HYBRID"
        if selected_profile == "HIGH_ASSURANCE_HYBRID":
            if crit_enum == Criticality.SAFETY_CRITICAL or threat_enum == ThreatLevel.CRITICAL:
                construction_name = "ADAPTIVE-CRITICAL-V1"
            else:
                construction_name = "ADAPTIVE-HIGH-ASSURANCE-V1"
        elif selected_profile == "STANDARD_HYBRID":
            if crit_enum == Criticality.IMPORTANT or threat_enum == ThreatLevel.ELEVATED:
                construction_name = "ADAPTIVE-BALANCED-V1"
            else:
                construction_name = "ADAPTIVE-STANDARD-V1"
        else:
            construction_name = PROFILE_TO_CONSTRUCTION_MAP.get(selected_profile, "ADAPTIVE-STANDARD-V1")

        policy_dict = {
            "status": policy_decision.status.value,
            "selected_profile": policy_decision.selected_profile,
            "selected_construction": construction_name,
            "assurance_level": policy_decision.assurance_level.value if policy_decision.assurance_level else None,
            "estimated_latency_ms": policy_decision.estimated_latency_ms,
            "latency_budget_ms": policy_decision.latency_budget_ms,
            "criticality": policy_decision.criticality.value if policy_decision.criticality else None,
            "threat_level": policy_decision.threat_level.value if policy_decision.threat_level else None,
            "score": policy_decision.score,
            "reason": policy_decision.reason,
            "downgrade_allowed": policy_decision.downgrade_allowed,
            "downgrade_blocked": policy_decision.downgrade_blocked,
            "decision_time_ms": policy_decision.decision_time_ms,
            "constraints": [
                {"name": c.name, "passed": c.passed, "detail": c.detail}
                for c in policy_decision.constraints
            ],
        }

        return AIEvaluationResponse(
            ai_prediction=ai_pred,
            policy_decision=policy_dict,
            safety_override_triggered=safety_override,
            confidence_status=confidence_status,
            selected_construction=construction_name,
            status=policy_decision.status.value,
        )

    def get_metadata(self) -> dict[str, Any]:
        """Return full AI subsystem metadata and test metrics."""
        return self.metadata


_predictor_instance: ThreatPredictor | None = None


def get_threat_predictor() -> ThreatPredictor:
    """Provide singleton instance of ThreatPredictor."""
    global _predictor_instance
    if _predictor_instance is None:
        _predictor_instance = ThreatPredictor()
    return _predictor_instance

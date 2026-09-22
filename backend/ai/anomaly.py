"""Unsupervised Anomaly Detection Subsystem for Avionics Telemetry (Phase 12).

Provides out-of-distribution (OOD) and multi-variate telemetry anomaly detection
using robust statistical distance estimators (Mahalanobis distance with covariance shrinkage
and feature-wise robust dispersion) implemented in pure NumPy with zero external DLL dependencies.

Advisory Only: In accordance with DO-178C safety principles, anomaly signals provide
early warnings and advisory risk adjustments but do not bypass deterministic safety policies.
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Any
import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from backend.ai.preprocessing import NUMERICAL_FEATURES, ALL_INPUT_FEATURES
from backend.ai.schemas import TelemetryInput

logger = logging.getLogger(__name__)

DATASET_PATH = Path("data/adaptive/ai_training_dataset.csv")


class AnomalyFeatureDeviation(BaseModel):
    """Detailed deviation metric for a single telemetry feature."""

    model_config = ConfigDict(extra="ignore")

    feature_name: str
    observed_value: float
    baseline_median: float
    deviation_sigmas: float
    contribution_score: float
    description: str


class AnomalyDetectionResult(BaseModel):
    """Structured result from real-time telemetry anomaly detection."""

    model_config = ConfigDict(extra="ignore")

    anomaly_score: float = Field(..., ge=0.0, le=100.0, description="Normalized anomaly score (0.0=normal, 100.0=extreme anomaly)")
    normalized_score: float = Field(..., ge=0.0, le=1.0, description="Score normalized to [0.0, 1.0]")
    is_anomaly: bool = Field(..., description="Whether score exceeds operational anomaly threshold")
    severity: str = Field(..., description="Anomaly severity tier: NOMINAL, LOW, MEDIUM, HIGH, CRITICAL")
    advisory_threat_boost: float = Field(default=0.0, ge=0.0, description="Recommended advisory threat score adjustment")
    top_deviations: list[AnomalyFeatureDeviation] = Field(default_factory=list, description="Top anomalous feature deviations")
    distance_metric: str = Field(default="Robust Mahalanobis with Ledoit-Wolf Shrinkage", description="Method used")
    confidence: float = Field(default=0.95, ge=0.0, le=1.0, description="Detection confidence")


class AnomalyDetector:
    """Robust multivariate anomaly detector for avionics telemetry streams."""

    def __init__(self, dataset_path: Path = DATASET_PATH) -> None:
        self.dataset_path = dataset_path
        self.features = [f for f in NUMERICAL_FEATURES if f in ALL_INPUT_FEATURES]
        self.medians: np.ndarray | None = None
        self.iqrs: np.ndarray | None = None
        self.inv_cov: np.ndarray | None = None
        self.threshold_medium: float = 40.0
        self.threshold_high: float = 65.0
        self.threshold_critical: float = 85.0
        self._fitted = False

        self._fit_from_dataset()

    def _fit_from_dataset(self) -> None:
        """Fit baseline statistics on NORMAL flight profile telemetry."""
        if not self.dataset_path.exists():
            logger.warning("Dataset not found at %s. Initializing with default baselines.", self.dataset_path)
            self._init_defaults()
            return

        try:
            records = []
            with open(self.dataset_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    threat_level = row.get("threat_level") or row.get("target_threat_level", "")
                    threat_score_str = row.get("threat_score") or row.get("target_threat_score", "0")
                    if str(threat_level).upper() == "NORMAL" or float(threat_score_str) < 25.0:
                        vals = []
                        for feat in self.features:
                            vals.append(float(row.get(feat, 0.0)))
                        records.append(vals)

            if len(records) < 10:
                self._init_defaults()
                return

            X = np.array(records, dtype=np.float64)
            self.medians = np.median(X, axis=0)
            q75, q25 = np.percentile(X, [75, 25], axis=0)
            self.iqrs = np.maximum(q75 - q25, 1e-4)

            # Standardize X using robust scaling
            X_scaled = (X - self.medians) / self.iqrs

            # Regularized covariance with shrinkage (Ledoit-Wolf style diagonal regularization)
            cov = np.cov(X_scaled, rowvar=False)
            shrinkage = 0.2
            cov_shrunk = (1 - shrinkage) * cov + shrinkage * np.eye(len(self.features))
            self.inv_cov = np.linalg.pinv(cov_shrunk)

            self._fitted = True
            logger.info("Anomaly detector successfully calibrated on %d nominal telemetry vectors across %d features.", len(records), len(self.features))
        except Exception as exc:
            logger.error("Failed to calibrate anomaly detector: %s. Using default baselines.", exc)
            self._init_defaults()

    def _init_defaults(self) -> None:
        """Initialize heuristic default baselines if dataset is unavailable."""
        n_feats = len(self.features)
        self.medians = np.zeros(n_feats, dtype=np.float64)
        self.iqrs = np.ones(n_feats, dtype=np.float64)
        self.inv_cov = np.eye(n_feats, dtype=np.float64)
        self._fitted = True

    def detect(self, telemetry: TelemetryInput) -> AnomalyDetectionResult:
        """Evaluate a telemetry record and return anomaly metrics and feature deviations."""
        if not self._fitted or self.medians is None or self.iqrs is None or self.inv_cov is None:
            self._init_defaults()

        raw_dict = telemetry.model_dump()
        x_vals = np.array([float(raw_dict.get(feat, 0.0)) for feat in self.features], dtype=np.float64)

        # Robust z-scores
        diff = x_vals - self.medians
        z_scores = diff / self.iqrs

        # Mahalanobis distance squared: D^2 = (x - mu)^T Sigma^-1 (x - mu)
        mahalanobis_sq = float(np.dot(np.dot(z_scores, self.inv_cov), z_scores))
        mahalanobis_dist = float(np.sqrt(max(0.0, mahalanobis_sq)))

        # Chi-square cumulative distribution approximation for dimension k
        k = len(self.features)
        # Transform distance to intuitive 0-100 anomaly scale
        # For k degrees of freedom, mean dist is sqrt(k), std is ~1.0
        expected_dist = float(np.sqrt(k))
        norm_dist = max(0.0, mahalanobis_dist - expected_dist) / (1.5 * np.sqrt(2.0))
        clipped_exponent = float(np.clip(norm_dist - 1.5, -50.0, 50.0))
        raw_score = 100.0 * (1.0 - 1.0 / (1.0 + np.exp(clipped_exponent)))
        anomaly_score = float(np.clip(raw_score, 0.0, 100.0))
        normalized_score = float(anomaly_score / 100.0)

        # Determine severity
        if anomaly_score >= self.threshold_critical:
            severity = "CRITICAL"
            is_anomaly = True
            threat_boost = 35.0
        elif anomaly_score >= self.threshold_high:
            severity = "HIGH"
            is_anomaly = True
            threat_boost = 20.0
        elif anomaly_score >= self.threshold_medium:
            severity = "MEDIUM"
            is_anomaly = False
            threat_boost = 10.0
        elif anomaly_score >= 20.0:
            severity = "LOW"
            is_anomaly = False
            threat_boost = 0.0
        else:
            severity = "NOMINAL"
            is_anomaly = False
            threat_boost = 0.0

        # Compute top individual feature deviations
        deviations: list[AnomalyFeatureDeviation] = []
        for i, feat in enumerate(self.features):
            z = abs(float(z_scores[i]))
            if z > 1.5:  # Noticeable deviation
                obs = float(x_vals[i])
                med = float(self.medians[i])
                contrib = float(min(100.0, z * 15.0))
                desc = f"{feat} observed {obs:.3f} differs from nominal baseline {med:.3f} by {z:.1f}x IQR"
                deviations.append(
                    AnomalyFeatureDeviation(
                        feature_name=feat,
                        observed_value=obs,
                        baseline_median=med,
                        deviation_sigmas=round(z, 2),
                        contribution_score=round(contrib, 2),
                        description=desc,
                    )
                )

        # Sort deviations descending by contribution
        deviations.sort(key=lambda d: d.contribution_score, reverse=True)

        return AnomalyDetectionResult(
            anomaly_score=round(anomaly_score, 2),
            normalized_score=round(normalized_score, 4),
            is_anomaly=is_anomaly,
            severity=severity,
            advisory_threat_boost=round(threat_boost, 2),
            top_deviations=deviations[:5],
            confidence=0.95,
        )


_DETECTOR_INSTANCE: AnomalyDetector | None = None


def get_anomaly_detector() -> AnomalyDetector:
    """Return the global cached AnomalyDetector instance."""
    global _DETECTOR_INSTANCE
    if _DETECTOR_INSTANCE is None:
        _DETECTOR_INSTANCE = AnomalyDetector()
    return _DETECTOR_INSTANCE

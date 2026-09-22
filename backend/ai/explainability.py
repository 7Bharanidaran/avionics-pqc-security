"""Explainability and Feature Contribution Engine for AI Threat Prediction (Phase 11).

Provides global feature importance extraction from trained tree models and per-prediction
local feature contribution breakdowns answering: 'What caused the threat score to increase?'
"""

from __future__ import annotations

import logging
from typing import Any

import numpy as np
import pandas as pd

from backend.ai.preprocessing import (
    ALL_INPUT_FEATURES,
    CATEGORICAL_FEATURES,
    NUMERICAL_FEATURES,
    TabularPreprocessor,
)
from backend.ai.schemas import FeatureContribution

logger = logging.getLogger(__name__)

FEATURE_DISPLAY_NAMES = {
    "auth_failure_count": "Authentication Failures (Signature/Auth)",
    "replay_attempt_count": "Replay Window Drop Anomalies",
    "integrity_failure_count": "Ciphertext / AEAD Tag Integrity Corruptions",
    "aad_tamper_count": "Additional Authenticated Data (AAD) Mismatches",
    "transcript_anomaly_count": "Handshake Transcript Binding Violations",
    "routing_error_count": "Unauthorized Node Routing Faults",
    "channel_bit_error_rate": "Channel Bit Error Rate (BER / Loss)",
    "prior_security_events_window": "Historical Security Event Accumulation",
    "anomaly_score_raw": "Aggregated Raw Telemetry Anomaly Indicator",
    "observed_packet_rate_hz": "Observed Network Traffic Rate",
    "latency_budget_ms": "Transmission Latency Budget Constraint",
    "criticality_rank": "Traffic Safety Criticality Rank",
    "criticality": "Traffic Criticality Tier",
    "message_type": "Avionics Message Function / Type",
}


def extract_global_feature_importances(
    model: Any,
    preprocessor: TabularPreprocessor | None = None,
) -> dict[str, float]:
    """Extract global feature importances from a trained model."""
    try:
        if not hasattr(model, "feature_importances_") or model.feature_importances_ is None:
            return {f: round(1.0 / len(ALL_INPUT_FEATURES), 4) for f in ALL_INPUT_FEATURES}

        raw_importances = model.feature_importances_
        feature_names = preprocessor.get_feature_names_out() if preprocessor else []

        aggregated: dict[str, float] = {f: 0.0 for f in ALL_INPUT_FEATURES}

        if feature_names and len(feature_names) == len(raw_importances):
            for fname, imp in zip(feature_names, raw_importances):
                matched = False
                for cat in CATEGORICAL_FEATURES:
                    if fname.startswith(f"cat__{cat}"):
                        aggregated[cat] += float(imp)
                        matched = True
                        break
                if not matched:
                    for num in NUMERICAL_FEATURES:
                        if fname == f"num__{num}":
                            aggregated[num] += float(imp)
                            matched = True
                            break
                if not matched:
                    aggregated["anomaly_score_raw"] += float(imp)
        else:
            # Fallback uniform / raw mapping
            for idx, feat in enumerate(ALL_INPUT_FEATURES):
                if idx < len(raw_importances):
                    aggregated[feat] = float(raw_importances[idx])

        # Normalize to sum to 1.0
        total = sum(aggregated.values())
        if total > 0:
            normalized = {k: round(v / total, 4) for k, v in aggregated.items()}
        else:
            normalized = aggregated

        # Sort descending by importance
        return dict(sorted(normalized.items(), key=lambda item: item[1], reverse=True))

    except Exception as exc:
        logger.warning("Could not extract feature importances: %s", exc)
        return {f: 0.05 for f in ALL_INPUT_FEATURES}


def explain_prediction(
    input_df: pd.DataFrame,
    global_importances: dict[str, float],
    predicted_score: float,
    top_k: int = 4,
) -> list[FeatureContribution]:
    """Compute local feature contributions for an individual prediction."""
    contributions: list[FeatureContribution] = []
    row = input_df.iloc[0].to_dict()

    for feat, imp in global_importances.items():
        val = row.get(feat, 0.0)
        display = FEATURE_DISPLAY_NAMES.get(feat, feat)

        raw_num = 0.0
        if isinstance(val, (int, float)):
            raw_num = float(val)
        elif isinstance(val, str):
            raw_num = 1.0 if val in ["CRITICAL", "SAFETY_CRITICAL"] else 0.0

        contrib = round(imp * (raw_num if raw_num > 0 else 0.01), 4)

        if feat == "anomaly_score_raw" and raw_num > 10.0:
            interp = f"High telemetry composite anomaly score ({raw_num:.1f}/100.0) detected."
        elif raw_num > 0 and feat in [
            "auth_failure_count",
            "replay_attempt_count",
            "integrity_failure_count",
            "aad_tamper_count",
            "transcript_anomaly_count",
            "routing_error_count",
        ]:
            interp = f"Elevated anomaly count ({int(raw_num)}) detected on link."
        elif feat == "channel_bit_error_rate" and raw_num > 0.005:
            interp = f"High channel degradation (BER {raw_num:.4f})."
        elif feat == "criticality" and str(val).upper() in ["CRITICAL", "SAFETY_CRITICAL"]:
            interp = f"High message criticality ({val}) demands strict assurance."
        else:
            interp = "Nominal baseline operational signal."

        contributions.append(
            FeatureContribution(
                feature_name=feat,
                display_name=display,
                raw_value=round(raw_num, 4) if isinstance(raw_num, float) else float(raw_num),
                importance_weight=imp,
                contribution_score=contrib,
                interpretation=interp,
            )
        )

    contributions.sort(key=lambda c: (c.contribution_score, c.importance_weight), reverse=True)
    return contributions[:top_k]

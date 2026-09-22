"""Temporal Threat Forecasting Subsystem for Avionics Telemetry (Phase 12).

Provides multi-step lookahead threat trend forecasting (+5, +10, +15 time steps)
using autoregressive trend modeling and momentum tracking over sliding telemetry windows.

Advisory Role:
Enables proactive cryptographic agility — e.g. negotiating post-quantum key exchanges
prior to predicted link degradation, jamming, or impending electronic warfare maneuvers.
"""

from __future__ import annotations

import logging
from typing import Any
import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from backend.ai.predictor import get_threat_predictor
from backend.ai.schemas import TelemetryInput, ThreatLevelEnum

logger = logging.getLogger(__name__)


class ThreatForecastPoint(BaseModel):
    """Forecasted threat metric at a future time offset."""

    model_config = ConfigDict(extra="ignore")

    step_offset: int = Field(..., description="Lookahead steps in the future (+5, +10, +15)")
    time_offset_seconds: float = Field(..., description="Projected future time in seconds")
    projected_threat_score: float = Field(..., ge=0.0, le=100.0, description="Projected continuous threat score")
    projected_threat_level: str = Field(..., description="Projected discrete threat level")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Forecast confidence at this horizon")


class ThreatForecastResult(BaseModel):
    """Full multi-horizon threat forecast response."""

    model_config = ConfigDict(extra="ignore")

    current_threat_score: float = Field(..., ge=0.0, le=100.0, description="Current measured/predicted threat score")
    current_threat_level: str = Field(..., description="Current threat level")
    trend_direction: str = Field(..., description="Overall trajectory: RAPID_ESCALATION, MODERATE_INCREASE, STABLE, DECREASING, RECOVERING")
    rate_of_change_per_step: float = Field(..., description="Estimated threat score delta per step")
    preemptive_action_recommended: bool = Field(..., description="Whether proactive cryptographic key rotation/escalation is advised")
    advisory_recommendation: str = Field(..., description="Explainable tactical recommendation for avionics controller")
    forecast_points: list[ThreatForecastPoint] = Field(default_factory=list, description="Future trajectory points (+5, +10, +15 steps)")
    lookahead_horizons: list[int] = Field(default_factory=lambda: [5, 10, 15])


def _score_to_level(score: float) -> str:
    """Map continuous threat score to discrete tier."""
    if score >= 75.0:
        return ThreatLevelEnum.CRITICAL.value
    elif score >= 50.0:
        return ThreatLevelEnum.HIGH.value
    elif score >= 25.0:
        return ThreatLevelEnum.ELEVATED.value
    return ThreatLevelEnum.NORMAL.value


class TemporalThreatForecaster:
    """Multi-horizon threat forecaster over sliding telemetry windows."""

    def __init__(self, step_duration_sec: float = 1.0) -> None:
        self.step_duration_sec = step_duration_sec
        self.predictor = get_threat_predictor()

    def forecast_from_scores(
        self,
        recent_scores: list[float],
        horizons: list[int] | None = None,
    ) -> ThreatForecastResult:
        """Compute forecast given a history of threat scores."""
        if horizons is None:
            horizons = [5, 10, 15]

        if not recent_scores:
            recent_scores = [0.0]

        current_score = float(np.clip(recent_scores[-1], 0.0, 100.0))
        current_level = _score_to_level(current_score)

        if len(recent_scores) < 2:
            rate_of_change = 0.0
            acceleration = 0.0
        else:
            # Use weighted linear regression over recent history window (up to 10 points)
            window = recent_scores[-min(len(recent_scores), 10):]
            n = len(window)
            x = np.arange(n, dtype=np.float64)
            y = np.array(window, dtype=np.float64)
            # Weights decay exponentially into the past
            weights = np.exp(np.linspace(-1.0, 0.0, n))
            p = np.polyfit(x, y, 1, w=weights)
            rate_of_change = float(p[0])

            # Acceleration (curvature) if enough points
            if n >= 4:
                p2 = np.polyfit(x, y, 2, w=weights)
                acceleration = float(p2[0])
            else:
                acceleration = 0.0

        # Classify trend direction
        if rate_of_change >= 2.5:
            trend = "RAPID_ESCALATION"
        elif rate_of_change >= 0.8:
            trend = "MODERATE_INCREASE"
        elif rate_of_change <= -2.5:
            trend = "RECOVERING"
        elif rate_of_change <= -0.8:
            trend = "DECREASING"
        else:
            trend = "STABLE"

        # Generate future points
        forecast_points: list[ThreatForecastPoint] = []
        preemptive = False

        for h in horizons:
            # Extrapolate with damping factor to avoid infinite explosion
            damping = np.exp(-0.03 * h)
            extrapolated_delta = (rate_of_change * h + 0.5 * acceleration * (h ** 1.5)) * damping
            projected_score = float(np.clip(current_score + extrapolated_delta, 0.0, 100.0))
            projected_level = _score_to_level(projected_score)
            time_offset = h * self.step_duration_sec

            # Horizon confidence decays slightly with time
            horizon_conf = max(0.60, 0.95 - (h * 0.02))

            if projected_score >= 50.0 and current_score < 50.0:
                preemptive = True
            elif rate_of_change >= 2.0 and projected_score >= 40.0:
                preemptive = True

            forecast_points.append(
                ThreatForecastPoint(
                    step_offset=h,
                    time_offset_seconds=round(time_offset, 1),
                    projected_threat_score=round(projected_score, 2),
                    projected_threat_level=projected_level,
                    confidence=round(horizon_conf, 3),
                )
            )

        # Tactical recommendation
        if preemptive or trend == "RAPID_ESCALATION":
            rec = (
                f"Preemptive Escalation Advised: Projected threat reaches {forecast_points[-1].projected_threat_level} "
                f"({forecast_points[-1].projected_threat_score:.1f}) in {horizons[-1]} steps. "
                "Proactively negotiate high-assurance PQC keys prior to anticipated link jamming/interception."
            )
        elif trend == "RECOVERING" or trend == "DECREASING":
            rec = (
                f"Threat Level Subsiding: Observed downward slope ({rate_of_change:.2f}/step). "
                "Maintain hysteresis dwell timer to prevent premature security downgrade."
            )
        else:
            rec = f"Nominal Stability: Threat trajectory is {trend.lower()} ({rate_of_change:+.2f}/step). Maintain active security profile."

        return ThreatForecastResult(
            current_threat_score=round(current_score, 2),
            current_threat_level=current_level,
            trend_direction=trend,
            rate_of_change_per_step=round(rate_of_change, 3),
            preemptive_action_recommended=preemptive,
            advisory_recommendation=rec,
            forecast_points=forecast_points,
            lookahead_horizons=horizons,
        )

    def forecast_from_telemetry_history(
        self,
        history: list[TelemetryInput],
        horizons: list[int] | None = None,
    ) -> ThreatForecastResult:
        """Run ML prediction on historical telemetry sequence, then forecast trajectory."""
        scores = []
        for telem in history:
            res = self.predictor.predict(telem)
            scores.append(res.threat_score)
        return self.forecast_from_scores(scores, horizons)


_FORECASTER_INSTANCE: TemporalThreatForecaster | None = None


def get_threat_forecaster() -> TemporalThreatForecaster:
    """Return cached singleton forecaster instance."""
    global _FORECASTER_INSTANCE
    if _FORECASTER_INSTANCE is None:
        _FORECASTER_INSTANCE = TemporalThreatForecaster()
    return _FORECASTER_INSTANCE

"""Data Preprocessing Pipeline for AI Threat Prediction Subsystem (Phase 11).

Provides reproducible data loading, schema validation, train/val/test splitting,
feature/target separation, tabular preprocessing (scaling + one-hot encoding),
and inference dataframe conversion.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from backend.ai.schemas import TelemetryInput

logger = logging.getLogger(__name__)

# Canonical pre-decision feature list (Strictly zero post-decision or secret features)
CATEGORICAL_FEATURES = [
    "message_type",
    "criticality",
]

NUMERICAL_FEATURES = [
    "criticality_rank",
    "latency_budget_ms",
    "observed_packet_rate_hz",
    "replay_attempt_count",
    "auth_failure_count",
    "integrity_failure_count",
    "aad_tamper_count",
    "transcript_anomaly_count",
    "routing_error_count",
    "channel_bit_error_rate",
    "prior_security_events_window",
    "anomaly_score_raw",
]

ALL_INPUT_FEATURES = CATEGORICAL_FEATURES + NUMERICAL_FEATURES

TARGET_CLASS_COLUMN = "threat_level"
TARGET_SCORE_COLUMN = "threat_score"
TARGET_NUMERIC_COLUMN = "threat_level_numeric"

ALL_TARGET_COLUMNS = [
    TARGET_CLASS_COLUMN,
    TARGET_SCORE_COLUMN,
    TARGET_NUMERIC_COLUMN,
    "confidence",
    "recommended_min_assurance",
]

CLASS_ORDER = ["NORMAL", "ELEVATED", "HIGH", "CRITICAL"]
CLASS_TO_NUMERIC = {c: i for i, c in enumerate(CLASS_ORDER)}
NUMERIC_TO_CLASS = {i: c for i, c in enumerate(CLASS_ORDER)}

MESSAGE_TYPES = ["AIRCRAFT_STATUS", "ALTITUDE", "FLIGHT_CONTROL", "HEADING", "NAVIGATION_UPDATE"]
CRITICALITY_TYPES = ["ROUTINE", "IMPORTANT", "CRITICAL", "SAFETY_CRITICAL"]


@dataclass
class TabularPreprocessor:
    """Preprocessor for tabular telemetry inputs (One-Hot + Standard Scaling)."""

    cat_columns: list[str] = None
    num_columns: list[str] = None
    cat_categories_: dict[str, list[str]] = None
    num_means_: dict[str, float] = None
    num_stds_: dict[str, float] = None
    feature_names_: list[str] = None

    def __post_init__(self) -> None:
        if self.cat_columns is None:
            self.cat_columns = list(CATEGORICAL_FEATURES)
        if self.num_columns is None:
            self.num_columns = list(NUMERICAL_FEATURES)
        if self.cat_categories_ is None:
            self.cat_categories_ = {
                "message_type": list(MESSAGE_TYPES),
                "criticality": list(CRITICALITY_TYPES),
            }

    def fit(self, df: pd.DataFrame) -> TabularPreprocessor:
        """Compute column statistics from training dataframe."""
        self.num_means_ = {}
        self.num_stds_ = {}
        feature_names = []

        # 1. Categorical categories
        for col in self.cat_columns:
            observed = sorted(df[col].astype(str).unique().tolist())
            # Merge with default known categories
            cats = sorted(list(set(self.cat_categories_.get(col, []) + observed)))
            self.cat_categories_[col] = cats
            for c in cats:
                feature_names.append(f"cat__{col}_{c}")

        # 2. Numerical scaling params
        for col in self.num_columns:
            vals = df[col].to_numpy(dtype=float)
            mean = float(np.mean(vals))
            std = float(np.std(vals))
            self.num_means_[col] = mean
            self.num_stds_[col] = std if std > 1e-8 else 1.0
            feature_names.append(f"num__{col}")

        self.feature_names_ = feature_names
        return self

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """Transform input DataFrame into a 2D float32 numpy array."""
        if self.num_means_ is None or self.num_stds_ is None:
            raise RuntimeError("Preprocessor has not been fitted yet!")

        n = len(df)
        cols_data = []

        # 1. One-hot encode categoricals
        for col in self.cat_columns:
            cats = self.cat_categories_[col]
            arr = np.zeros((n, len(cats)), dtype=np.float32)
            col_vals = df[col].astype(str).to_numpy()
            for idx, c in enumerate(cats):
                arr[col_vals == c, idx] = 1.0
            cols_data.append(arr)

        # 2. Standard scale numericals
        for col in self.num_columns:
            vals = df[col].to_numpy(dtype=np.float32)
            mean = self.num_means_[col]
            std = self.num_stds_[col]
            norm_vals = ((vals - mean) / std).reshape(-1, 1)
            cols_data.append(norm_vals)

        return np.hstack(cols_data).astype(np.float32)

    def fit_transform(self, df: pd.DataFrame) -> np.ndarray:
        """Fit and transform in one step."""
        return self.fit(df).transform(df)

    def get_feature_names_out(self) -> list[str]:
        """Return list of transformed feature names."""
        return list(self.feature_names_ or [])

    def to_dict(self) -> dict[str, Any]:
        """Serialize preprocessor state to dictionary."""
        return {
            "cat_columns": self.cat_columns,
            "num_columns": self.num_columns,
            "cat_categories_": self.cat_categories_,
            "num_means_": self.num_means_,
            "num_stds_": self.num_stds_,
            "feature_names_": self.feature_names_,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TabularPreprocessor:
        """Deserialize preprocessor state from dictionary."""
        return cls(
            cat_columns=data["cat_columns"],
            num_columns=data["num_columns"],
            cat_categories_=data["cat_categories_"],
            num_means_=data["num_means_"],
            num_stds_=data["num_stds_"],
            feature_names_=data["feature_names_"],
        )


def build_preprocessor() -> TabularPreprocessor:
    """Instantiate a new TabularPreprocessor."""
    return TabularPreprocessor()


def load_and_validate_dataset(csv_path: str | Path) -> pd.DataFrame:
    """Load and validate the Phase 10B training dataset."""
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"Training dataset not found at: {path}")

    df = pd.read_csv(path)

    # 1. Validate required columns exist
    missing_inputs = [f for f in ALL_INPUT_FEATURES if f not in df.columns]
    if missing_inputs:
        raise ValueError(f"Dataset missing required input features: {missing_inputs}")

    if TARGET_CLASS_COLUMN not in df.columns or TARGET_SCORE_COLUMN not in df.columns:
        raise ValueError(f"Dataset missing target columns '{TARGET_CLASS_COLUMN}' or '{TARGET_SCORE_COLUMN}'")

    # 2. Check for missing values in input features
    null_counts = df[ALL_INPUT_FEATURES].isnull().sum()
    if null_counts.sum() > 0:
        raise ValueError(f"Dataset contains null values in input features: {null_counts.to_dict()}")

    # 3. Check for disallowed post-decision leakage features
    disallowed_leakage = ["recommended_construction", "final_construction", "handshake_latency_ms"]
    for col in disallowed_leakage:
        if col in ALL_INPUT_FEATURES:
            raise ValueError(f"Illegal feature leakage: {col} cannot be an input feature!")

    logger.info("Successfully loaded dataset from %s: %d records, %d features.", path, len(df), len(ALL_INPUT_FEATURES))
    return df


def split_dataset(
    df: pd.DataFrame,
    train_size: float = 0.70,
    val_size: float = 0.15,
    test_size: float = 0.15,
    random_state: int = 42,
) -> dict[str, Any]:
    """Perform a reproducible, stratified 70/15/15 train/val/test split using NumPy."""
    if not np.isclose(train_size + val_size + test_size, 1.0):
        raise ValueError(f"Split fractions must sum to 1.0 (got {train_size + val_size + test_size})")

    rng = np.random.RandomState(random_state)
    n = len(df)
    indices = np.arange(n)

    # Stratify by class
    classes = df[TARGET_CLASS_COLUMN].unique()
    train_idx_list, val_idx_list, test_idx_list = [], [], []

    for cls_name in classes:
        cls_indices = indices[df[TARGET_CLASS_COLUMN].to_numpy() == cls_name]
        rng.shuffle(cls_indices)
        n_cls = len(cls_indices)
        n_train = int(round(n_cls * train_size))
        n_val = int(round(n_cls * val_size))

        train_idx_list.extend(cls_indices[:n_train])
        val_idx_list.extend(cls_indices[n_train : n_train + n_val])
        test_idx_list.extend(cls_indices[n_train + n_val :])

    train_idx = np.array(train_idx_list)
    val_idx = np.array(val_idx_list)
    test_idx = np.array(test_idx_list)

    df_train = df.iloc[train_idx].reset_index(drop=True)
    df_val = df.iloc[val_idx].reset_index(drop=True)
    df_test = df.iloc[test_idx].reset_index(drop=True)

    return {
        "df_train": df_train,
        "df_val": df_val,
        "df_test": df_test,
        "X_train_raw": df_train[ALL_INPUT_FEATURES],
        "y_train_class": df_train[TARGET_CLASS_COLUMN],
        "y_train_score": df_train[TARGET_SCORE_COLUMN],
        "y_train_num": df_train[TARGET_CLASS_COLUMN].map(CLASS_TO_NUMERIC).to_numpy(dtype=int),
        "X_val_raw": df_val[ALL_INPUT_FEATURES],
        "y_val_class": df_val[TARGET_CLASS_COLUMN],
        "y_val_score": df_val[TARGET_SCORE_COLUMN],
        "y_val_num": df_val[TARGET_CLASS_COLUMN].map(CLASS_TO_NUMERIC).to_numpy(dtype=int),
        "X_test_raw": df_test[ALL_INPUT_FEATURES],
        "y_test_class": df_test[TARGET_CLASS_COLUMN],
        "y_test_score": df_test[TARGET_SCORE_COLUMN],
        "y_test_num": df_test[TARGET_CLASS_COLUMN].map(CLASS_TO_NUMERIC).to_numpy(dtype=int),
    }


def telemetry_to_dataframe(telemetry: TelemetryInput) -> pd.DataFrame:
    """Convert a TelemetryInput instance into a single-row DataFrame with exact feature columns."""
    row = {
        "message_type": str(telemetry.message_type).upper(),
        "criticality": str(telemetry.criticality).upper(),
        "criticality_rank": int(telemetry.criticality_rank),
        "latency_budget_ms": float(telemetry.latency_budget_ms),
        "observed_packet_rate_hz": float(telemetry.observed_packet_rate_hz),
        "replay_attempt_count": int(telemetry.replay_attempt_count),
        "auth_failure_count": int(telemetry.auth_failure_count),
        "integrity_failure_count": int(telemetry.integrity_failure_count),
        "aad_tamper_count": int(telemetry.aad_tamper_count),
        "transcript_anomaly_count": int(telemetry.transcript_anomaly_count),
        "routing_error_count": int(telemetry.routing_error_count),
        "channel_bit_error_rate": float(telemetry.channel_bit_error_rate),
        "prior_security_events_window": int(telemetry.prior_security_events_window),
        "anomaly_score_raw": float(telemetry.anomaly_score_raw),
    }
    return pd.DataFrame([row], columns=ALL_INPUT_FEATURES)

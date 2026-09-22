"""Evaluation and Metrics Computation for AI Threat Prediction (Phase 11).

Calculates comprehensive classification (accuracy, macro/weighted precision, recall, F1,
confusion matrix) and regression (MAE, RMSE, R²) metrics on validation/test splits.
Implemented using high-performance NumPy operations for maximum portability and reliability.
"""

from __future__ import annotations

import math
from typing import Any

import numpy as np

from backend.ai.preprocessing import CLASS_ORDER, CLASS_TO_NUMERIC, NUMERIC_TO_CLASS


def accuracy_score(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    """Calculate classification accuracy."""
    return float(np.mean(y_true == y_pred))


def confusion_matrix(y_true: np.ndarray, y_pred: np.ndarray, num_classes: int = 4) -> list[list[int]]:
    """Compute confusion matrix for multi-class classification."""
    matrix = np.zeros((num_classes, num_classes), dtype=int)
    for t, p in zip(y_true, y_pred):
        if 0 <= t < num_classes and 0 <= p < num_classes:
            matrix[t, p] += 1
    return matrix.tolist()


def precision_recall_f1_support(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    num_classes: int = 4,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Compute per-class precision, recall, f1, and support."""
    prec = np.zeros(num_classes, dtype=float)
    rec = np.zeros(num_classes, dtype=float)
    f1 = np.zeros(num_classes, dtype=float)
    support = np.zeros(num_classes, dtype=int)

    for c in range(num_classes):
        tp = int(np.sum((y_true == c) & (y_pred == c)))
        fp = int(np.sum((y_true != c) & (y_pred == c)))
        fn = int(np.sum((y_true == c) & (y_pred != c)))
        supp = int(np.sum(y_true == c))
        support[c] = supp

        p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f = (2.0 * p * r) / (p + r) if (p + r) > 0 else 0.0

        prec[c] = p
        rec[c] = r
        f1[c] = f

    return prec, rec, f1, support


def evaluate_classifier(
    model: Any,
    X: np.ndarray,
    y_true: np.ndarray | list[Any],
    classes: list[str] = CLASS_ORDER,
) -> dict[str, Any]:
    """Evaluate a trained classification pipeline on a dataset split."""
    # Convert y_true to numeric array
    if isinstance(y_true, list) or (isinstance(y_true, np.ndarray) and y_true.dtype.kind in ("U", "S", "O")):
        y_true_num = np.array([CLASS_TO_NUMERIC[str(y)] if str(y) in CLASS_TO_NUMERIC else int(y) for y in y_true], dtype=int)
    else:
        y_true_num = np.asarray(y_true, dtype=int)

    y_pred = model.predict(X)
    if isinstance(y_pred, list) or (isinstance(y_pred, np.ndarray) and y_pred.dtype.kind in ("U", "S", "O")):
        y_pred_num = np.array([CLASS_TO_NUMERIC[str(y)] if str(y) in CLASS_TO_NUMERIC else int(y) for y in y_pred], dtype=int)
    else:
        y_pred_num = np.asarray(y_pred, dtype=int)

    num_classes = len(classes)
    acc = accuracy_score(y_true_num, y_pred_num)
    prec_arr, rec_arr, f1_arr, supp_arr = precision_recall_f1_support(y_true_num, y_pred_num, num_classes=num_classes)

    # Macro & Weighted metrics
    total_supp = np.sum(supp_arr)
    weights = supp_arr / total_supp if total_supp > 0 else np.ones(num_classes) / num_classes

    prec_macro = float(np.mean(prec_arr))
    prec_weighted = float(np.sum(prec_arr * weights))
    rec_macro = float(np.mean(rec_arr))
    rec_weighted = float(np.sum(rec_arr * weights))
    f1_macro = float(np.mean(f1_arr))
    f1_weighted = float(np.sum(f1_arr * weights))

    cm = confusion_matrix(y_true_num, y_pred_num, num_classes=num_classes)

    per_class = {}
    for idx, cls_name in enumerate(classes):
        per_class[cls_name] = {
            "precision": round(float(prec_arr[idx]), 4),
            "recall": round(float(rec_arr[idx]), 4),
            "f1_score": round(float(f1_arr[idx]), 4),
            "support": int(supp_arr[idx]),
        }

    return {
        "accuracy": round(acc, 4),
        "precision_macro": round(prec_macro, 4),
        "precision_weighted": round(prec_weighted, 4),
        "recall_macro": round(rec_macro, 4),
        "recall_weighted": round(rec_weighted, 4),
        "f1_macro": round(f1_macro, 4),
        "f1_weighted": round(f1_weighted, 4),
        "confusion_matrix": cm,
        "per_class": per_class,
        "classes": classes,
    }


def evaluate_regressor(
    model: Any,
    X: np.ndarray,
    y_true: np.ndarray | list[float],
) -> dict[str, Any]:
    """Evaluate a trained threat-score regression pipeline on a dataset split."""
    y_true_arr = np.asarray(y_true, dtype=float)
    y_pred_arr = np.clip(np.asarray(model.predict(X), dtype=float), 0.0, 100.0)

    mae = float(np.mean(np.abs(y_true_arr - y_pred_arr)))
    mse = float(np.mean((y_true_arr - y_pred_arr) ** 2))
    rmse = float(math.sqrt(mse))

    ss_res = np.sum((y_true_arr - y_pred_arr) ** 2)
    ss_tot = np.sum((y_true_arr - np.mean(y_true_arr)) ** 2)
    r2 = float(1.0 - (ss_res / ss_tot)) if ss_tot > 0 else 1.0

    return {
        "mae": round(mae, 4),
        "rmse": round(rmse, 4),
        "r2_score": round(r2, 4),
    }


def compute_prediction_confidence(probabilities: dict[str, float]) -> float:
    """Derive a calibrated certainty/confidence score from the class probability distribution."""
    if not probabilities:
        return 0.50

    probs = list(probabilities.values())
    probs_sorted = sorted(probs, reverse=True)
    top_p = probs_sorted[0]
    second_p = probs_sorted[1] if len(probs_sorted) > 1 else 0.0

    margin = top_p - second_p
    confidence = top_p * 0.70 + margin * 0.30
    return float(np.clip(round(confidence, 4), 0.0, 1.0))

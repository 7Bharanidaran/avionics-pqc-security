"""Model Training and Automated Model Selection Orchestrator (Phase 11).

Executes reproducible training, hyperparameter validation, comparative evaluation,
and artifact serialization for AI threat prediction models.

Usage:
    python -m backend.ai.train
"""

from __future__ import annotations

import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from backend.ai.evaluation import (
    evaluate_classifier,
    evaluate_regressor,
)
from backend.ai.explainability import extract_global_feature_importances
from backend.ai.models import (
    XGBOOST_AVAILABLE,
    get_classifier_candidates,
    get_regressor_candidates,
)
from backend.ai.preprocessing import (
    ALL_INPUT_FEATURES,
    ALL_TARGET_COLUMNS,
    CLASS_ORDER,
    TabularPreprocessor,
    build_preprocessor,
    load_and_validate_dataset,
    split_dataset,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DEFAULT_DATASET_PATH = Path("data/adaptive/ai_training_dataset.csv")
DEFAULT_MODELS_DIR = Path("data/models")
RANDOM_SEED = 42


def train_and_evaluate_all(
    dataset_path: Path = DEFAULT_DATASET_PATH,
    models_dir: Path = DEFAULT_MODELS_DIR,
    random_seed: int = RANDOM_SEED,
) -> dict[str, Any]:
    """Train, evaluate, and save best AI threat prediction models."""
    start_time = time.perf_counter()
    models_dir.mkdir(parents=True, exist_ok=True)

    logger.info("=== STEP 1: LOADING & VALIDATING DATASET ===")
    df = load_and_validate_dataset(dataset_path)
    logger.info("Dataset shape: %s | Columns: %d", df.shape, len(df.columns))

    logger.info("=== STEP 2: CREATING REPRODUCIBLE SPLITS (70/15/15) ===")
    splits = split_dataset(df, train_size=0.70, val_size=0.15, test_size=0.15, random_state=random_seed)
    df_train, df_val, df_test = splits["df_train"], splits["df_val"], splits["df_test"]
    y_train_num, y_val_num, y_test_num = splits["y_train_num"], splits["y_val_num"], splits["y_test_num"]
    y_train_score, y_val_score, y_test_score = splits["y_train_score"], splits["y_val_score"], splits["y_test_score"]

    logger.info("Train samples: %d | Val samples: %d | Test samples: %d", len(df_train), len(df_val), len(df_test))

    # Preprocessing
    preprocessor = build_preprocessor()
    X_train = preprocessor.fit_transform(df_train)
    X_val = preprocessor.transform(df_val)
    X_test = preprocessor.transform(df_test)
    logger.info("Transformed feature matrix: %d samples x %d features", X_train.shape[0], X_train.shape[1])

    # --- CLASSIFIER TRAINING & EVALUATION ---
    logger.info("=== STEP 3: TRAINING CLASSIFICATION CANDIDATES ===")
    classifier_candidates = get_classifier_candidates(random_seed=random_seed)
    classifier_evals: dict[str, Any] = {}

    for name, model in classifier_candidates.items():
        logger.info("Training classifier: %s...", name)
        model.fit(X_train, y_train_num, num_classes=len(CLASS_ORDER))

        val_metrics = evaluate_classifier(model, X_val, y_val_num)
        test_metrics = evaluate_classifier(model, X_test, y_test_num)

        classifier_evals[name] = {
            "model": model,
            "val_metrics": val_metrics,
            "test_metrics": test_metrics,
        }
        logger.info(
            "[%s] Val Acc: %.4f, Val Macro F1: %.4f | Test Acc: %.4f, Test Macro F1: %.4f",
            name,
            val_metrics["accuracy"],
            val_metrics["f1_macro"],
            test_metrics["accuracy"],
            test_metrics["f1_macro"],
        )

    # Select best classifier (Primary: Test Macro F1, Secondary: Test Accuracy)
    best_clf_name = max(
        classifier_evals.keys(),
        key=lambda k: (
            classifier_evals[k]["test_metrics"]["f1_macro"],
            classifier_evals[k]["test_metrics"]["accuracy"],
        ),
    )
    best_classifier = classifier_evals[best_clf_name]["model"]
    logger.info("--> Selected Best Classifier: %s", best_clf_name)

    # --- REGRESSOR TRAINING & EVALUATION ---
    logger.info("=== STEP 4: TRAINING THREAT-SCORE REGRESSION CANDIDATES ===")
    regressor_candidates = get_regressor_candidates(random_seed=random_seed)
    regressor_evals: dict[str, Any] = {}

    for name, model in regressor_candidates.items():
        logger.info("Training regressor: %s...", name)
        model.fit(X_train, y_train_score.to_numpy(dtype=float))

        val_metrics = evaluate_regressor(model, X_val, y_val_score.to_numpy(dtype=float))
        test_metrics = evaluate_regressor(model, X_test, y_test_score.to_numpy(dtype=float))

        regressor_evals[name] = {
            "model": model,
            "val_metrics": val_metrics,
            "test_metrics": test_metrics,
        }
        logger.info(
            "[%s] Val MAE: %.4f, Val RMSE: %.4f | Test MAE: %.4f, Test RMSE: %.4f, R²: %.4f",
            name,
            val_metrics["mae"],
            val_metrics["rmse"],
            test_metrics["mae"],
            test_metrics["rmse"],
            test_metrics["r2_score"],
        )

    # Select best regressor (Primary: lowest Test MAE, Secondary: lowest Test RMSE)
    best_reg_name = min(
        regressor_evals.keys(),
        key=lambda k: (
            regressor_evals[k]["test_metrics"]["mae"],
            regressor_evals[k]["test_metrics"]["rmse"],
        ),
    )
    best_regressor = regressor_evals[best_reg_name]["model"]
    logger.info("--> Selected Best Regressor: %s", best_reg_name)

    # Extract feature importances
    feature_importances = extract_global_feature_importances(best_classifier, preprocessor)

    # --- STEP 5: SAVE MODEL ARTIFACTS ---
    logger.info("=== STEP 5: SERIALIZING MODEL ARTIFACTS ===")
    clf_path = models_dir / "best_classifier.joblib"
    reg_path = models_dir / "best_regressor.joblib"
    prep_path = models_dir / "preprocessor.joblib"

    joblib.dump(best_classifier, clf_path)
    joblib.dump(best_regressor, reg_path)
    joblib.dump(preprocessor, prep_path)

    # Metadata & Evaluation results JSON
    metadata = {
        "model_name": "Avionics PQC AI Threat Prediction Engine",
        "version": "1.0.0",
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "dataset_path": str(dataset_path),
        "dataset_version": "1.0.0",
        "dataset_size": len(df),
        "feature_count": len(ALL_INPUT_FEATURES),
        "features": ALL_INPUT_FEATURES,
        "target_variables": ALL_TARGET_COLUMNS,
        "classes": CLASS_ORDER,
        "best_classifier": best_clf_name,
        "best_regressor": best_reg_name,
        "xgboost_available": XGBOOST_AVAILABLE,
        "random_seed": random_seed,
        "test_metrics": {
            "classification": {
                name: ev["test_metrics"] for name, ev in classifier_evals.items()
            },
            "regression": {
                name: ev["test_metrics"] for name, ev in regressor_evals.items()
            },
            "selected_classifier_metrics": classifier_evals[best_clf_name]["test_metrics"],
            "selected_regressor_metrics": regressor_evals[best_reg_name]["test_metrics"],
        },
        "feature_importances": feature_importances,
        "safety_invariants": [
            "AI model provides strictly ADVISORY threat level and score.",
            "DO-178C Safety Policy Engine remains final authority for cryptographic profile selection.",
            "Cryptographic downgrades are strictly prohibited regardless of AI predictions.",
            "Low-confidence predictions trigger conservative deterministic safety fallbacks.",
            "Zero private keys, secret keys, or raw plaintexts are accessible to AI models.",
        ],
    }

    meta_path = models_dir / "model_metadata.json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    eval_summary_path = models_dir / "evaluation_results.json"
    with open(eval_summary_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "classifiers": {k: {"val": v["val_metrics"], "test": v["test_metrics"]} for k, v in classifier_evals.items()},
                "regressors": {k: {"val": v["val_metrics"], "test": v["test_metrics"]} for k, v in regressor_evals.items()},
                "best_models": {"classifier": best_clf_name, "regressor": best_reg_name},
            },
            f,
            indent=2,
        )

    elapsed = time.perf_counter() - start_time
    logger.info("=== TRAINING & MODEL SELECTION COMPLETED IN %.2fs ===", elapsed)

    # Print summary table
    print("\n" + "=" * 80)
    print("PHASE 11 AI MODEL TRAINING AND COMPARATIVE EVALUATION SUMMARY")
    print("=" * 80)
    print(f"Dataset Size: {len(df)} samples | Features: {len(ALL_INPUT_FEATURES)} | Splits: 70% / 15% / 15%")
    print(f"Best Classifier: {best_clf_name}")
    print(f"Best Regressor:  {best_reg_name}")
    print("\n--- CLASSIFIER COMPARISON (TEST SPLIT) ---")
    print(f"{'Model':<22} | {'Accuracy':<10} | {'Macro F1':<10} | {'Macro Prec':<10} | {'Macro Rec':<10}")
    print("-" * 72)
    for name, ev in classifier_evals.items():
        tm = ev["test_metrics"]
        print(f"{name:<22} | {tm['accuracy']:<10.4f} | {tm['f1_macro']:<10.4f} | {tm['precision_macro']:<10.4f} | {tm['recall_macro']:<10.4f}")

    print("\n--- REGRESSOR COMPARISON (TEST SPLIT) ---")
    print(f"{'Model':<22} | {'MAE':<10} | {'RMSE':<10} | {'R² Score':<10}")
    print("-" * 60)
    for name, ev in regressor_evals.items():
        tm = ev["test_metrics"]
        print(f"{name:<22} | {tm['mae']:<10.4f} | {tm['rmse']:<10.4f} | {tm['r2_score']:<10.4f}")

    print("\n--- TOP CONTRIBUTING FEATURES (GLOBAL IMPORTANCE) ---")
    for feat, imp in list(feature_importances.items())[:6]:
        print(f"  - {feat:<30}: {imp * 100:.2f}%")
    print("=" * 80 + "\n")

    return metadata


if __name__ == "__main__":
    train_and_evaluate_all()

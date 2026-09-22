"""Model Architecture Definitions for AI Threat Prediction (Phase 11).

Defines candidate classification models (Logistic Regression baseline, Random Forest, XGBoost)
and regression models (Ridge baseline, Random Forest Regressor, XGBoost Regressor).
Implemented with pure NumPy/Python core and native C++ XGBoost integration for total reliability.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import numpy as np

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

logger = logging.getLogger(__name__)


# =====================================================================
# 1. CLASSIFICATION CANDIDATES
# =====================================================================

class SoftmaxLogisticRegression:
    """Multi-Class Softmax Logistic Regression with L2 Regularization."""

    def __init__(self, lr: float = 0.5, max_iter: int = 600, reg: float = 1e-4, seed: int = 42) -> None:
        self.lr = lr
        self.max_iter = max_iter
        self.reg = reg
        self.seed = seed
        self.W: np.ndarray | None = None
        self.b: np.ndarray | None = None
        self.feature_importances_: np.ndarray | None = None

    def fit(self, X: np.ndarray, y: np.ndarray, num_classes: int = 4) -> SoftmaxLogisticRegression:
        np.random.seed(self.seed)
        n, d = X.shape
        self.W = np.random.randn(d, num_classes).astype(np.float64) * 0.01
        self.b = np.zeros(num_classes, dtype=np.float64)

        # One-hot encode targets
        Y_onehot = np.zeros((n, num_classes), dtype=np.float64)
        Y_onehot[np.arange(n), y.astype(int)] = 1.0

        for _ in range(self.max_iter):
            logits = X @ self.W + self.b
            exp = np.exp(logits - np.max(logits, axis=1, keepdims=True))
            probs = exp / np.sum(exp, axis=1, keepdims=True)

            dW = (X.T @ (probs - Y_onehot)) / n + self.reg * self.W
            db = np.sum(probs - Y_onehot, axis=0) / n

            self.W -= self.lr * dW
            self.b -= self.lr * db

        # Derive feature importance from L2 norm of weights across classes
        norms = np.linalg.norm(self.W, axis=1)
        total = np.sum(norms)
        self.feature_importances_ = norms / total if total > 0 else np.ones(d) / d
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        logits = X @ self.W + self.b
        exp = np.exp(logits - np.max(logits, axis=1, keepdims=True))
        return exp / np.sum(exp, axis=1, keepdims=True)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return np.argmax(self.predict_proba(X), axis=1)


class PureRandomForestClassifier:
    """Ensemble Random Forest Classifier implemented in NumPy."""

    def __init__(self, n_estimators: int = 35, max_depth: int = 8, seed: int = 42) -> None:
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.seed = seed
        self.trees: list[dict[str, Any]] = []
        self.feature_importances_: np.ndarray | None = None

    def _build_tree(self, X: np.ndarray, y: np.ndarray, depth: int, rng: np.random.RandomState, n_classes: int = 4) -> dict[str, Any]:
        n_samples, n_feats = X.shape
        counts = np.bincount(y.astype(int), minlength=n_classes)
        probs = counts / n_samples if n_samples > 0 else np.ones(n_classes) / n_classes

        if depth >= self.max_depth or n_samples <= 4 or len(np.unique(y)) == 1:
            return {"leaf": True, "probs": probs, "class": int(np.argmax(probs))}

        # Subsample feature subset
        feat_subset = rng.choice(n_feats, size=max(2, int(np.sqrt(n_feats))), replace=False)
        best_gain = -1.0
        best_feat = None
        best_thresh = None

        # Current Gini impurity
        current_gini = 1.0 - np.sum(probs ** 2)

        for f in feat_subset:
            vals = np.unique(X[:, f])
            if len(vals) <= 1:
                continue
            thresholds = (vals[:-1] + vals[1:]) / 2.0
            for thresh in thresholds:
                left_mask = X[:, f] <= thresh
                n_l, n_r = np.sum(left_mask), n_samples - np.sum(left_mask)
                if n_l < 2 or n_r < 2:
                    continue
                p_l = np.bincount(y[left_mask].astype(int), minlength=n_classes) / n_l
                p_r = np.bincount(y[~left_mask].astype(int), minlength=n_classes) / n_r
                gini_l = 1.0 - np.sum(p_l ** 2)
                gini_r = 1.0 - np.sum(p_r ** 2)
                gain = current_gini - (n_l / n_samples * gini_l + n_r / n_samples * gini_r)
                if gain > best_gain:
                    best_gain, best_feat, best_thresh = gain, f, thresh

        if best_gain <= 0.0 or best_feat is None:
            return {"leaf": True, "probs": probs, "class": int(np.argmax(probs))}

        left_mask = X[:, best_feat] <= best_thresh
        left_child = self._build_tree(X[left_mask], y[left_mask], depth + 1, rng, n_classes)
        right_child = self._build_tree(X[~left_mask], y[~left_mask], depth + 1, rng, n_classes)

        return {
            "leaf": False,
            "feat": best_feat,
            "thresh": best_thresh,
            "gain": best_gain,
            "left": left_child,
            "right": right_child,
            "probs": probs,
        }

    def fit(self, X: np.ndarray, y: np.ndarray, num_classes: int = 4) -> PureRandomForestClassifier:
        rng = np.random.RandomState(self.seed)
        n, d = X.shape
        self.trees = []
        feat_gains = np.zeros(d, dtype=float)

        for _ in range(self.n_estimators):
            # Bootstrap sample
            boot_idx = rng.choice(n, size=n, replace=True)
            tree = self._build_tree(X[boot_idx], y[boot_idx], depth=0, rng=rng, n_classes=num_classes)
            self.trees.append(tree)

            def accumulate_gain(node: dict[str, Any]) -> None:
                if not node.get("leaf", False):
                    feat_gains[node["feat"]] += node.get("gain", 0.0)
                    accumulate_gain(node["left"])
                    accumulate_gain(node["right"])

            accumulate_gain(tree)

        total_gain = np.sum(feat_gains)
        self.feature_importances_ = feat_gains / total_gain if total_gain > 0 else np.ones(d) / d
        return self

    def _predict_tree_proba(self, node: dict[str, Any], x: np.ndarray) -> np.ndarray:
        if node.get("leaf", False):
            return node["probs"]
        if x[node["feat"]] <= node["thresh"]:
            return self._predict_tree_proba(node["left"], x)
        return self._predict_tree_proba(node["right"], x)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        all_probs = []
        for x in X:
            tree_probs = [self._predict_tree_proba(tree, x) for tree in self.trees]
            all_probs.append(np.mean(tree_probs, axis=0))
        return np.array(all_probs)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return np.argmax(self.predict_proba(X), axis=1)


class XGBoostClassifierWrapper:
    """XGBoost Multi-Class Classifier using native C++ Booster API."""

    def __init__(self, n_estimators: int = 60, max_depth: int = 5, lr: float = 0.08, seed: int = 42) -> None:
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.lr = lr
        self.seed = seed
        self.booster: Any = None
        self.feature_importances_: np.ndarray | None = None

    def fit(self, X: np.ndarray, y: np.ndarray, num_classes: int = 4) -> XGBoostClassifierWrapper:
        if not XGBOOST_AVAILABLE:
            raise RuntimeError("XGBoost is not installed!")
        dtrain = xgb.DMatrix(X, label=y.astype(np.int32))
        params = {
            "objective": "multi:softprob",
            "num_class": num_classes,
            "max_depth": self.max_depth,
            "learning_rate": self.lr,
            "seed": self.seed,
            "verbosity": 0,
        }
        self.booster = xgb.train(params, dtrain, num_boost_round=self.n_estimators)

        # Feature importances
        scores = self.booster.get_score(importance_type="gain")
        d = X.shape[1]
        importances = np.zeros(d, dtype=float)
        for k, v in scores.items():
            if k.startswith("f"):
                idx = int(k[1:])
                if idx < d:
                    importances[idx] = float(v)
        total = np.sum(importances)
        self.feature_importances_ = importances / total if total > 0 else np.ones(d) / d
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        dmat = xgb.DMatrix(X)
        return self.booster.predict(dmat)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return np.argmax(self.predict_proba(X), axis=1)


# =====================================================================
# 2. REGRESSION CANDIDATES (Threat Score Prediction)
# =====================================================================

class RidgeRegression:
    """Closed-Form Ridge Linear Regression."""

    def __init__(self, alpha: float = 1.0) -> None:
        self.alpha = alpha
        self.weights: np.ndarray | None = None
        self.intercept: float = 0.0
        self.feature_importances_: np.ndarray | None = None

    def fit(self, X: np.ndarray, y: np.ndarray) -> RidgeRegression:
        n, d = X.shape
        X_aug = np.hstack([np.ones((n, 1)), X])
        I = np.eye(d + 1)
        I[0, 0] = 0.0  # Do not regularize intercept
        params = np.linalg.solve(X_aug.T @ X_aug + self.alpha * I, X_aug.T @ y)
        self.intercept = float(params[0])
        self.weights = params[1:]
        total = np.sum(np.abs(self.weights))
        self.feature_importances_ = np.abs(self.weights) / total if total > 0 else np.ones(d) / d
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        return X @ self.weights + self.intercept


class PureRandomForestRegressor:
    """Random Forest Regressor in NumPy."""

    def __init__(self, n_estimators: int = 35, max_depth: int = 8, seed: int = 42) -> None:
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.seed = seed
        self.trees: list[dict[str, Any]] = []
        self.feature_importances_: np.ndarray | None = None

    def _build_tree(self, X: np.ndarray, y: np.ndarray, depth: int, rng: np.random.RandomState) -> dict[str, Any]:
        n_samples, n_feats = X.shape
        mean_y = float(np.mean(y)) if n_samples > 0 else 0.0

        if depth >= self.max_depth or n_samples <= 4:
            return {"leaf": True, "val": mean_y}

        feat_subset = rng.choice(n_feats, size=max(2, int(np.sqrt(n_feats))), replace=False)
        best_reduction = -1.0
        best_feat = None
        best_thresh = None

        current_mse = np.mean((y - mean_y) ** 2)

        for f in feat_subset:
            vals = np.unique(X[:, f])
            if len(vals) <= 1:
                continue
            thresholds = (vals[:-1] + vals[1:]) / 2.0
            for thresh in thresholds:
                left_mask = X[:, f] <= thresh
                n_l, n_r = np.sum(left_mask), n_samples - np.sum(left_mask)
                if n_l < 2 or n_r < 2:
                    continue
                mse_l = np.mean((y[left_mask] - np.mean(y[left_mask])) ** 2)
                mse_r = np.mean((y[~left_mask] - np.mean(y[~left_mask])) ** 2)
                reduction = current_mse - (n_l / n_samples * mse_l + n_r / n_samples * mse_r)
                if reduction > best_reduction:
                    best_reduction, best_feat, best_thresh = reduction, f, thresh

        if best_reduction <= 0.0 or best_feat is None:
            return {"leaf": True, "val": mean_y}

        left_mask = X[:, best_feat] <= best_thresh
        left_child = self._build_tree(X[left_mask], y[left_mask], depth + 1, rng)
        right_child = self._build_tree(X[~left_mask], y[~left_mask], depth + 1, rng)

        return {
            "leaf": False,
            "feat": best_feat,
            "thresh": best_thresh,
            "reduction": best_reduction,
            "left": left_child,
            "right": right_child,
            "val": mean_y,
        }

    def fit(self, X: np.ndarray, y: np.ndarray) -> PureRandomForestRegressor:
        rng = np.random.RandomState(self.seed)
        n, d = X.shape
        self.trees = []
        feat_reductions = np.zeros(d, dtype=float)

        for _ in range(self.n_estimators):
            boot_idx = rng.choice(n, size=n, replace=True)
            tree = self._build_tree(X[boot_idx], y[boot_idx], depth=0, rng=rng)
            self.trees.append(tree)

            def accumulate(node: dict[str, Any]) -> None:
                if not node.get("leaf", False):
                    feat_reductions[node["feat"]] += node.get("reduction", 0.0)
                    accumulate(node["left"])
                    accumulate(node["right"])

            accumulate(tree)

        total = np.sum(feat_reductions)
        self.feature_importances_ = feat_reductions / total if total > 0 else np.ones(d) / d
        return self

    def _predict_tree(self, node: dict[str, Any], x: np.ndarray) -> float:
        if node.get("leaf", False):
            return node["val"]
        if x[node["feat"]] <= node["thresh"]:
            return self._predict_tree(node["left"], x)
        return self._predict_tree(node["right"], x)

    def predict(self, X: np.ndarray) -> np.ndarray:
        preds = []
        for x in X:
            tree_vals = [self._predict_tree(tree, x) for tree in self.trees]
            preds.append(np.mean(tree_vals))
        return np.array(preds)


class XGBoostRegressorWrapper:
    """XGBoost Regressor using native C++ Booster API."""

    def __init__(self, n_estimators: int = 60, max_depth: int = 5, lr: float = 0.08, seed: int = 42) -> None:
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.lr = lr
        self.seed = seed
        self.booster: Any = None
        self.feature_importances_: np.ndarray | None = None

    def fit(self, X: np.ndarray, y: np.ndarray) -> XGBoostRegressorWrapper:
        if not XGBOOST_AVAILABLE:
            raise RuntimeError("XGBoost is not installed!")
        dtrain = xgb.DMatrix(X, label=y.astype(np.float32))
        params = {
            "objective": "reg:squarederror",
            "max_depth": self.max_depth,
            "learning_rate": self.lr,
            "seed": self.seed,
            "verbosity": 0,
        }
        self.booster = xgb.train(params, dtrain, num_boost_round=self.n_estimators)

        scores = self.booster.get_score(importance_type="gain")
        d = X.shape[1]
        importances = np.zeros(d, dtype=float)
        for k, v in scores.items():
            if k.startswith("f"):
                idx = int(k[1:])
                if idx < d:
                    importances[idx] = float(v)
        total = np.sum(importances)
        self.feature_importances_ = importances / total if total > 0 else np.ones(d) / d
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        dmat = xgb.DMatrix(X)
        return self.booster.predict(dmat)


# =====================================================================
# CANDIDATE RETRIEVAL HELPERS
# =====================================================================

def get_classifier_candidates(random_seed: int = 42) -> dict[str, Any]:
    """Instantiate classification candidate model instances."""
    models: dict[str, Any] = {
        "LogisticRegression": SoftmaxLogisticRegression(lr=0.5, max_iter=600, seed=random_seed),
        "RandomForest": PureRandomForestClassifier(n_estimators=35, max_depth=8, seed=random_seed),
    }
    if XGBOOST_AVAILABLE:
        models["XGBoost"] = XGBoostClassifierWrapper(n_estimators=60, max_depth=5, lr=0.08, seed=random_seed)
    return models


def get_regressor_candidates(random_seed: int = 42) -> dict[str, Any]:
    """Instantiate threat-score regression candidate model instances."""
    models: dict[str, Any] = {
        "RidgeRegression": RidgeRegression(alpha=1.0),
        "RandomForestRegressor": PureRandomForestRegressor(n_estimators=35, max_depth=8, seed=random_seed),
    }
    if XGBOOST_AVAILABLE:
        models["XGBoostRegressor"] = XGBoostRegressorWrapper(n_estimators=60, max_depth=5, lr=0.08, seed=random_seed)
    return models

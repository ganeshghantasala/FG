"""
Offline ablation experiment for FakeGuard's high-importance SSL feature.

Compares:
1. The current saved 22-feature runtime model on a stratified holdout.
2. A separate Random Forest trained on the same training split with
   `sslfinal_state` removed.

This does not fetch URLs, alter FakeGuard files, overwrite the model, or save a
candidate model. It is a model-level diagnostic on UCI dataset ID 327 only.
"""

from __future__ import annotations

import joblib
import numpy as np
from ucimlrepo import fetch_ucirepo
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split


MODEL_PATH = "fakeguard_model_runtime.joblib"
RANDOM_STATE = 42
TEST_SIZE = 0.20
SSL_FEATURE = "sslfinal_state"


def report(name, model, X_test, y_test, feature_names) -> dict:
    data = X_test.loc[:, feature_names]
    predictions = model.predict(data)
    class_order = list(model.classes_)
    phishing_column = class_order.index(1)
    probabilities = model.predict_proba(data)[:, phishing_column]

    tn, fp, fn, tp = confusion_matrix(
        y_test, predictions, labels=[0, 1]
    ).ravel()
    result = {
        "accuracy": accuracy_score(y_test, predictions),
        "precision": precision_score(y_test, predictions, zero_division=0),
        "recall": recall_score(y_test, predictions, zero_division=0),
        "f1": f1_score(y_test, predictions, zero_division=0),
        "roc_auc": roc_auc_score(y_test, probabilities),
        "average_precision": average_precision_score(y_test, probabilities),
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "TN": int(tn),
        "FP": int(fp),
        "FN": int(fn),
        "TP": int(tp),
    }

    print(f"\n{name}")
    print(f"Features used: {len(feature_names)}")
    for key in (
        "accuracy",
        "precision",
        "recall",
        "f1",
        "roc_auc",
        "average_precision",
        "false_positive_rate",
    ):
        print(f"{key:22s}: {result[key]:.6f}")
    print(f"TN={result['TN']} FP={result['FP']} FN={result['FN']} TP={result['TP']}")
    return result


def main() -> None:
    bundle = joblib.load(MODEL_PATH)
    current_features = list(bundle["feature_names"])

    if SSL_FEATURE not in current_features:
        raise ValueError(
            f"{SSL_FEATURE!r} is not in the runtime model's feature list."
        )

    print("OFFLINE EXPERIMENT ONLY")
    print("No URLs fetched. No application files or saved models changed.")
    print("Loading UCI Phishing Websites dataset (ID 327)...")
    dataset = fetch_ucirepo(id=327)

    X = dataset.data.features.copy()
    y = (dataset.data.targets.iloc[:, 0] == -1).astype(int)

    missing = [name for name in current_features if name not in X.columns]
    if missing:
        raise ValueError(f"Training data is missing runtime features: {missing}")

    X = (
        X.replace([np.inf, -np.inf], np.nan)
        .reindex(columns=current_features)
        .fillna(0)
    )

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    print(f"Dataset rows: {len(X)}")
    print(f"Training rows: {len(X_train)}")
    print(f"Test rows: {len(X_test)}")
    print("Target encoding: class 1 = phishing; class 0 = legitimate.")

    baseline = report(
        "A. Current saved runtime model",
        bundle["model"],
        X_test,
        y_test,
        current_features,
    )

    candidate_features = [name for name in current_features if name != SSL_FEATURE]
    candidate = RandomForestClassifier(
        n_estimators=400,
        max_depth=None,
        min_samples_leaf=1,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    candidate.fit(X_train[candidate_features], y_train)

    candidate_metrics = report(
        "B. Separate candidate trained without sslfinal_state",
        candidate,
        X_test,
        y_test,
        candidate_features,
    )

    print("\nCandidate minus current baseline (percentage points for rates):")
    for key in (
        "accuracy",
        "precision",
        "recall",
        "f1",
        "roc_auc",
        "average_precision",
        "false_positive_rate",
    ):
        difference = candidate_metrics[key] - baseline[key]
        print(f"{key:22s}: {difference:+.6f}")

    print(
        "\nInterpretation: this is only an offline random-split ablation on "
        "UCI dataset 327. It does not prove live detection will improve, and "
        "the candidate model was not saved or deployed."
    )


if __name__ == "__main__":
    main()

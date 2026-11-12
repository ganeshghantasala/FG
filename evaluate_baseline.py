
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from ucimlrepo import fetch_ucirepo
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
    average_precision_score,
)

OUT = Path("research_results")
OUT.mkdir(exist_ok=True)

MODEL_PATH = Path("fakeguard_model.joblib")

if not MODEL_PATH.exists():
    raise FileNotFoundError(
        "Model not found. Run python train.py first."
    )

print("[1/5] Loading saved model...")
bundle = joblib.load(MODEL_PATH)
model = bundle["model"]

print("[2/5] Loading UCI dataset...")
ds = fetch_ucirepo(id=327)
X = ds.data.features.copy()
y = (ds.data.targets.iloc[:, 0] == -1).astype(int)

X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

# Ensure the model receives the same ordered features.
expected_features = bundle["feature_names"]
if list(X.columns) != list(expected_features):
    raise ValueError(
        "Dataset feature names/order do not match the saved model."
    )

# Reproduce the original train.py test split.
_, X_test, _, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y,
)

print("[3/5] Evaluating baseline...")
pred = model.predict(X_test)

class_positions = list(model.classes_)
phishing_index = class_positions.index(1)
phishing_probability = model.predict_proba(X_test)[:, phishing_index]

tn, fp, fn, tp = confusion_matrix(
    y_test, pred, labels=[0, 1]
).ravel()

specificity = tn / (tn + fp) if (tn + fp) else 0.0
false_positive_rate = fp / (fp + tn) if (fp + tn) else 0.0

metrics = {
    "model": "Random Forest",
    "dataset": "UCI Phishing Websites",
    "test_samples": int(len(y_test)),
    "accuracy": float(accuracy_score(y_test, pred)),
    "precision": float(precision_score(y_test, pred, zero_division=0)),
    "recall": float(recall_score(y_test, pred, zero_division=0)),
    "f1_score": float(f1_score(y_test, pred, zero_division=0)),
    "specificity": float(specificity),
    "false_positive_rate": float(false_positive_rate),
    "roc_auc": float(roc_auc_score(y_test, phishing_probability)),
    "average_precision": float(
        average_precision_score(y_test, phishing_probability)
    ),
    "confusion_matrix": {
        "true_negative": int(tn),
        "false_positive": int(fp),
        "false_negative": int(fn),
        "true_positive": int(tp),
    },
}

print("[4/5] Saving results...")

with open(OUT / "baseline_metrics.json", "w", encoding="utf-8") as f:
    json.dump(metrics, f, indent=2)

report = classification_report(
    y_test,
    pred,
    labels=[0, 1],
    target_names=["Legitimate", "Phishing"],
    output_dict=True,
    zero_division=0,
)
pd.DataFrame(report).transpose().to_csv(
    OUT / "classification_report.csv"
)

cm = pd.DataFrame(
    [[tn, fp], [fn, tp]],
    index=["Actual Legitimate", "Actual Phishing"],
    columns=["Predicted Legitimate", "Predicted Phishing"],
)
cm.to_csv(OUT / "confusion_matrix.csv")

predictions = pd.DataFrame({
    "sample_index": X_test.index,
    "actual_label": y_test.to_numpy(),
    "predicted_label": pred,
    "phishing_probability": phishing_probability,
})
predictions["correct"] = (
    predictions["actual_label"] == predictions["predicted_label"]
)
predictions.to_csv(OUT / "test_predictions.csv", index=False)

if hasattr(model, "feature_importances_"):
    importance = pd.DataFrame({
        "feature": expected_features,
        "importance": model.feature_importances_,
    }).sort_values("importance", ascending=False)

    importance.to_csv(
        OUT / "feature_importance.csv", index=False
    )

print("[5/5] Complete\n")
print("=== Baseline research metrics ===")
for name, value in metrics.items():
    print(f"{name}: {value}")

print(f"\nResults saved in: {OUT.resolve()}")

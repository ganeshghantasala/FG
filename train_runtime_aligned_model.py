
import joblib
import numpy as np
import pandas as pd
from ucimlrepo import fetch_ucirepo
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)

OUTPUT = "fakeguard_model_runtime.joblib"

UNAVAILABLE = {
    "age_of_domain",
    "dnsrecord",
    "web_traffic",
    "page_rank",
    "google_index",
    "links_pointing_to_page",
    "statistical_report",
    "domain_registration_length",
}

print("[1/5] Loading dataset and original model...")
bundle = joblib.load("fakeguard_model.joblib")
original_model = bundle["model"]
feature_names = bundle["feature_names"]

ds = fetch_ucirepo(id=327)
X = ds.data.features.copy()
y = (ds.data.targets.iloc[:, 0] == -1).astype(int)

X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
X = X.reindex(columns=feature_names)

if X.isna().any().any():
    raise ValueError("Dataset features do not match the saved model.")

unavailable = [
    name for name in feature_names
    if name.lower() in UNAVAILABLE
]
available = [
    name for name in feature_names
    if name.lower() not in UNAVAILABLE
]

print("Original feature count:", len(feature_names))
print("Available feature count:", len(available))
print("Excluded features:", unavailable)

print("\n[2/5] Creating the same stratified split...")
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y,
)

print("Training rows:", len(X_train))
print("Testing rows:", len(X_test))

def show_metrics(name, truth, predictions):
    print(f"\n{name}")
    print(f"Accuracy : {accuracy_score(truth, predictions):.6f}")
    print(f"Precision: {precision_score(truth, predictions, zero_division=0):.6f}")
    print(f"Recall   : {recall_score(truth, predictions, zero_division=0):.6f}")
    print(f"F1-score : {f1_score(truth, predictions, zero_division=0):.6f}")

print("\n[3/5] Evaluating the original model...")
original_pred = original_model.predict(X_test)
show_metrics("Original model: 30 features", y_test, original_pred)

print("\n[4/5] Evaluating the original model with missing features zeroed...")
X_zeroed = X_test.copy()
X_zeroed[unavailable] = 0
zeroed_pred = original_model.predict(X_zeroed)
show_metrics("Original model: unavailable features zeroed", y_test, zeroed_pred)

print("\nTraining a separate model with available features...")
aligned_model = RandomForestClassifier(
    n_estimators=400,
    max_depth=None,
    min_samples_leaf=1,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1,
)
aligned_model.fit(X_train[available], y_train)

aligned_pred = aligned_model.predict(X_test[available])
show_metrics("New model: 23 available features", y_test, aligned_pred)

joblib.dump(
    {
        "model": aligned_model,
        "feature_names": available,
        "excluded_features": unavailable,
        "dataset_id": 327,
    },
    OUTPUT,
)

print("\n[5/5] Experiment complete.")
print("Saved separate model:", OUTPUT)
print("The original fakeguard_model.joblib was not modified.")

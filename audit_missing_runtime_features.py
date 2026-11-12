
import joblib
import numpy as np
import pandas as pd
from ucimlrepo import fetch_ucirepo
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score
)

bundle = joblib.load("fakeguard_model.joblib")
model = bundle["model"]
feature_names = bundle["feature_names"]

print("Loading UCI Phishing Websites dataset...")
ds = fetch_ucirepo(id=327)
X = ds.data.features.copy()
y = (ds.data.targets.iloc[:, 0] == -1).astype(int)

X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
X = X.reindex(columns=feature_names)

if X.isna().any().any():
    raise ValueError("Some model features could not be matched to the dataset.")

_, X_test, _, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

missing_features = [
    "age_of_domain",
    "dnsrecord",
    "web_traffic",
    "page_rank",
    "google_index",
    "links_pointing_to_page",
    "statistical_report",
]

for name in missing_features:
    if name not in X_test.columns:
        raise ValueError(f"Feature not found in dataset: {name}")

X_zeroed = X_test.copy()
X_zeroed[missing_features] = 0

def report(name, data):
    pred = model.predict(data)
    print(f"\n{name}")
    print(f"Accuracy : {accuracy_score(y_test, pred):.6f}")
    print(f"Precision: {precision_score(y_test, pred, zero_division=0):.6f}")
    print(f"Recall   : {recall_score(y_test, pred, zero_division=0):.6f}")
    print(f"F1       : {f1_score(y_test, pred, zero_division=0):.6f}")

report("Original held-out test features", X_test)
report("Test features with unavailable signals set to zero", X_zeroed)

print("\nNumber of test rows:", len(X_test))
print("Features forced to zero:", len(missing_features))

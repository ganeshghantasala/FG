import os, joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
from ucimlrepo import fetch_ucirepo

OUT = "fakeguard_model.joblib"

print("[1/4] Downloading UCI Phishing Websites dataset...")
ds = fetch_ucirepo(id=327)
X = ds.data.features.copy()
y = ds.data.targets.iloc[:, 0].copy()

# UCI uses -1/0/1 feature values and target -1/1.
y = (y == -1).astype(int)  # 1 = phishing, 0 = legitimate

# Keep exact dataset feature order.
feature_names = list(X.columns)
X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

print("[2/4] Training Random Forest...")
model = RandomForestClassifier(
    n_estimators=400,
    max_depth=None,
    min_samples_leaf=1,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)

pred = model.predict(X_test)
print("\n=== FakeGuard baseline ML evaluation ===")
print(f"Accuracy : {accuracy_score(y_test, pred):.4f}")
print(f"Precision: {precision_score(y_test, pred):.4f}")
print(f"Recall   : {recall_score(y_test, pred):.4f}")
print(f"F1       : {f1_score(y_test, pred):.4f}")
print(classification_report(y_test, pred, target_names=["Legitimate", "Phishing"]))

joblib.dump(
    {"model": model, "feature_names": feature_names},
    OUT
)
print(f"[4/4] Saved {OUT}")

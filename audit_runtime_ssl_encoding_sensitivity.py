from __future__ import annotations
import joblib
import numpy as np
from ucimlrepo import fetch_ucirepo
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score, average_precision_score
from sklearn.model_selection import train_test_split

MODEL_PATH = "fakeguard_model_runtime.joblib"
FEATURE = "sslfinal_state"

def metrics(model, X, y):
    pred = model.predict(X)
    prob = model.predict_proba(X)[:, list(model.classes_).index(1)]
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "accuracy": accuracy_score(y, pred),
        "precision": precision_score(y, pred, zero_division=0),
        "recall": recall_score(y, pred, zero_division=0),
        "f1": f1_score(y, pred, zero_division=0),
        "roc_auc": roc_auc_score(y, prob),
        "average_precision": average_precision_score(y, prob),
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp),
        "pred": pred, "prob": prob,
    }

def show(title, m):
    print("\n" + title)
    for k in ("accuracy", "precision", "recall", "f1", "roc_auc", "average_precision", "false_positive_rate"):
        print(f"{k:22s}: {m[k]:.6f}")
    print(f"TN={m['TN']} FP={m['FP']} FN={m['FN']} TP={m['TP']}")

def main():
    print("OFFLINE SENSITIVITY AUDIT ONLY")
    print("No URLs fetched; no saved model or application files changed.")
    bundle = joblib.load(MODEL_PATH)
    features = list(bundle["feature_names"])
    if FEATURE not in features:
        raise ValueError(f"{FEATURE!r} missing from saved runtime model")
    ds = fetch_ucirepo(id=327)
    X = ds.data.features.copy()
    y = (ds.data.targets.iloc[:, 0] == -1).astype(int)
    missing = [f for f in features if f not in X.columns]
    if missing:
        raise ValueError(f"Dataset missing model features: {missing}")
    X = X.replace([np.inf, -np.inf], np.nan).reindex(columns=features).fillna(0)
    _, xt, _, yt = train_test_split(X, y, test_size=0.20, random_state=42, stratify=y)
    raw = xt.copy()
    changed = xt.copy()
    neutral_count = int((changed[FEATURE] == 0).sum())
    changed[FEATURE] = changed[FEATURE].replace({0: 1})
    a, b = metrics(bundle["model"], raw, yt), metrics(bundle["model"], changed, yt)
    print("Test rows:", len(xt))
    print(f"Rows with {FEATURE}=0 changed to +1:", neutral_count)
    show("A. Original held-out feature values", a)
    show("B. Stress test: neutral SSL state collapsed to +1", b)
    print("\nSensitivity summary")
    print("Predicted labels changed:", int(np.sum(a["pred"] != b["pred"])), "/", len(xt))
    print("Mean absolute probability change:", f"{np.abs(a['prob'] - b['prob']).mean():.6f}")
    print("This collapse is only a simplified stress test, not an exact reconstruction of live TLS status.")

if __name__ == "__main__":
    main()

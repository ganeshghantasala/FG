
from pathlib import Path
import json

import numpy as np
import pandas as pd
from ucimlrepo import fetch_ucirepo
from sklearn.model_selection import GroupShuffleSplit
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
    average_precision_score,
)

OUT = Path("research_results")
OUT.mkdir(exist_ok=True)

URL_FEATURES = [
    "URLLength", "DomainLength", "IsDomainIP",
    "CharContinuationRate", "TLDLength", "NoOfSubDomain",
    "HasObfuscation", "NoOfObfuscatedChar", "ObfuscationRatio",
    "NoOfLettersInURL", "LetterRatioInURL",
    "NoOfDegitsInURL", "DegitRatioInURL",
    "NoOfEqualsInURL", "NoOfQMarkInURL",
    "NoOfAmpersandInURL", "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL", "IsHTTPS",
]

PAGE_FEATURES = [
    "LineOfCode", "LargestLineLength", "HasTitle",
    "DomainTitleMatchScore", "URLTitleMatchScore",
    "HasFavicon", "Robots", "IsResponsive",
    "NoOfURLRedirect", "NoOfSelfRedirect",
    "HasDescription", "NoOfPopup", "NoOfiFrame",
    "HasExternalFormSubmit", "HasSocialNet",
    "HasSubmitButton", "HasHiddenFields", "HasPasswordField",
    "Bank", "Pay", "Crypto", "HasCopyrightInfo",
    "NoOfImage", "NoOfCSS", "NoOfJS",
    "NoOfSelfRef", "NoOfEmptyRef", "NoOfExternalRef",
]

FEATURES = URL_FEATURES + PAGE_FEATURES

print("[1/6] Loading dataset...")
ds = fetch_ucirepo(id=967)
X = ds.data.features.copy()
y = (ds.data.targets.iloc[:, 0].astype(int) == 0).astype(int)

missing = sorted(set(FEATURES) - set(X.columns))
if missing:
    raise ValueError(f"Missing expected features: {missing}")

numeric = (
    X[FEATURES]
    .apply(pd.to_numeric, errors="coerce")
    .replace([np.inf, -np.inf], np.nan)
)

# Use a sentinel for hashing missing feature values.
# The sentinel is not used to train the model.
signature_data = numeric.fillna(-999999999.0)
signatures = pd.util.hash_pandas_object(
    signature_data, index=False
).to_numpy(dtype="uint64")

domains = X["Domain"].astype(str).str.strip().str.lower()
if domains.eq("").any():
    raise ValueError("Empty domain values found; inspect before evaluation.")

print("[2/6] Creating the original domain-separated split...")
splitter = GroupShuffleSplit(
    n_splits=1, test_size=0.20, random_state=42
)
train_idx, test_idx = next(
    splitter.split(numeric, y, groups=domains)
)

train_signature_set = set(signatures[train_idx].tolist())

# Keep test rows whose exact selected feature vector was not in training.
keep_mask = np.array([
    sig not in train_signature_set
    for sig in signatures[test_idx]
])
strict_test_idx = test_idx[keep_mask]

if len(strict_test_idx) == 0:
    raise ValueError("No novel feature vectors remain in the test set.")

print("[3/6] Checking strict test-set separation...")
domain_overlap = set(domains.iloc[train_idx]).intersection(
    set(domains.iloc[strict_test_idx])
)
signature_overlap = train_signature_set.intersection(
    set(signatures[strict_test_idx].tolist())
)

assert not domain_overlap, "Domain overlap detected."
assert not signature_overlap, "Identical feature vectors remain."

y_train = y.iloc[train_idx]
y_test = y.iloc[strict_test_idx]

if y_train.nunique() != 2 or y_test.nunique() != 2:
    raise ValueError("Both classes must be present in train and test.")

print(f"Original test rows: {len(test_idx)}")
print(f"Retained novel-pattern test rows: {len(strict_test_idx)}")
print(f"Excluded repeated-pattern rows: {len(test_idx) - len(strict_test_idx)}")
print(f"Domain overlap: {len(domain_overlap)}")
print(f"Feature-vector overlap: {len(signature_overlap)}")

print("[4/6] Training combined-feature Random Forest...")
x_train = numeric.iloc[train_idx].copy()
x_test = numeric.iloc[strict_test_idx].copy()

# Impute using training data only.
medians = x_train.median().fillna(0)
x_train = x_train.fillna(medians).fillna(0)
x_test = x_test.fillna(medians).fillna(0)

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced_subsample",
)
model.fit(x_train, y_train)

print("[5/6] Evaluating strict test set...")
pred = model.predict(x_test)
probabilities = model.predict_proba(x_test)[
    :, list(model.classes_).index(1)
]

tn, fp, fn, tp = confusion_matrix(
    y_test, pred, labels=[0, 1]
).ravel()

metrics = {
    "evaluation": "Domain-separated and novel-feature-vector test",
    "model": "Random Forest",
    "features": len(FEATURES),
    "training_rows": int(len(train_idx)),
    "original_test_rows": int(len(test_idx)),
    "strict_test_rows": int(len(strict_test_idx)),
    "excluded_repeated_pattern_rows": int(len(test_idx) - len(strict_test_idx)),
    "domain_overlap": len(domain_overlap),
    "feature_vector_overlap": len(signature_overlap),
    "accuracy": float(accuracy_score(y_test, pred)),
    "precision": float(precision_score(y_test, pred, zero_division=0)),
    "recall": float(recall_score(y_test, pred, zero_division=0)),
    "f1_score": float(f1_score(y_test, pred, zero_division=0)),
    "roc_auc": float(roc_auc_score(y_test, probabilities)),
    "average_precision": float(average_precision_score(y_test, probabilities)),
    "specificity": float(tn / (tn + fp)) if tn + fp else 0.0,
    "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
    "true_negative": int(tn),
    "false_positive": int(fp),
    "false_negative": int(fn),
    "true_positive": int(tp),
}

(OUT / "strict_evaluation_metrics.json").write_text(
    json.dumps(metrics, indent=2), encoding="utf-8"
)

pd.DataFrame([metrics]).to_csv(
    OUT / "strict_evaluation_metrics.csv", index=False
)

pd.DataFrame({
    "actual_is_phishing": y_test.to_numpy(),
    "predicted_is_phishing": pred,
    "phishing_probability": probabilities,
}).to_csv(OUT / "strict_test_predictions.csv", index=False)

print("[6/6] Finished.")
for name, value in metrics.items():
    print(f"{name}: {value}")

print(f"\nSaved results in: {OUT.resolve()}")

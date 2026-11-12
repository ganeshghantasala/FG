
from pathlib import Path
import json

import numpy as np
import pandas as pd
from ucimlrepo import fetch_ucirepo
from sklearn.model_selection import GroupShuffleSplit
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score, average_precision_score,
)

OUT = Path("research_results")
OUT.mkdir(exist_ok=True)

URL_FEATURES = [
    "URLLength", "DomainLength", "IsDomainIP", "TLDLength",
    "NoOfSubDomain", "HasObfuscation", "NoOfObfuscatedChar",
    "ObfuscationRatio", "NoOfLettersInURL", "LetterRatioInURL",
    "NoOfDegitsInURL", "DegitRatioInURL", "NoOfEqualsInURL",
    "NoOfQMarkInURL", "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL", "IsHTTPS",
]

PAGE_FEATURES = [
    "LineOfCode", "LargestLineLength", "HasTitle", "HasFavicon",
    "Robots", "IsResponsive", "NoOfURLRedirect", "NoOfSelfRedirect",
    "HasDescription", "NoOfPopup", "NoOfiFrame", "HasExternalFormSubmit",
    "HasSocialNet", "HasSubmitButton", "HasHiddenFields",
    "HasPasswordField", "Bank", "Pay", "Crypto", "HasCopyrightInfo",
    "NoOfImage", "NoOfCSS", "NoOfJS", "NoOfSelfRef",
    "NoOfEmptyRef", "NoOfExternalRef",
]
FEATURES = URL_FEATURES + PAGE_FEATURES

print("[1/6] Loading PhiUSIIL...")
ds = fetch_ucirepo(id=967)
X = ds.data.features.copy()
y = (ds.data.targets.iloc[:, 0].astype(int) == 0).astype(int)

missing = sorted(set(FEATURES + ["Domain"]) - set(X.columns))
if missing:
    raise ValueError(f"Required dataset columns missing: {missing}")

groups = X["Domain"].astype(str).str.strip().str.lower()
if groups.eq("").any():
    raise ValueError("Empty domains found; cannot make domain-separated split.")

numeric = (
    X[FEATURES]
    .apply(pd.to_numeric, errors="coerce")
    .replace([np.inf, -np.inf], np.nan)
)

print("[2/6] Recreating the domain-separated, strict test split...")
splitter = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
train_idx, test_idx = next(splitter.split(numeric, y, groups=groups))

# Remove test rows whose complete 44-feature vector appears in training.
signatures = pd.util.hash_pandas_object(
    numeric.fillna(-999999999.0), index=False
).to_numpy(dtype="uint64")
train_signatures = set(signatures[train_idx].tolist())
strict_mask = np.array([
    sig not in train_signatures for sig in signatures[test_idx]
])
test_idx = test_idx[strict_mask]

domain_overlap = set(groups.iloc[train_idx]) & set(groups.iloc[test_idx])
vector_overlap = train_signatures & set(signatures[test_idx].tolist())
if domain_overlap or vector_overlap:
    raise RuntimeError("Train/test separation check failed.")

X_train = numeric.iloc[train_idx][FEATURES].copy()
X_test = numeric.iloc[test_idx][FEATURES].copy()
y_train = y.iloc[train_idx].to_numpy()
y_test = y.iloc[test_idx].to_numpy()

medians = X_train.median().fillna(0)
X_train = X_train.fillna(medians).fillna(0)
X_test = X_test.fillna(medians).fillna(0)

print("Training rows:", len(train_idx))
print("Strict test rows:", len(test_idx))
print("Shared domains:", len(domain_overlap))
print("Shared complete feature vectors:", len(vector_overlap))

print("[3/6] Training the combined-core ML baseline...")
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced_subsample",
)
model.fit(X_train, y_train)
classes = list(model.classes_)
phishing_col = classes.index(1)
ml_risk = model.predict_proba(X_test)[:, phishing_col]

print("[4/6] Building explicitly approximate HTML/identity signals...")
page = X.iloc[test_idx].reset_index(drop=True)

def flag(column):
    return (
        pd.to_numeric(page[column], errors="coerce")
        .fillna(0).to_numpy() > 0
    )

has_form_proxy = flag("HasSubmitButton")
has_password = flag("HasPasswordField")
external_form = flag("HasExternalFormSubmit")
has_iframe = flag("NoOfiFrame")
external_refs = (
    pd.to_numeric(page["NoOfExternalRef"], errors="coerce")
    .fillna(0).to_numpy()
)
self_refs = (
    pd.to_numeric(page["NoOfSelfRef"], errors="coerce")
    .fillna(0).to_numpy()
)

# Proxy: the dataset has no direct equivalent for every live HTML signal.
html_risk = (
    0.20 * has_form_proxy.astype(float)
    + 0.25 * has_password.astype(float)
    + 0.20 * external_form.astype(float)
    + 0.10 * has_iframe.astype(float)
    + 0.10 * ((external_refs > 0) & ((external_refs + self_refs) > 0)).astype(float)
)
html_risk = np.clip(html_risk, 0, 1)

# Approximate identity signals using available keyword-category flags.
keyword_count = (
    flag("Bank").astype(float)
    + flag("Pay").astype(float)
    + flag("Crypto").astype(float)
)
identity_risk = (
    0.20 * keyword_count
    + 0.35 * (has_form_proxy & has_password).astype(float)
    + 0.35 * external_form.astype(float)
)
identity_risk = np.clip(identity_risk, 0, 1)

weighted_without_rules = np.clip(
    0.55 * ml_risk + 0.25 * html_risk + 0.20 * identity_risk,
    0, 1,
)

contradiction_1 = (ml_risk < 0.35) & (html_risk > 0.55)
contradiction_2 = has_password & external_form
bonus = (
    0.18 * contradiction_1.astype(float)
    + 0.12 * contradiction_2.astype(float)
)
weighted_with_rules = np.clip(weighted_without_rules + bonus, 0, 1)

print("[5/6] Evaluating the three risk scores...")
scores = {
    "ML only": ml_risk,
    "Weighted fusion, no contradiction rules": weighted_without_rules,
    "Weighted fusion with contradiction rules": weighted_with_rules,
}

def calculate_metrics(name, score):
    # Same fixed alert threshold for all approaches; not tuned on test data.
    predicted = score >= 0.45
    tn, fp, fn, tp = confusion_matrix(
        y_test, predicted, labels=[0, 1]
    ).ravel()

    return {
        "method": name,
        "test_rows": len(y_test),
        "alert_threshold": 0.45,
        "accuracy": accuracy_score(y_test, predicted),
        "precision": precision_score(y_test, predicted, zero_division=0),
        "recall": recall_score(y_test, predicted, zero_division=0),
        "f1_score": f1_score(y_test, predicted, zero_division=0),
        "specificity": tn / (tn + fp) if tn + fp else 0.0,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "roc_auc_score": roc_auc_score(y_test, score),
        "average_precision": average_precision_score(y_test, score),
        "true_negative": int(tn),
        "false_positive": int(fp),
        "false_negative": int(fn),
        "true_positive": int(tp),
    }

metrics = pd.DataFrame([
    calculate_metrics(name, score) for name, score in scores.items()
])

predictions = pd.DataFrame({
    "actual_is_phishing": y_test,
    "ml_risk": ml_risk,
    "html_risk_proxy": html_risk,
    "identity_risk_proxy": identity_risk,
    "contradiction_rule_1": contradiction_1,
    "contradiction_rule_2": contradiction_2,
    "contradiction_bonus": bonus,
    "weighted_without_rules": weighted_without_rules,
    "weighted_with_rules": weighted_with_rules,
})
metrics.to_csv(OUT / "risk_fusion_proxy_metrics.csv", index=False)
predictions.to_csv(OUT / "risk_fusion_proxy_predictions.csv", index=False)

setup = {
    "dataset": "UCI PhiUSIIL, fetched via ucimlrepo id 967",
    "positive_class": "Phishing (original target label 0)",
    "split": "GroupShuffleSplit by normalized Domain, random_state 42",
    "test_filter": "Remove test rows with complete 44-feature vectors in training",
    "fixed_alert_threshold": 0.45,
    "model": "RandomForestClassifier, 100 trees, random_state 42",
    "important_limitation": (
        "HTML and identity scores are dataset-derived proxies, not outputs "
        "from FakeGuard's live feature_engine.py. These results do not "
        "validate the exact live risk engine or imply live-site accuracy."
    ),
    "contradiction_rule_1_cases": int(contradiction_1.sum()),
    "contradiction_rule_2_cases": int(contradiction_2.sum()),
    "any_contradiction_cases": int((bonus > 0).sum()),
    "shared_domains": len(domain_overlap),
    "shared_complete_feature_vectors": len(vector_overlap),
}
(OUT / "risk_fusion_proxy_setup.json").write_text(
    json.dumps(setup, indent=2), encoding="utf-8"
)

print("\n=== Risk Fusion Proxy Results ===")
print(metrics.to_string(index=False, float_format=lambda v: f"{v:.4f}"))
print("\nRule 1 triggered:", int(contradiction_1.sum()), "test cases")
print("Rule 2 triggered:", int(contradiction_2.sum()), "test cases")
print("Any contradiction bonus:", int((bonus > 0).sum()), "test cases")
print("\nSaved:")
print(OUT / "risk_fusion_proxy_metrics.csv")
print(OUT / "risk_fusion_proxy_predictions.csv")
print(OUT / "risk_fusion_proxy_setup.json")
print("\n[6/6] Experiment completed.")

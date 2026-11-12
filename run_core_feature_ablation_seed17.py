
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

OUT = Path("research_results_seed17")
OUT.mkdir(exist_ok=True)

# Conservative feature groups: exclude selected derived/cross-signal features.
URL_FEATURES = [
    "URLLength", "DomainLength", "IsDomainIP",
    "TLDLength", "NoOfSubDomain",
    "HasObfuscation", "NoOfObfuscatedChar", "ObfuscationRatio",
    "NoOfLettersInURL", "LetterRatioInURL",
    "NoOfDegitsInURL", "DegitRatioInURL",
    "NoOfEqualsInURL", "NoOfQMarkInURL",
    "NoOfAmpersandInURL", "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL", "IsHTTPS",
]

PAGE_FEATURES = [
    "LineOfCode", "LargestLineLength", "HasTitle",
    "HasFavicon", "Robots", "IsResponsive",
    "NoOfURLRedirect", "NoOfSelfRedirect",
    "HasDescription", "NoOfPopup", "NoOfiFrame",
    "HasExternalFormSubmit", "HasSocialNet",
    "HasSubmitButton", "HasHiddenFields", "HasPasswordField",
    "Bank", "Pay", "Crypto", "HasCopyrightInfo",
    "NoOfImage", "NoOfCSS", "NoOfJS",
    "NoOfSelfRef", "NoOfEmptyRef", "NoOfExternalRef",
]

EXPERIMENTS = {
    "URL structure only": URL_FEATURES,
    "Webpage/context only": PAGE_FEATURES,
    "Combined core features": URL_FEATURES + PAGE_FEATURES,
    'Combined without top six': [f for f in URL_FEATURES + PAGE_FEATURES if f not in {'LineOfCode', 'NoOfExternalRef', 'NoOfSelfRef', 'NoOfImage', 'NoOfJS', 'NoOfCSS'}],
    "Combined without 10 selected features": [f for f in URL_FEATURES + PAGE_FEATURES if f not in {'LineOfCode', 'NoOfExternalRef', 'NoOfSelfRef', 'NoOfImage', 'NoOfJS', 'NoOfCSS', 'HasSocialNet', 'HasCopyrightInfo', 'HasDescription', 'IsHTTPS'}],
}

print("[1/6] Loading PhiUSIIL dataset...")
ds = fetch_ucirepo(id=967)
X = ds.data.features.copy()

# Original label: 0 = phishing, 1 = legitimate.
y = (ds.data.targets.iloc[:, 0].astype(int) == 0).astype(int)

ALL_FEATURES = URL_FEATURES + PAGE_FEATURES
missing = sorted(set(ALL_FEATURES) - set(X.columns))
if missing:
    raise ValueError(f"Missing dataset features: {missing}")

# Domain is used only for grouping, never as a model feature.
groups = X["Domain"].astype(str).str.strip().str.lower()
if groups.eq("").any():
    raise ValueError("Empty Domain values found.")

numeric = (
    X[ALL_FEATURES]
    .apply(pd.to_numeric, errors="coerce")
    .replace([np.inf, -np.inf], np.nan)
)

print("[2/6] Creating domain-separated split...")
splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=17,
)
train_idx, test_idx = next(
    splitter.split(numeric, y, groups=groups)
)

# Identify exact combined-core feature vectors shared by train/test.
# Missing values use a sentinel only for duplicate detection.
signature_data = numeric.fillna(-999999999.0)
signatures = pd.util.hash_pandas_object(
    signature_data, index=False
).to_numpy(dtype="uint64")

train_signatures = set(signatures[train_idx].tolist())

keep = np.array([
    signature not in train_signatures
    for signature in signatures[test_idx]
])
strict_test_idx = test_idx[keep]

train_domains = set(groups.iloc[train_idx])
test_domains = set(groups.iloc[strict_test_idx])
domain_overlap = train_domains.intersection(test_domains)

feature_overlap = train_signatures.intersection(
    set(signatures[strict_test_idx].tolist())
)

if domain_overlap or feature_overlap:
    raise RuntimeError("Strict separation check failed.")

y_train = y.iloc[train_idx]
y_test = y.iloc[strict_test_idx]

if y_train.nunique() != 2 or y_test.nunique() != 2:
    raise ValueError("Both classes must appear in train and test.")

print("Training rows:", len(train_idx))
print("Original test rows:", len(test_idx))
print("Strict test rows:", len(strict_test_idx))
print("Excluded repeated core vectors:", len(test_idx) - len(strict_test_idx))
print("Shared domains:", len(domain_overlap))
print("Shared core feature vectors:", len(feature_overlap))

results = []
predictions_out = []
importance_out = []

for experiment, features in EXPERIMENTS.items():
    print(f"\n[3/6] Training: {experiment}")
    print("Features:", len(features))

    x_train = numeric.iloc[train_idx][features].copy()
    x_test = numeric.iloc[strict_test_idx][features].copy()

    # Fit imputation values on training data only.
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

    predicted = model.predict(x_test)
    positive_index = list(model.classes_).index(1)
    probability = model.predict_proba(x_test)[:, positive_index]

    tn, fp, fn, tp = confusion_matrix(
        y_test, predicted, labels=[0, 1]
    ).ravel()

    result = {
        "experiment": experiment,
        "feature_count": len(features),
        "train_rows": len(train_idx),
        "strict_test_rows": len(strict_test_idx),
        "accuracy": float(accuracy_score(y_test, predicted)),
        "precision": float(precision_score(
            y_test, predicted, zero_division=0
        )),
        "recall": float(recall_score(
            y_test, predicted, zero_division=0
        )),
        "f1_score": float(f1_score(
            y_test, predicted, zero_division=0
        )),
        "specificity": float(tn / (tn + fp)) if tn + fp else 0.0,
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
        "roc_auc": float(roc_auc_score(y_test, probability)),
        "average_precision": float(
            average_precision_score(y_test, probability)
        ),
        "true_negative": int(tn),
        "false_positive": int(fp),
        "false_negative": int(fn),
        "true_positive": int(tp),
    }
    results.append(result)

    for name, importance in zip(features, model.feature_importances_):
        importance_out.append({
            "experiment": experiment,
            "feature": name,
            "importance": float(importance),
        })

    predictions_out.append(pd.DataFrame({
        "experiment": experiment,
        "test_row_position": strict_test_idx,
        "actual_is_phishing": y_test.to_numpy(),
        "predicted_is_phishing": predicted,
        "phishing_probability": probability,
    }))

    print(
        f"Accuracy={result['accuracy']:.4f}, "
        f"Precision={result['precision']:.4f}, "
        f"Recall={result['recall']:.4f}, "
        f"F1={result['f1_score']:.4f}"
    )

print("\n[4/6] Saving results...")
results_df = pd.DataFrame(results)
results_df.to_csv(OUT / "core_feature_comparison.csv", index=False)

pd.DataFrame(importance_out).to_csv(
    OUT / "core_feature_importances.csv", index=False
)

pd.concat(predictions_out, ignore_index=True).to_csv(
    OUT / "core_feature_predictions.csv", index=False
)

setup = {
    "dataset": "UCI PhiUSIIL",
    "split": "GroupShuffleSplit by normalized Domain",
    "random_state": 42,
    "positive_class": "phishing (original label 0)",
    "excluded_features": [
        "CharContinuationRate",
        "URLTitleMatchScore",
        "DomainTitleMatchScore",
        "URLSimilarityIndex",
        "URLCharProb",
        "TLDLegitimateProb",
    ],
    "train_rows": int(len(train_idx)),
    "original_test_rows": int(len(test_idx)),
    "strict_test_rows": int(len(strict_test_idx)),
    "shared_domains": len(domain_overlap),
    "shared_core_vectors": len(feature_overlap),
}
(OUT / "core_feature_experiment_setup.json").write_text(
    json.dumps(setup, indent=2), encoding="utf-8"
)

print("[5/6] Comparison summary")
display_cols = [
    "experiment", "feature_count", "accuracy", "precision",
    "recall", "f1_score", "false_positive_rate", "roc_auc",
]
print(results_df[display_cols].to_string(index=False))

print("[6/6] Experiment complete.")
print("Results saved in:", OUT.resolve())

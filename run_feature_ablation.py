
from pathlib import Path
import json
import time

import numpy as np
import pandas as pd
from ucimlrepo import fetch_ucirepo
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit
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

# URL-structure features.
# Deliberately exclude derived probability/similarity scores.
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

# Page/context features, including matching between page title,
# domain and URL. These are precomputed dataset features.
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

EXPERIMENTS = {
    "URL structure only": URL_FEATURES,
    "Webpage/context only": PAGE_FEATURES,
    "Combined": URL_FEATURES + PAGE_FEATURES,
}

print("[1/5] Loading PhiUSIIL dataset...")
dataset = fetch_ucirepo(id=967)
X = dataset.data.features.copy()
raw_labels = dataset.data.targets.iloc[:, 0].astype(int)

# Positive class = phishing.
y = (raw_labels == 0).astype(int)

required = sorted(set(URL_FEATURES + PAGE_FEATURES))
missing = sorted(set(required) - set(X.columns))
if missing:
    raise ValueError(f"Dataset is missing these features: {missing}")

# Domain is used ONLY to prevent the same domain appearing in both
# train and test. It is not passed as a model feature.
if "Domain" not in X.columns:
    raise ValueError("The dataset has no Domain column for grouped splitting.")

groups = (
    X["Domain"].astype(str).str.strip().str.lower()
)
if groups.eq("").any():
    raise ValueError("Some rows have an empty Domain; inspect the data first.")

print("[2/5] Preparing a domain-separated 80/20 split...")
splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42,
)
train_idx, test_idx = next(splitter.split(X, y, groups=groups))

y_train = y.iloc[train_idx]
y_test = y.iloc[test_idx]

if y_train.nunique() != 2 or y_test.nunique() != 2:
    raise ValueError(
        "A split does not contain both classes. Review the split before "
        "reporting results."
    )

train_domains = set(groups.iloc[train_idx])
test_domains = set(groups.iloc[test_idx])
overlap = train_domains.intersection(test_domains)

if overlap:
    raise RuntimeError("Domain leakage detected between train and test.")

print(f"Training rows: {len(train_idx)}")
print(f"Testing rows: {len(test_idx)}")
print(f"Training domains: {len(train_domains)}")
print(f"Testing domains: {len(test_domains)}")
print("Shared domains across partitions:", len(overlap))
print("Positive class: phishing (label 0)")

all_metrics = []
all_importances = []
all_predictions = []

for experiment_name, columns in EXPERIMENTS.items():
    print(f"\n[3/5] Training experiment: {experiment_name}")
    print(f"Number of features: {len(columns)}")

    # Ensure numeric inputs and handle any unexpected missing values
    # using medians calculated from training data only.
    x_train = X.iloc[train_idx][columns].apply(
        pd.to_numeric, errors="coerce"
    ).copy()
    x_test = X.iloc[test_idx][columns].apply(
        pd.to_numeric, errors="coerce"
    ).copy()

    medians = x_train.median().fillna(0)
    x_train = x_train.fillna(medians).fillna(0)
    x_test = x_test.fillna(medians).fillna(0)

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced_subsample",
    )

    start = time.perf_counter()
    model.fit(x_train, y_train)
    training_seconds = time.perf_counter() - start

    start = time.perf_counter()
    predictions = model.predict(x_test)
    probabilities = model.predict_proba(x_test)[
        :, list(model.classes_).index(1)
    ]
    prediction_seconds = time.perf_counter() - start

    tn, fp, fn, tp = confusion_matrix(
        y_test, predictions, labels=[0, 1]
    ).ravel()

    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    metrics = {
        "experiment": experiment_name,
        "features": len(columns),
        "train_rows": len(train_idx),
        "test_rows": len(test_idx),
        "accuracy": accuracy_score(y_test, predictions),
        "precision": precision_score(
            y_test, predictions, zero_division=0
        ),
        "recall": recall_score(
            y_test, predictions, zero_division=0
        ),
        "f1_score": f1_score(
            y_test, predictions, zero_division=0
        ),
        "specificity": specificity,
        "false_positive_rate": fpr,
        "roc_auc": roc_auc_score(y_test, probabilities),
        "average_precision": average_precision_score(
            y_test, probabilities
        ),
        "true_negative": int(tn),
        "false_positive": int(fp),
        "false_negative": int(fn),
        "true_positive": int(tp),
        "training_seconds": round(training_seconds, 3),
        "prediction_seconds": round(prediction_seconds, 3),
    }

    all_metrics.append(metrics)

    for feature, importance in zip(
        columns, model.feature_importances_
    ):
        all_importances.append({
            "experiment": experiment_name,
            "feature": feature,
            "importance": float(importance),
        })

    all_predictions.append(pd.DataFrame({
        "experiment": experiment_name,
        "test_row_position": test_idx,
        "actual_is_phishing": y_test.to_numpy(),
        "predicted_is_phishing": predictions,
        "phishing_probability": probabilities,
    }))

    print(
        f"Accuracy={metrics['accuracy']:.4f}, "
        f"Precision={metrics['precision']:.4f}, "
        f"Recall={metrics['recall']:.4f}, "
        f"F1={metrics['f1_score']:.4f}"
    )

print("\n[4/5] Saving experiment results...")
metrics_df = pd.DataFrame(all_metrics)
metrics_df.to_csv(OUT / "feature_group_comparison.csv", index=False)

pd.DataFrame(all_importances).to_csv(
    OUT / "feature_importances_by_group.csv", index=False
)

pd.concat(all_predictions, ignore_index=True).to_csv(
    OUT / "feature_group_test_predictions.csv", index=False
)

split_summary = {
    "dataset": "UCI PhiUSIIL Phishing URL (Website)",
    "dataset_rows": int(len(X)),
    "feature_groups": {
        name: columns for name, columns in EXPERIMENTS.items()
    },
    "excluded_derived_features": [
        "URLSimilarityIndex",
        "TLDLegitimateProb",
        "URLCharProb",
    ],
    "positive_class": "phishing (original dataset label 0)",
    "split_method": "GroupShuffleSplit by Domain",
    "random_state": 42,
    "train_rows": int(len(train_idx)),
    "test_rows": int(len(test_idx)),
    "train_domains": len(train_domains),
    "test_domains": len(test_domains),
    "overlapping_domains": len(overlap),
    "training_model": "RandomForestClassifier",
    "n_estimators": 100,
}

(OUT / "feature_group_experiment_setup.json").write_text(
    json.dumps(split_summary, indent=2),
    encoding="utf-8",
)

print("[5/5] Finished.\n")
columns_to_show = [
    "experiment", "features", "accuracy", "precision", "recall",
    "f1_score", "specificity", "false_positive_rate", "roc_auc",
]
print(metrics_df[columns_to_show].to_string(
    index=False,
    formatters={
        column: "{:.4f}".format
        for column in [
            "accuracy", "precision", "recall", "f1_score",
            "specificity", "false_positive_rate", "roc_auc",
        ]
    },
))

print(f"\nFiles saved in: {OUT.resolve()}")

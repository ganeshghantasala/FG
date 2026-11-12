
from pathlib import Path
import pandas as pd
from ucimlrepo import fetch_ucirepo
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import roc_auc_score

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
DERIVED_FEATURES = {
    "CharContinuationRate",
    "URLTitleMatchScore",
}

print("[1/5] Loading dataset...")
ds = fetch_ucirepo(id=967)
X = ds.data.features.copy()
y = (ds.data.targets.iloc[:, 0].astype(int) == 0).astype(int)

# Reproduce the domain-separated split from the main experiment.
groups = X["Domain"].astype(str).str.strip().str.lower()
splitter = GroupShuffleSplit(
    n_splits=1, test_size=0.20, random_state=42
)
train_idx, test_idx = next(
    splitter.split(X, y, groups=groups)
)

y_test = y.iloc[test_idx]
X_test = X.iloc[test_idx][FEATURES].copy()
X_numeric = X[FEATURES].apply(
    pd.to_numeric, errors="coerce"
).fillna(0)

print("[2/5] Auditing individual feature predictiveness...")
rows = []

for feature in FEATURES:
    values = pd.to_numeric(
        X_test[feature], errors="coerce"
    ).fillna(0)

    if values.nunique() < 2:
        auc = None
        best_auc = None
        direction = "constant"
    else:
        auc = roc_auc_score(y_test, values)
        best_auc = max(auc, 1 - auc)
        direction = (
            "higher values associate with phishing"
            if auc >= 0.5
            else "lower values associate with phishing"
        )

    rows.append({
        "feature": feature,
        "test_auc_raw": auc,
        "best_direction_auc": best_auc,
        "direction": direction,
        "derived_feature": feature in DERIVED_FEATURES,
    })

audit = pd.DataFrame(rows)

importance_path = OUT / "feature_importances_by_group.csv"
if importance_path.exists():
    importance = pd.read_csv(importance_path)
    importance = importance[
        importance["experiment"] == "Combined"
    ][["feature", "importance"]]
    audit = audit.merge(importance, on="feature", how="left")

audit = audit.sort_values(
    "best_direction_auc", ascending=False, na_position="last"
)
audit.to_csv(OUT / "feature_leakage_audit.csv", index=False)

print("\nTop 12 individual features by test-set AUC:")
print(audit.head(12).to_string(index=False))

if "importance" in audit.columns:
    print("\nTop 12 features by Random Forest importance:")
    print(
        audit.sort_values("importance", ascending=False)
        .head(12)[["feature", "importance", "best_direction_auc"]]
        .to_string(index=False)
    )

print("\n[3/5] Checking exact feature-vector duplicates...")
signatures = pd.util.hash_pandas_object(
    X_numeric, index=False
).astype("uint64")

train_signatures = set(signatures.iloc[train_idx].tolist())
test_signatures = signatures.iloc[test_idx]

overlapping_rows = int(test_signatures.isin(train_signatures).sum())

signature_labels = pd.DataFrame({
    "signature": signatures,
    "label": y.to_numpy(),
})
label_counts = signature_labels.groupby(
    "signature"
)["label"].nunique()

conflicting_signatures = int((label_counts > 1).sum())

print("Test rows with an identical training feature vector:",
      overlapping_rows)
print("Unique feature vectors associated with both labels:",
      conflicting_signatures)

print("\n[4/5] Checking domain separation...")
train_domains = set(groups.iloc[train_idx])
test_domains = set(groups.iloc[test_idx])
domain_overlap = train_domains.intersection(test_domains)

print("Shared domains:", len(domain_overlap))
print("Training rows:", len(train_idx))
print("Testing rows:", len(test_idx))

print("\n[5/5] Saving summary...")
summary = [
    "FakeGuard feature audit",
    f"Training rows: {len(train_idx)}",
    f"Testing rows: {len(test_idx)}",
    f"Shared domains: {len(domain_overlap)}",
    f"Test rows with identical training feature vectors: {overlapping_rows}",
    f"Feature vectors associated with both labels: {conflicting_signatures}",
    "",
    "Top individual features by AUC:",
    audit.head(12).to_string(index=False),
]

(OUT / "feature_audit_summary.txt").write_text(
    "\n".join(summary),
    encoding="utf-8",
)

print("Saved feature_leakage_audit.csv")
print("Saved feature_audit_summary.txt")
print("\nAudit completed.")

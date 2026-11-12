
from pathlib import Path

import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score
)

OUT = Path("research_results")
source = OUT / "core_feature_predictions.csv"

if not source.exists():
    raise FileNotFoundError(
        "Run run_core_feature_ablation.py first."
    )

df = pd.read_csv(source)

required = {
    "experiment",
    "test_row_position",
    "actual_is_phishing",
    "predicted_is_phishing",
    "phishing_probability",
}
if not required.issubset(df.columns):
    raise ValueError(f"Missing columns: {required - set(df.columns)}")

wide = df.pivot(
    index="test_row_position",
    columns="experiment",
    values="phishing_probability",
)

labels = df.drop_duplicates("test_row_position").set_index(
    "test_row_position"
)["actual_is_phishing"]

expected = [
    "URL structure only",
    "Webpage/context only",
    "Combined core features",
]
if not set(expected).issubset(wide.columns):
    raise ValueError("Expected model predictions are missing.")

wide = wide[expected].join(labels)
wide = wide.dropna()

y = wide["actual_is_phishing"].astype(int)

url_p = wide["URL structure only"]
page_p = wide["Webpage/context only"]
combined_p = wide["Combined core features"]

url_pred = (url_p >= 0.5).astype(int)
page_pred = (page_p >= 0.5).astype(int)
combined_pred = (combined_p >= 0.5).astype(int)

# Simple, pre-specified late fusion: average the two probabilities.
fusion_p = (url_p + page_p) / 2
fusion_pred = (fusion_p >= 0.5).astype(int)

def metrics(name, prediction):
    return {
        "model": name,
        "accuracy": accuracy_score(y, prediction),
        "precision": precision_score(y, prediction, zero_division=0),
        "recall": recall_score(y, prediction, zero_division=0),
        "f1_score": f1_score(y, prediction, zero_division=0),
    }

results = pd.DataFrame([
    metrics("URL only", url_pred),
    metrics("Webpage only", page_pred),
    metrics("Combined core features", combined_pred),
    metrics("Late fusion: mean probability", fusion_pred),
])

disagreement = url_pred != page_pred
subset = wide.loc[disagreement]

print("=== Signal Fusion Analysis ===")
print("Test examples:", len(wide))
print("URL/page disagreement cases:", int(disagreement.sum()))
print("Disagreement rate:", round(float(disagreement.mean()), 6))

if len(subset):
    disagree_y = subset["actual_is_phishing"].astype(int)
    print("\nAccuracy on disagreement cases:")
    for name, prediction in [
        ("URL only", url_pred),
        ("Webpage only", page_pred),
        ("Combined", combined_pred),
        ("Late fusion", fusion_pred),
    ]:
        selected = prediction.loc[disagreement]
        print(
            f"{name}: "
            f"{accuracy_score(disagree_y, selected):.4f}"
        )

results.to_csv(OUT / "signal_fusion_metrics.csv", index=False)

case_output = pd.DataFrame({
    "actual_is_phishing": y,
    "url_probability": url_p,
    "page_probability": page_p,
    "combined_probability": combined_p,
    "fusion_probability": fusion_p,
    "url_prediction": url_pred,
    "page_prediction": page_pred,
    "combined_prediction": combined_pred,
    "fusion_prediction": fusion_pred,
    "signals_disagree": disagreement,
})
case_output.loc[disagreement].to_csv(
    OUT / "signal_disagreement_cases.csv"
)

print("\n=== Overall comparison ===")
print(results.to_string(index=False, float_format=lambda x: f"{x:.4f}"))
print("\nSaved:")
print(OUT / "signal_fusion_metrics.csv")
print(OUT / "signal_disagreement_cases.csv")


from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix,
)

path = Path("research_results/risk_fusion_proxy_predictions.csv")
df = pd.read_csv(path)

y = df["actual_is_phishing"].astype(int).to_numpy()
base = df["weighted_without_rules"].to_numpy()
rule1 = df["contradiction_rule_1"].astype(bool).to_numpy()
rule2 = df["contradiction_rule_2"].astype(bool).to_numpy()

scores = {
    "ML only": df["ml_risk"].to_numpy(),
    "Weighted fusion, no rules": base,
    "Rule 1 only (+0.18)": np.clip(base + 0.18 * rule1, 0, 1),
    "Rule 2 only (+0.12)": np.clip(base + 0.12 * rule2, 0, 1),
    "Both contradiction rules": df["weighted_with_rules"].to_numpy(),
}

def report(name, score):
    pred = score >= 0.45
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    print(
        f"{name}: accuracy={accuracy_score(y, pred):.4f}, "
        f"precision={precision_score(y, pred, zero_division=0):.4f}, "
        f"recall={recall_score(y, pred, zero_division=0):.4f}, "
        f"F1={f1_score(y, pred, zero_division=0):.4f}, "
        f"FP={fp}, FN={fn}"
    )

print("\n=== Individual Contradiction Rule Audit ===")
for name, score in scores.items():
    report(name, score)

print("\n=== Trigger Counts by True Class ===")
for name, triggered in [("Rule 1", rule1), ("Rule 2", rule2)]:
    print(
        f"{name}: total={int(triggered.sum())}, "
        f"phishing={int(((y == 1) & triggered).sum())}, "
        f"legitimate={int(((y == 0) & triggered).sum())}"
    )

base_alert = base >= 0.45
both_alert = scores["Both contradiction rules"] >= 0.45

print("\n=== Effect of Adding Both Rules ===")
print("Additional total alerts:", int((both_alert & ~base_alert).sum()))
print(
    "Additional legitimate websites flagged:",
    int(((y == 0) & both_alert & ~base_alert).sum())
)
print(
    "Additional phishing websites correctly flagged:",
    int(((y == 1) & both_alert & ~base_alert).sum())
)

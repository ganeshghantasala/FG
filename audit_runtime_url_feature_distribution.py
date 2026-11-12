"""Offline audit: compare runtime URL-feature values with UCI 327 training values.

This script makes no URL requests and does not change FakeGuard or its models.
It fetches the UCI dataset metadata/data through ucimlrepo, then reconstructs
URL-only features for the already-saved sample manifest. HTML-derived features
are intentionally excluded because the sample manifest does not store page HTML.
"""
from __future__ import annotations

from pathlib import Path
import sys
import pandas as pd
import joblib
from ucimlrepo import fetch_ucirepo
from feature_engine import extract_features

ROOT = Path(__file__).resolve().parent
OUT_DIR = ROOT / "research_results_external_fresh"
MANIFEST = OUT_DIR / "fresh_sample_manifest.csv"
RESULTS = OUT_DIR / "fresh_external_validation_results_after_brand_warning.csv"
OUTPUT = OUT_DIR / "runtime_url_feature_distribution_audit.csv"

URL_FEATURE_MAP = {
    "having_ip_address": "having_IP_Address",
    "url_length": "URL_Length",
    "shortining_service": "Shortining_Service",
    "having_at_symbol": "having_At_Symbol",
    "double_slash_redirecting": "double_slash_redirecting",
    "prefix_suffix": "Prefix_Suffix",
    "having_sub_domain": "having_Sub_Domain",
    "sslfinal_state": "sslfinal_state",
    "port": "port",
    "https_token": "https_token",
    "abnormal_url": "Abnormal_URL",
}


def main() -> int:
    if not MANIFEST.exists() or not RESULTS.exists():
        print("Saved fresh manifest/results not found. Ensure you run this in FakeGuard-main.")
        return 2

    bundle = joblib.load(ROOT / "fakeguard_model_runtime.joblib")
    features = [str(x).lower() for x in bundle["feature_names"]]
    ds = fetch_ucirepo(id=327)
    train_x = ds.data.features.copy()
    train_y = (ds.data.targets.iloc[:, 0] == -1).astype(int)

    # Confirm the runtime bundle uses dataset columns by exact name.
    missing = [name for name in features if name not in train_x.columns]
    if missing:
        print("Runtime features missing from UCI 327:", missing)
        return 1

    manifest = pd.read_csv(MANIFEST, dtype=str, keep_default_na=False)
    results = pd.read_csv(RESULTS, dtype=str, keep_default_na=False)
    result_by_row = {str(row["sample_row"]): row for _, row in results.iterrows()}

    records = []
    for _, row in manifest.iterrows():
        sample_row = str(row["sample_row"])
        result = result_by_row.get(sample_row, {})
        submitted_url = str(row.get("url", ""))
        final_url = str(result.get("final_url", "")) or submitted_url
        try:
            live_features, _ = extract_features(final_url, "", original_url=submitted_url)
        except Exception as exc:
            print(f"Could not extract row {sample_row}: {exc}")
            continue

        for model_name, runtime_key in URL_FEATURE_MAP.items():
            if model_name not in features:
                continue
            training_col = pd.to_numeric(train_x[model_name], errors="coerce")
            live_value = live_features.get(runtime_key)
            train_values = set(training_col.dropna().unique().tolist())
            records.append({
                "sample_row": sample_row,
                "source": str(row.get("source", "")),
                "source_label": str(row.get("source_label", "")),
                "scan_status": str(result.get("scan_status", "")),
                "submitted_url": submitted_url,
                "feature": model_name,
                "runtime_value_without_html": live_value,
                "training_observed_values": ",".join(map(str, sorted(train_values))),
                "runtime_value_in_training_support": live_value in train_values,
                "train_phishing_minus1_rate": float((training_col[train_y.eq(1)] == -1).mean()),
                "train_phishing_zero_rate": float((training_col[train_y.eq(1)] == 0).mean()),
                "train_phishing_plus1_rate": float((training_col[train_y.eq(1)] == 1).mean()),
                "train_legitimate_minus1_rate": float((training_col[train_y.eq(0)] == -1).mean()),
                "train_legitimate_zero_rate": float((training_col[train_y.eq(0)] == 0).mean()),
                "train_legitimate_plus1_rate": float((training_col[train_y.eq(0)] == 1).mean()),
            })

    audit = pd.DataFrame(records)
    audit.to_csv(OUTPUT, index=False, encoding="utf-8")

    print("OFFLINE AUDIT ONLY: no URLs fetched; no model or application files changed.")
    print("Runtime model features:", len(features))
    print("Checked URL-derived features:", len([x for x in URL_FEATURE_MAP if x in features]))
    print("Saved sample rows:", len(manifest))
    if len(audit):
        print("URL-feature cells outside training value support:", int((~audit["runtime_value_in_training_support"]).sum()), "of", len(audit))
        print("By feature (rows in saved sample, no HTML supplied):")
        summary = audit.groupby("feature").agg(
            rows=("sample_row", "count"),
            distinct_runtime_values=("runtime_value_without_html", "nunique"),
            out_of_support=("runtime_value_in_training_support", lambda s: int((~s).sum())),
        )
        print(summary.to_string())
        print("\nFirst 25 feature rows:")
        print(audit[["sample_row", "source", "feature", "runtime_value_without_html", "training_observed_values", "runtime_value_in_training_support"]].head(25).to_string(index=False))
    print("\nDetailed CSV:", OUTPUT)
    print("LIMITATION: Empty HTML is used intentionally; this checks URL-derived inputs only, not the full live feature vector.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

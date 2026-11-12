"""Small, reproducible pilot for FakeGuard external-source validation.

Default mode prepares and previews a manifest. Pass --scan to fetch selected
URLs through FakeGuard's local Flask test client. Pass --repair-existing to
recalculate the saved pilot results without sending new network requests.

FakeGuard's API returns score/ml/html/identity in percentage points (0-100),
so this evaluator uses a 45.0 percentage-point threshold, not 0.45.
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent
PHISHTANK = ROOT / "phishtank_online_valid.csv"
TRANCO = ROOT / "tranco.csv"
OUT_DIR = ROOT / "research_results_external"
MANIFEST_PATH = OUT_DIR / "sample_manifest.csv"
RESULTS_PATH = OUT_DIR / "external_validation_results.csv"
SUMMARY_PATH = OUT_DIR / "external_validation_summary.json"

SEED = 17
PHISH_SAMPLE_SIZE = 10
POPULAR_CANDIDATE_SAMPLE_SIZE = 10
TRANCO_CANDIDATE_POOL_SIZE = 5000
RISK_THRESHOLD = 45.0  # API score is percentage points on a 0-100 scale.
PAUSE_BETWEEN_REQUESTS_SECONDS = 1.0


def require_files() -> None:
    missing = [str(p.name) for p in (PHISHTANK, TRANCO) if not p.is_file()]
    if missing:
        raise FileNotFoundError(
            "Required file(s) missing from the same folder as this script: "
            + ", ".join(missing)
        )


def make_manifest() -> pd.DataFrame:
    require_files()
    OUT_DIR.mkdir(exist_ok=True)

    ph = pd.read_csv(PHISHTANK, dtype=str, keep_default_na=False)
    required = {"url", "verified", "online", "phish_id", "submission_time"}
    if not required.issubset(ph.columns):
        raise ValueError(f"PhishTank CSV is missing columns: {sorted(required - set(ph.columns))}")
    ph["url"] = ph["url"].astype(str).str.strip()
    ph = ph[
        ph["url"].ne("")
        & ph["verified"].str.strip().str.lower().eq("yes")
        & ph["online"].str.strip().str.lower().eq("yes")
    ].drop_duplicates(subset=["url"])
    if ph.empty:
        raise ValueError("No eligible verified/online PhishTank URL rows were found.")
    ph_sample = ph.sample(n=min(PHISH_SAMPLE_SIZE, len(ph)), random_state=SEED).copy()
    ph_rows = pd.DataFrame({
        "source": "PhishTank",
        "source_label": "verified_phishing",
        "source_id": ph_sample["phish_id"].astype(str),
        "source_timestamp": ph_sample["submission_time"].astype(str),
        "url": ph_sample["url"].astype(str),
    })

    tr = pd.read_csv(
        TRANCO, header=None, names=["rank", "domain"], dtype=str,
        keep_default_na=False, nrows=TRANCO_CANDIDATE_POOL_SIZE,
    )
    tr["rank"] = tr["rank"].astype(str).str.strip()
    tr["domain"] = tr["domain"].astype(str).str.strip().str.lower()
    tr = tr[tr["domain"].ne("")].drop_duplicates(subset=["domain"])
    if tr.empty:
        raise ValueError("No Tranco domains were found in the selected candidate pool.")
    tr_sample = tr.sample(n=min(POPULAR_CANDIDATE_SAMPLE_SIZE, len(tr)), random_state=SEED).copy()
    tr_sample["url"] = tr_sample["domain"].map(
        lambda d: d if d.startswith(("http://", "https://")) else "https://" + d
    )
    tr_rows = pd.DataFrame({
        "source": "Tranco",
        "source_label": "popular_domain_candidate",
        "source_id": tr_sample["rank"].astype(str),
        "source_timestamp": "",
        "url": tr_sample["url"].astype(str),
    })
    manifest = pd.concat([ph_rows, tr_rows], ignore_index=True)
    manifest.insert(0, "sample_row", range(1, len(manifest) + 1))
    manifest.to_csv(MANIFEST_PATH, index=False, encoding="utf-8")
    return manifest


def preview(manifest: pd.DataFrame) -> None:
    print("Sample manifest prepared; no URLs have been scanned.")
    print(f"Manifest: {MANIFEST_PATH}")
    print(f"Rows: {len(manifest)} | Seed: {SEED}")
    print("Selected records by source:")
    print(manifest.groupby(["source", "source_label"]).size().to_string())
    print("\nSelected PhishTank record IDs and feed timestamps:")
    p = manifest[manifest["source"].eq("PhishTank")]
    print(p[["source_id", "source_timestamp"]].to_string(index=False))
    print("\nSelected Tranco ranks:")
    t = manifest[manifest["source"].eq("Tranco")]
    print(", ".join(t["source_id"].astype(str).tolist()))
    print("\nNote: Tranco popularity is not ground-truth evidence that a site is benign.")
    print("To make live requests through FakeGuard's local fetcher, rerun with --scan.")


def as_score(value) -> float | None:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if not 0.0 <= score <= 100.0:
        return None
    return score


def classify_result(row: dict) -> dict:
    """Normalize one saved/API result; no network access occurs here."""
    try:
        http_status = int(row.get("http_status"))
    except (TypeError, ValueError):
        http_status = None
    score = as_score(row.get("risk_score"))
    has_api_result = bool(row.get("app_label")) or bool(row.get("app_class"))
    success = http_status == 200 and score is not None and has_api_result
    source_label = str(row.get("source_label", ""))
    flagged = bool(score >= RISK_THRESHOLD) if success else None
    if not success:
        outcome = "fetch_or_api_failure"
    elif source_label == "verified_phishing":
        outcome = "TP" if flagged else "FN"
    else:
        outcome = "flagged_popular_domain_candidate" if flagged else "not_flagged_popular_domain_candidate"
    row.update({
        "http_status": http_status,
        "scan_status": "success" if success else "failure",
        "risk_score": score,
        "threshold": RISK_THRESHOLD,
        "flagged_as_suspicious": flagged,
        "outcome": outcome,
    })
    return row


def make_summary(results: pd.DataFrame) -> dict:
    ph = results[results["source_label"].eq("verified_phishing")]
    tr = results[results["source_label"].eq("popular_domain_candidate")]
    ph_ok = ph[ph["scan_status"].eq("success")]
    tr_ok = tr[tr["scan_status"].eq("success")]
    tp = int((ph_ok["outcome"] == "TP").sum())
    fn = int((ph_ok["outcome"] == "FN").sum())
    flagged_candidates = int(tr_ok["flagged_as_suspicious"].fillna(False).sum())
    return {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "sampling_seed": SEED,
        "risk_score_scale": "percentage points, 0 to 100",
        "risk_threshold_percentage_points": RISK_THRESHOLD,
        "phish_sample_requested": PHISH_SAMPLE_SIZE,
        "popular_domain_candidate_sample_requested": POPULAR_CANDIDATE_SAMPLE_SIZE,
        "tranco_candidate_pool_size": TRANCO_CANDIDATE_POOL_SIZE,
        "total_rows": int(len(results)),
        "successful_scans": int((results["scan_status"] == "success").sum()),
        "failed_scans": int((results["scan_status"] == "failure").sum()),
        "verified_phishing_successful_scans": int(len(ph_ok)),
        "verified_phishing_TP": tp,
        "verified_phishing_FN": fn,
        "verified_phishing_detection_rate_among_successful_scans": (tp / len(ph_ok)) if len(ph_ok) else None,
        "popular_domain_candidate_successful_scans": int(len(tr_ok)),
        "popular_domain_candidates_flagged": flagged_candidates,
        "popular_domain_candidate_flag_rate_not_a_false_positive_rate": (flagged_candidates / len(tr_ok)) if len(tr_ok) else None,
        "results_csv": str(RESULTS_PATH),
        "important_limitations": [
            "This is a small exploratory pilot, not a publication-grade estimate.",
            "PhishTank online status can change between feed download and scan time.",
            "Tranco supplies popular-domain candidates, not confirmed benign labels.",
            "Fetch failures are excluded from detection-rate denominators and reported separately.",
            "Live results can change with site content, redirects, hosting, and time.",
            "The existing pilot was re-scored from its saved API responses; no new sites were contacted during repair.",
        ],
    }


def write_summary(results: pd.DataFrame) -> None:
    results.to_csv(RESULTS_PATH, index=False, encoding="utf-8")
    summary = make_summary(results)
    SUMMARY_PATH.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print("\nCorrected summary:")
    print(json.dumps(summary, indent=2))
    print(f"\nResults saved locally to: {RESULTS_PATH}")
    print(f"Summary saved locally to: {SUMMARY_PATH}")


def repair_existing() -> None:
    if not RESULTS_PATH.exists():
        raise FileNotFoundError(f"No saved results to repair: {RESULTS_PATH}")
    old = pd.read_csv(RESULTS_PATH, keep_default_na=False)
    rows = [classify_result(r) for r in old.to_dict(orient="records")]
    fixed = pd.DataFrame(rows)
    print("Reclassifying saved results only; no URLs will be fetched.")
    print("Threshold: 45.0 on FakeGuard API's 0-100 percentage-point score scale.")
    print("Valid scan = HTTP 200 + numeric 0-100 score + API label/class.")
    print("\nRows by source, status and outcome:")
    print(fixed.groupby(["source", "scan_status", "outcome"], dropna=False).size().to_string())
    write_summary(fixed)


def scan(manifest: pd.DataFrame) -> None:
    import app as fakeguard  # noqa: WPS433
    client = fakeguard.app.test_client()
    records: list[dict] = []
    total = len(manifest)
    print("LIVE SCAN ENABLED: the selected sites will be fetched through app.py.")
    print("Do not browse to these URLs manually. Failures will be recorded, not hidden.")
    print("API scores are treated as percentage points (0-100); alert threshold = 45.0.\n")

    for _, row in manifest.iterrows():
        start = time.monotonic()
        http_status = None
        data = {}
        exception_text = ""
        try:
            response = client.post("/api/analyze", json={"url": str(row["url"])})
            http_status = int(response.status_code)
            data = response.get_json(silent=True) or {}
        except Exception as exc:  # preserve row-level failures in the audit file
            exception_text = f"{type(exc).__name__}: {str(exc)[:180]}"

        raw_score = data.get("score") if isinstance(data, dict) else None
        score = as_score(raw_score)
        rec = {
            "sample_row": int(row["sample_row"]),
            "source": str(row["source"]),
            "source_label": str(row["source_label"]),
            "source_id": str(row["source_id"]),
            "source_timestamp": str(row["source_timestamp"]),
            "url": str(row["url"]),
            "http_status": http_status,
            "scan_status": "failure",
            "risk_score": score,
            "threshold": RISK_THRESHOLD,
            "flagged_as_suspicious": None,
            "app_label": data.get("label") if isinstance(data, dict) else None,
            "app_class": data.get("cls") if isinstance(data, dict) else None,
            "final_url": data.get("final_url") if isinstance(data, dict) else None,
            "outcome": "fetch_or_api_failure",
            "error": (str(data.get("error", ""))[:180] if isinstance(data, dict) else "") or exception_text,
            "duration_seconds": round(time.monotonic() - start, 3),
        }
        rec = classify_result(rec)
        records.append(rec)
        print(
            f"[{len(records)}/{total}] {rec['source']} ID/rank={rec['source_id']} "
            f"status={rec['scan_status']} HTTP={http_status} "
            f"risk={score if score is not None else 'n/a'} outcome={rec['outcome']}"
        )
        time.sleep(PAUSE_BETWEEN_REQUESTS_SECONDS)

    write_summary(pd.DataFrame(records))


def main() -> int:
    try:
        if "--repair-existing" in sys.argv[1:]:
            repair_existing()
            return 0
        manifest = make_manifest()
        if "--scan" in sys.argv[1:]:
            scan(manifest)
        else:
            preview(manifest)
        return 0
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Fresh external-source pilot for FakeGuard.

Default mode: build/preview a manifest only; no URLs are fetched.
--scan: fetch selected URLs through FakeGuard's existing local Flask app.

Sampling uses PhishTank entries whose verification_time is within the last
24 hours at manifest-creation time, plus a reproducible sample of domains from
the first 5,000 Tranco rows. Tranco entries are candidate controls, not known
benign ground truth.

Writes only to research_results_external_fresh/ and does not modify the older
pilot or the benchmark result folders.
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd

ROOT = Path(__file__).resolve().parent
PHISHTANK = ROOT / "phishtank_online_valid.csv"
TRANCO = ROOT / "tranco.csv"
OUT_DIR = ROOT / "research_results_external_fresh"
MANIFEST_PATH = OUT_DIR / "fresh_sample_manifest.csv"
RESULTS_PATH = OUT_DIR / "fresh_external_validation_results.csv"
SUMMARY_PATH = OUT_DIR / "fresh_external_validation_summary.json"

SEED = 43
PHISH_SAMPLE_SIZE = 10
POPULAR_CANDIDATE_SAMPLE_SIZE = 10
TRANCO_CANDIDATE_POOL_SIZE = 5000
FRESHNESS_HOURS = 24
RISK_THRESHOLD = 45.0  # API uses percentage points, on a 0-100 scale.
PAUSE_BETWEEN_REQUESTS_SECONDS = 1.0


def require_files() -> None:
    missing = [p.name for p in (PHISHTANK, TRANCO) if not p.is_file()]
    if missing:
        raise FileNotFoundError(
            "Required file(s) must be in the same folder as this script: "
            + ", ".join(missing)
        )


def prepare_manifest() -> tuple[pd.DataFrame, dict]:
    require_files()
    OUT_DIR.mkdir(exist_ok=True)
    created = datetime.now(timezone.utc)
    cutoff = created - timedelta(hours=FRESHNESS_HOURS)

    ph = pd.read_csv(PHISHTANK, dtype=str, keep_default_na=False)
    required = {"url", "phish_id", "verified", "online", "verification_time"}
    missing = required - set(ph.columns)
    if missing:
        raise ValueError(f"PhishTank CSV is missing columns: {sorted(missing)}")
    ph["url"] = ph["url"].astype(str).str.strip()
    ph["verification_time_parsed"] = pd.to_datetime(
        ph["verification_time"], utc=True, errors="coerce"
    )
    eligible = ph[
        ph["url"].ne("")
        & ph["verified"].astype(str).str.strip().str.lower().eq("yes")
        & ph["online"].astype(str).str.strip().str.lower().eq("yes")
        & ph["verification_time_parsed"].notna()
        & ph["verification_time_parsed"].ge(cutoff)
        & ph["verification_time_parsed"].le(created)
    ].drop_duplicates(subset=["url"])
    if len(eligible) < PHISH_SAMPLE_SIZE:
        raise ValueError(
            f"Only {len(eligible)} entries meet the last-{FRESHNESS_HOURS}-hours "
            f"criteria; {PHISH_SAMPLE_SIZE} are required. Use a fresh feed or "
            "increase FRESHNESS_HOURS deliberately and document the change."
        )
    ph_sample = eligible.sample(n=PHISH_SAMPLE_SIZE, random_state=SEED).copy()
    ph_rows = pd.DataFrame({
        "source": "PhishTank",
        "source_label": "verified_phishing_recently_verified",
        "source_id": ph_sample["phish_id"].astype(str),
        "source_timestamp": ph_sample["verification_time"].astype(str),
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
        raise ValueError("No domains were found in the selected Tranco candidate pool.")
    tr_sample = tr.sample(
        n=min(POPULAR_CANDIDATE_SAMPLE_SIZE, len(tr)), random_state=SEED
    ).copy()
    tr_sample["url"] = tr_sample["domain"].map(
        lambda d: d if d.startswith(("http://", "https://")) else "https://" + d
    )
    tr_rows = pd.DataFrame({
        "source": "Tranco",
        "source_label": "popular_domain_candidate_not_confirmed_benign",
        "source_id": tr_sample["rank"].astype(str),
        "source_timestamp": "",
        "url": tr_sample["url"].astype(str),
    })

    manifest = pd.concat([ph_rows, tr_rows], ignore_index=True)
    manifest.insert(0, "sample_row", range(1, len(manifest) + 1))
    manifest.to_csv(MANIFEST_PATH, index=False, encoding="utf-8")
    metadata = {
        "manifest_created_utc": created.isoformat(),
        "phish_verification_cutoff_utc": cutoff.isoformat(),
        "freshness_window_hours": FRESHNESS_HOURS,
        "sampling_seed": SEED,
        "fresh_phishtank_eligible_count": int(len(eligible)),
        "fresh_phishtank_selected_count": int(len(ph_rows)),
        "tranco_pool_size": int(len(tr)),
        "tranco_selected_count": int(len(tr_rows)),
        "risk_threshold_percentage_points": RISK_THRESHOLD,
    }
    (OUT_DIR / "fresh_sample_setup.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf-8"
    )
    return manifest, metadata


def preview(manifest: pd.DataFrame, metadata: dict) -> None:
    print("Fresh sample manifest prepared; no URLs have been scanned.")
    print(f"Manifest: {MANIFEST_PATH}")
    print(f"Verification cutoff UTC: {metadata['phish_verification_cutoff_utc']}")
    print(f"Eligible recent PhishTank URLs: {metadata['fresh_phishtank_eligible_count']}")
    print(f"Rows: {len(manifest)} | Seed: {SEED}")
    print("Selected records by source:")
    print(manifest.groupby(["source", "source_label"]).size().to_string())
    print("\nPhishTank record IDs and verification timestamps:")
    print(manifest.loc[manifest.source.eq("PhishTank"), ["source_id", "source_timestamp"]].to_string(index=False))
    print("\nTranco ranks:")
    print(", ".join(manifest.loc[manifest.source.eq("Tranco"), "source_id"].astype(str)))
    print("\nTranco domains are popularity candidates, not confirmed benign labels.")
    print("To submit controlled live requests through FakeGuard, rerun with --scan.")


def valid_score(value) -> float | None:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    return score if 0.0 <= score <= 100.0 else None


def classify(rec: dict) -> dict:
    try:
        http = int(rec.get("http_status"))
    except (TypeError, ValueError):
        http = None
    score = valid_score(rec.get("risk_score"))
    api_label = rec.get("app_label")
    api_class = rec.get("app_class")
    success = http == 200 and score is not None and (bool(api_label) or bool(api_class))
    flagged = score >= RISK_THRESHOLD if success else None
    source_label = str(rec.get("source_label", ""))
    if not success:
        outcome = "fetch_or_api_failure"
    elif source_label == "verified_phishing_recently_verified":
        outcome = "TP" if flagged else "FN"
    else:
        outcome = "flagged_popular_domain_candidate" if flagged else "not_flagged_popular_domain_candidate"
    rec.update({
        "http_status": http,
        "scan_status": "success" if success else "failure",
        "risk_score": score,
        "threshold_percentage_points": RISK_THRESHOLD,
        "flagged_as_suspicious": flagged,
        "outcome": outcome,
    })
    return rec


def summary(results: pd.DataFrame, metadata: dict) -> dict:
    ph = results[results.source_label.eq("verified_phishing_recently_verified")]
    tr = results[results.source_label.eq("popular_domain_candidate_not_confirmed_benign")]
    ph_ok = ph[ph.scan_status.eq("success")]
    tr_ok = tr[tr.scan_status.eq("success")]
    tp = int(ph_ok.outcome.eq("TP").sum())
    fn = int(ph_ok.outcome.eq("FN").sum())
    tr_flagged = int(tr_ok.flagged_as_suspicious.fillna(False).sum())
    return {
        **metadata,
        "completed_utc": datetime.now(timezone.utc).isoformat(),
        "risk_score_scale": "FakeGuard API score in percentage points, 0-100",
        "total_rows": int(len(results)),
        "successful_scans": int(results.scan_status.eq("success").sum()),
        "failed_scans": int(results.scan_status.eq("failure").sum()),
        "recently_verified_phishing_successful_scans": int(len(ph_ok)),
        "recently_verified_phishing_TP": tp,
        "recently_verified_phishing_FN": fn,
        "detection_rate_among_successful_recent_phishing_scans": tp / len(ph_ok) if len(ph_ok) else None,
        "tranco_candidate_successful_scans": int(len(tr_ok)),
        "tranco_candidates_flagged": tr_flagged,
        "tranco_candidate_flag_rate_not_false_positive_rate": tr_flagged / len(tr_ok) if len(tr_ok) else None,
        "results_csv": str(RESULTS_PATH),
        "limitations": [
            "This is a small exploratory pilot, not a publication-grade performance estimate.",
            "Recent PhishTank verification timestamps do not guarantee the page is still phishing when fetched.",
            "Tranco popularity does not establish benign ground truth; its flagged rate is not a false-positive rate.",
            "Fetch/API failures are reported separately and excluded from detection-rate denominators.",
            "Live content, DNS, redirects, anti-bot measures, and network conditions can change results.",
            "ML, HTML, identity, and evidence fields are recorded to diagnose component behavior, not to prove causal explanations.",
        ],
    }


def scan(manifest: pd.DataFrame, metadata: dict) -> None:
    import app as fakeguard

    client = fakeguard.app.test_client()
    records = []
    print("LIVE SCAN ENABLED. No manual browser interaction is needed.")
    print("The script uses FakeGuard's local Flask test client; failures are preserved.")
    print(f"Final risk threshold: {RISK_THRESHOLD:.1f}/100. Output folder: {OUT_DIR}\n")
    for _, row in manifest.iterrows():
        started = time.monotonic()
        http_status = None
        data = {}
        exception_text = ""
        try:
            response = client.post("/api/analyze", json={"url": str(row["url"])})
            http_status = int(response.status_code)
            data = response.get_json(silent=True) or {}
        except Exception as exc:  # record per-row errors; continue to next row
            exception_text = f"{type(exc).__name__}: {str(exc)[:200]}"
        meta = data.get("meta", {}) if isinstance(data, dict) else {}
        rec = {
            "sample_row": int(row.sample_row),
            "source": str(row.source),
            "source_label": str(row.source_label),
            "source_id": str(row.source_id),
            "source_timestamp": str(row.source_timestamp),
            "url": str(row.url),
            "http_status": http_status,
            "scan_status": "failure",
            "risk_score": valid_score(data.get("score")) if isinstance(data, dict) else None,
            "ml_score": valid_score(data.get("ml")) if isinstance(data, dict) else None,
            "html_risk_score": valid_score(data.get("html")) if isinstance(data, dict) else None,
            "identity_risk_score": valid_score(data.get("identity")) if isinstance(data, dict) else None,
            "app_label": data.get("label") if isinstance(data, dict) else None,
            "app_class": data.get("cls") if isinstance(data, dict) else None,
            "final_url": data.get("final_url") if isinstance(data, dict) else None,
            "input_hostname": (urlparse(str(row.url)).hostname or "").lower(),
            "final_hostname": (urlparse(str(data.get("final_url", ""))).hostname or "").lower() if isinstance(data, dict) else "",
            "reasons_json": json.dumps(data.get("reasons", []), ensure_ascii=False) if isinstance(data, dict) else "[]",
            "meta_json": json.dumps(meta, ensure_ascii=False, sort_keys=True) if isinstance(meta, dict) else "{}",
            "error": (str(data.get("error", ""))[:240] if isinstance(data, dict) else "") or exception_text,
            "duration_seconds": round(time.monotonic() - started, 3),
            "scan_time_utc": datetime.now(timezone.utc).isoformat(),
        }
        rec["hostname_changed"] = bool(rec["input_hostname"] and rec["final_hostname"] and rec["input_hostname"] != rec["final_hostname"])
        rec = classify(rec)
        records.append(rec)
        print(
            f"[{len(records)}/{len(manifest)}] {rec['source']} ID/rank={rec['source_id']} "
            f"status={rec['scan_status']} HTTP={http_status} "
            f"risk={rec['risk_score'] if rec['risk_score'] is not None else 'n/a'} "
            f"ML={rec['ml_score'] if rec['ml_score'] is not None else 'n/a'} "
            f"HTML={rec['html_risk_score'] if rec['html_risk_score'] is not None else 'n/a'} "
            f"Identity={rec['identity_risk_score'] if rec['identity_risk_score'] is not None else 'n/a'} "
            f"outcome={rec['outcome']}"
        )
        time.sleep(PAUSE_BETWEEN_REQUESTS_SECONDS)
    result_df = pd.DataFrame(records)
    result_df.to_csv(RESULTS_PATH, index=False, encoding="utf-8")
    report = summary(result_df, metadata)
    SUMMARY_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("\nSUMMARY")
    print(json.dumps(report, indent=2))
    print(f"\nDetailed results saved to: {RESULTS_PATH}")
    print(f"Summary saved to: {SUMMARY_PATH}")


def main() -> int:
    if "--scan" in sys.argv and "--repair-existing" in sys.argv:
        print("Choose only one mode: --scan or default preview. This script never repairs old pilot files.")
        return 2
    if "--repair-existing" in sys.argv:
        print("This fresh-sample script does not modify or repair the older pilot.")
        print("Run evaluate_fakeguard_external.py --repair-existing for the earlier saved pilot.")
        return 2
    manifest, metadata = prepare_manifest()
    if "--scan" in sys.argv:
        scan(manifest, metadata)
    else:
        preview(manifest, metadata)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

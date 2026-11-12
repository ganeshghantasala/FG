"""Local shadow audit for possible brand/domain mismatches in saved FakeGuard results.

Makes no network requests and does not change FakeGuard code, scores, or results.
A flag means manual review candidate, not confirmed phishing.
"""
from __future__ import annotations
import re
from pathlib import Path
from urllib.parse import urlparse
import pandas as pd
import tldextract

ROOT = Path(__file__).resolve().parent
OUT_DIR = ROOT / "research_results_external_fresh"
MANIFEST_PATH = OUT_DIR / "fresh_sample_manifest.csv"
RESULTS_PATH = OUT_DIR / "fresh_external_validation_results_after_original_url_patch.csv"
OUTPUT_PATH = OUT_DIR / "brand_mismatch_shadow_audit.csv"

# Small starter list; incomplete by design. Verify official-domain mappings before expanding.
BRAND_OFFICIAL_DOMAINS = {
    "allegrolokalnie": {"allegrolokalnie.pl"},
    "allegro": {"allegro.pl"},
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de"},
    "google": {"google.com", "google.co.in", "google.in"},
    "microsoft": {"microsoft.com"},
    "apple": {"apple.com"},
    "facebook": {"facebook.com"},
    "instagram": {"instagram.com"},
    "netflix": {"netflix.com"},
    "ebay": {"ebay.com", "ebay.co.uk", "ebay.de"},
    "dhl": {"dhl.com"},
    "ups": {"ups.com"},
    "linkedin": {"linkedin.com"},
    "binance": {"binance.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "bankofamerica": {"bankofamerica.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
}
# Avoid downloading the public suffix list during this offline audit.
EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

def hostname(url: str) -> str:
    try:
        return (urlparse(str(url)).hostname or "").lower().rstrip(".")
    except Exception:
        return ""

def registrable_domain(url: str) -> str:
    e = EXTRACT(str(url))
    return ".".join(x for x in (e.domain, e.suffix) if x).lower()

def matching_brands(host: str) -> list[str]:
    normalized = re.sub(r"[^a-z0-9]", "", (host or "").lower())
    found = [brand for brand in BRAND_OFFICIAL_DOMAINS if brand in normalized]
    # Do not separately report a shorter term contained in a longer matched brand.
    return sorted(
        [b for b in found if not any(b != other and b in other for other in found)],
        key=len, reverse=True,
    )

def main() -> int:
    if not MANIFEST_PATH.exists():
        raise FileNotFoundError(f"Saved manifest not found: {MANIFEST_PATH}")
    if not RESULTS_PATH.exists():
        raise FileNotFoundError(f"Patched results not found: {RESULTS_PATH}")
    manifest = pd.read_csv(MANIFEST_PATH, dtype=str, keep_default_na=False)
    results = pd.read_csv(RESULTS_PATH, dtype=str, keep_default_na=False)
    if "sample_row" not in manifest.columns or "sample_row" not in results.columns:
        raise ValueError("Expected 'sample_row' column in both CSV files.")
    result_map = {str(r["sample_row"]): r for _, r in results.iterrows()}
    records = []
    for _, row in manifest.iterrows():
        sample = str(row["sample_row"])
        result = result_map.get(sample)
        submitted = str(row.get("url", ""))
        final = str(result.get("final_url", "")) if result is not None else ""
        submitted_host = hostname(submitted)
        submitted_reg = registrable_domain(submitted)
        final_host = hostname(final)
        final_reg = registrable_domain(final) if final else ""
        brands = matching_brands(submitted_host)
        mismatches = [b for b in brands if submitted_reg not in BRAND_OFFICIAL_DOMAINS[b]]
        records.append({
            "sample_row": sample,
            "source": str(row.get("source", "")),
            "source_label": str(row.get("source_label", "")),
            "source_id": str(row.get("source_id", "")),
            "scan_status": str(result.get("scan_status", "")) if result is not None else "no_result",
            "risk_score": str(result.get("risk_score", "")) if result is not None else "",
            "submitted_url": submitted,
            "submitted_hostname": submitted_host,
            "submitted_registered_domain": submitted_reg,
            "matched_brand_terms": ";".join(brands),
            "mismatch_brand_terms": ";".join(mismatches),
            "brand_domain_mismatch_review": bool(mismatches),
            "final_hostname": final_host,
            "final_registered_domain": final_reg,
            "final_host_changed": bool(submitted_host and final_host and submitted_host != final_host),
        })
    audit = pd.DataFrame(records)
    audit.to_csv(OUTPUT_PATH, index=False, encoding="utf-8")
    flagged = audit[audit["brand_domain_mismatch_review"]]
    print("SHADOW-MODE AUDIT ONLY: no URLs fetched; FakeGuard scores unchanged.")
    print(f"Rows audited: {len(audit)}")
    print(f"Brand/domain mismatch review candidates: {len(flagged)}")
    print("\nCounts by source:")
    print(audit.groupby("source")["brand_domain_mismatch_review"].agg(["count", "sum"]).to_string())
    columns = ["sample_row", "source", "source_id", "scan_status", "risk_score", "submitted_hostname", "submitted_registered_domain", "mismatch_brand_terms", "final_hostname"]
    print("\nRows flagged for manual review:")
    print(flagged[columns].to_string(index=False) if len(flagged) else "(none)")
    print(f"\nDetailed audit saved to: {OUTPUT_PATH}")
    print("Flags are review candidates, not confirmed phishing. The starter brand list is incomplete and may produce false positives.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

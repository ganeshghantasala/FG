from pathlib import Path
import sys

ROOT = Path.cwd()
ENGINE = ROOT / "feature_engine.py"
APP = ROOT / "app.py"
TEST = ROOT / "test_brand_mismatch.py"

if not ENGINE.exists() or not APP.exists():
    print("ERROR: Run this script from the FakeGuard-main project folder (where app.py and feature_engine.py exist).")
    sys.exit(2)

engine_text = ENGINE.read_text(encoding="utf-8")
app_text = APP.read_text(encoding="utf-8")

# Avoid applying the patch twice.
if "def detect_brand_domain_mismatch(" in engine_text or "brand_domain_mismatch" in app_text:
    print("ERROR: Brand mismatch patch marker already exists. No files changed.")
    sys.exit(2)

terms_anchor = '''SUSPICIOUS_TERMS = {
    "login","signin","verify","verification","secure","account","update",
    "password","bank","wallet","payment","confirm","unlock","suspend",
    "authentication","credential","billing","invoice"
}
'''
if terms_anchor not in engine_text:
    print("ERROR: Could not find the expected SUSPICIOUS_TERMS block. No files changed.")
    sys.exit(2)

function_block = terms_anchor + '''

# Small, explicit starter list for a review warning. This is not a complete
# brand registry and must not be treated as proof that a URL is malicious.
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


def detect_brand_domain_mismatch(host, registered_domain):
    """Return known brand terms in hostname whose registered domain is not official.

    Matching is restricted to whole hostname labels (after removing hyphens and
    punctuation), not URL paths or arbitrary substrings. Results are review
    candidates only; this intentionally does not change a risk score.
    """
    labels = {
        re.sub(r"[^a-z0-9]", "", label.lower())
        for label in (host or "").lower().rstrip(".").split(".")
        if label
    }
    registered_domain = (registered_domain or "").lower().rstrip(".")
    matches = [brand for brand in BRAND_OFFICIAL_DOMAINS if brand in labels]
    matches = [
        brand for brand in matches
        if not any(brand != other and brand in other for other in matches)
    ]
    return [
        brand for brand in sorted(matches, key=len, reverse=True)
        if registered_domain not in BRAND_OFFICIAL_DOMAINS[brand]
    ]
'''
engine_text = engine_text.replace(terms_anchor, function_block, 1)

old_extract = '''    ext = tldextract.extract(url)

    # HTML-relative links and page metadata use the actual fetched destination.
'''
new_extract = '''    ext = tldextract.extract(url)
    submitted_registered = ".".join(
        x for x in [ext.domain, ext.suffix] if x
    )
    brand_mismatch_brands = detect_brand_domain_mismatch(
        host, submitted_registered or host
    )

    # HTML-relative links and page metadata use the actual fetched destination.
'''
if old_extract not in engine_text:
    print("ERROR: Could not locate the expected URL feature setup. No files changed.")
    sys.exit(2)
engine_text = engine_text.replace(old_extract, new_extract, 1)

meta_anchor = '''    meta = {
        "registered_domain": registered or host,
        "hostname": page_host,
'''
meta_replacement = '''    meta = {
        "registered_domain": registered or page_host,
        "hostname": page_host,
        "submitted_hostname": host,
        "submitted_registered_domain": submitted_registered or host,
        "brand_domain_mismatch": bool(brand_mismatch_brands),
        "brand_mismatch_brands": brand_mismatch_brands,
'''
if meta_anchor not in engine_text:
    print("ERROR: Could not locate the expected metadata dictionary. No files changed.")
    sys.exit(2)
engine_text = engine_text.replace(meta_anchor, meta_replacement, 1)

reason_anchor = '''    if meta["suspicious_terms"]: reasons.append("The address or page includes account/security terms: " + ", ".join(meta["suspicious_terms"][:6]))
    if contradiction: reasons.append("The address looked lower-risk to the model, but page behavior raised concerns, so FakeGuard increased the review score.")
'''
reason_replacement = '''    if meta["suspicious_terms"]: reasons.append("The address or page includes account/security terms: " + ", ".join(meta["suspicious_terms"][:6]))
    if meta.get("brand_domain_mismatch"):
        brands = ", ".join(meta.get("brand_mismatch_brands", []))
        submitted_domain = meta.get("submitted_registered_domain") or "an unrecognized domain"
        reasons.append(
            f"Brand/domain review warning: the submitted hostname contains a known brand term ({brands}), "
            f"but its registered domain is {submitted_domain}. Verify the address through the brand's official website. "
            "This warning is not confirmation of phishing."
        )
    if contradiction: reasons.append("The address looked lower-risk to the model, but page behavior raised concerns, so FakeGuard increased the review score.")
'''
if reason_anchor not in app_text:
    print("ERROR: Could not locate the expected explanation block. No files changed.")
    sys.exit(2)

# Create backups before writing either edited file.
engine_backup = ROOT / "feature_engine.py.before_brand_mismatch_warning.bak"
app_backup = ROOT / "app.py.before_brand_mismatch_warning.bak"
if engine_backup.exists() or app_backup.exists():
    print("ERROR: A backup file with the target name already exists. Move/rename it before retrying; no files changed.")
    sys.exit(2)

engine_backup.write_text(ENGINE.read_text(encoding="utf-8"), encoding="utf-8")
app_backup.write_text(APP.read_text(encoding="utf-8"), encoding="utf-8")

try:
    ENGINE.write_text(engine_text, encoding="utf-8")
    APP.write_text(app_text.replace(reason_anchor, reason_replacement, 1), encoding="utf-8")
except Exception:
    # Restore both files if an unexpected write error occurs.
    ENGINE.write_text(engine_backup.read_text(encoding="utf-8"), encoding="utf-8")
    APP.write_text(app_backup.read_text(encoding="utf-8"), encoding="utf-8")
    print("ERROR: Write failed; source files restored from backups.")
    raise

if not TEST.exists():
    test_text = r'''import unittest

from feature_engine import extract_features
from risk_engine import calculate_fused_score


class BrandMismatchWarningTests(unittest.TestCase):
    def scan_meta(self, original_url):
        _, meta = extract_features(
            "https://allegro.pl/", "", original_url=original_url
        )
        return meta

    def test_official_allegro_domain_not_flagged(self):
        meta = self.scan_meta("https://www.allegro.pl/")
        self.assertFalse(meta["brand_domain_mismatch"])

    def test_allegro_brand_on_unrelated_registered_domain_flagged(self):
        meta = self.scan_meta("https://allegro.fake-example.sbs/")
        self.assertTrue(meta["brand_domain_mismatch"])
        self.assertIn("allegro", meta["brand_mismatch_brands"])

    def test_allegro_lokalnie_impersonation_flagged(self):
        meta = self.scan_meta("https://allegrolokalnie.pl-oferta6890786784.sbs/")
        self.assertTrue(meta["brand_domain_mismatch"])
        self.assertIn("allegrolokalnie", meta["brand_mismatch_brands"])

    def test_brand_word_in_path_only_not_flagged(self):
        meta = self.scan_meta("https://example.org/paypal/login")
        self.assertFalse(meta["brand_domain_mismatch"])

    def test_paypal_subdomain_under_unrelated_domain_flagged(self):
        meta = self.scan_meta("https://paypal.com.example.org/")
        self.assertTrue(meta["brand_domain_mismatch"])

    def test_official_subdomain_not_flagged(self):
        meta = self.scan_meta("https://shop.paypal.com/")
        self.assertFalse(meta["brand_domain_mismatch"])

    def test_score_formula_ignores_brand_warning_metadata(self):
        meta = {
            "html_risk": 0.0,
            "identity_risk": 0.0,
            "brand_domain_mismatch": True,
            "brand_mismatch_brands": ["allegro"],
        }
        score_with_warning, contradiction_with_warning = calculate_fused_score(0.1, meta)
        meta_without_warning = {"html_risk": 0.0, "identity_risk": 0.0}
        score_without_warning, contradiction_without_warning = calculate_fused_score(
            0.1, meta_without_warning
        )
        self.assertEqual(score_with_warning, score_without_warning)
        self.assertEqual(contradiction_with_warning, contradiction_without_warning)


if __name__ == "__main__":
    unittest.main(verbosity=2)
'''
    TEST.write_text(test_text, encoding="utf-8")

print("Brand/domain review-warning patch applied.")
print("Existing model weights, scoring weights, and risk thresholds were not changed.")
print("Backups created:")
print(" -", engine_backup.name)
print(" -", app_backup.name)
print("Added test:", TEST.name)

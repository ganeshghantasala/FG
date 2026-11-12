from __future__ import annotations

from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent
APP = ROOT / "app.py"
TEST = ROOT / "test_brand_review_floor.py"
BACKUP = ROOT / "app.py.before_brand_review_floor.bak"

if not APP.exists():
    raise FileNotFoundError(f"Cannot find {APP}")

source = APP.read_text(encoding="utf-8")

helper = (
    "def apply_brand_domain_review_floor(score, meta, threshold=0.45):\n"
    "    # Apply a cautious manual-review floor; this is not proof of phishing.\n"
    "    score = float(score)\n"
    "    threshold = float(threshold)\n"
    "    if not 0.0 <= score <= 1.0:\n"
    "        raise ValueError('score must be between 0 and 1')\n"
    "    if not 0.0 <= threshold <= 1.0:\n"
    "        raise ValueError('threshold must be between 0 and 1')\n"
    "    flagged = bool((meta or {}).get('brand_domain_mismatch'))\n"
    "    return (max(score, threshold) if flagged else score), flagged\n"
    "\n\n"
)

anchor = "def analyze(url):"
calc_line = "    score, contradiction = calculate_fused_score(ml_risk, meta)"
old_calc_block = calc_line + "\n\n    reasons = []"
new_calc_block = (
    calc_line + "\n"
    "    base_score = score\n"
    "    score, review_floor_applied = apply_brand_domain_review_floor(score, meta)\n"
    "\n"
    "    reasons = []"
)

return_old = '        "reasons":reasons, "meta":meta, "status":status, "final_url":final_url'
return_new = (
    '        "reasons":reasons, "meta":meta, "status":status, "final_url":final_url,\n'
    '        "base_score":round(base_score*100,1),\n'
    '        "brand_review_floor_applied":review_floor_applied'
)

if "def apply_brand_domain_review_floor(" in source and "brand_review_floor_applied" in source:
    print("Brand/domain review-floor patch already appears to be applied; app.py unchanged.")
else:
    if anchor not in source:
        raise RuntimeError("Could not find analyze(url) function. No files changed.")
    if old_calc_block not in source:
        raise RuntimeError("Could not find expected score calculation block. No files changed.")
    if return_old not in source:
        raise RuntimeError("Could not find expected API result dictionary line. No files changed.")

    patched = source.replace(anchor, helper + anchor, 1)
    patched = patched.replace(old_calc_block, new_calc_block, 1)
    patched = patched.replace(return_old, return_new, 1)

    if patched == source:
        raise RuntimeError("No source change detected; no files changed.")
    if not BACKUP.exists():
        shutil.copy2(APP, BACKUP)
    APP.write_text(patched, encoding="utf-8")
    print("Brand/domain manual-review floor applied in analyze().")
    print(f"Backup created: {BACKUP.name}")

test_source = r'''import unittest

from app import apply_brand_domain_review_floor


class BrandDomainReviewFloorTests(unittest.TestCase):
    def test_flagged_low_score_is_raised_to_review_threshold(self):
        score, applied = apply_brand_domain_review_floor(
            0.165, {"brand_domain_mismatch": True}
        )
        self.assertEqual(score, 0.45)
        self.assertTrue(applied)

    def test_flagged_score_already_above_threshold_is_preserved(self):
        score, applied = apply_brand_domain_review_floor(
            0.62, {"brand_domain_mismatch": True}
        )
        self.assertEqual(score, 0.62)
        self.assertTrue(applied)

    def test_unflagged_score_is_unchanged(self):
        score, applied = apply_brand_domain_review_floor(
            0.165, {"brand_domain_mismatch": False}
        )
        self.assertEqual(score, 0.165)
        self.assertFalse(applied)

    def test_missing_flag_does_not_change_score(self):
        score, applied = apply_brand_domain_review_floor(0.21, {})
        self.assertEqual(score, 0.21)
        self.assertFalse(applied)

    def test_invalid_score_rejected(self):
        with self.assertRaises(ValueError):
            apply_brand_domain_review_floor(1.1, {"brand_domain_mismatch": True})


if __name__ == "__main__":
    unittest.main(verbosity=2)
'''

TEST.write_text(test_source, encoding="utf-8")
print(f"Added tests: {TEST.name}")
print("Behavior: a supported brand/domain mismatch floors displayed risk at 45/100.")
print("The pre-floor fused score is retained as base_score; output records brand_review_floor_applied.")
print("The rule is a manual-review heuristic, not proof of phishing.")
print("No model weights or calculate_fused_score weights were changed.")

from __future__ import annotations

from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent
ENGINE = ROOT / "feature_engine.py"
TEST = ROOT / "test_sfh_mapping.py"
BACKUP = ROOT / "feature_engine.py.before_sfh_alignment.bak"

if not ENGINE.exists():
    raise FileNotFoundError(f"Cannot find {ENGINE}")

source = ENGINE.read_text(encoding="utf-8")
old_rule = '    f["SFH"] = -1 if external_forms or abnormal_forms else 1'
new_rule = "\n".join([
    "    # Ternary SFH approximation: blank/non-functional handlers are suspicious,",
    "    # external form handlers are neutral/uncertain, and same-site or absent",
    "    # forms fall into the normal state. If several forms exist, the most",
    "    # concerning observed handler takes precedence.",
    "    if abnormal_forms:",
    '        f["SFH"] = -1',
    "    elif external_forms:",
    '        f["SFH"] = 0',
    "    else:",
    '        f["SFH"] = 1',
])

if new_rule in source:
    print("SFH alignment patch already appears to be applied; source unchanged.")
else:
    if old_rule not in source:
        raise RuntimeError(
            "Expected SFH feature rule was not found. No files changed; inspect feature_engine.py."
        )
    patched = source.replace(old_rule, new_rule, 1)
    if patched == source:
        raise RuntimeError("No source change detected; no files changed.")
    if not BACKUP.exists():
        shutil.copy2(ENGINE, BACKUP)
    ENGINE.write_text(patched, encoding="utf-8")
    print("SFH tri-state alignment patch applied.")
    print(f"Backup created: {BACKUP.name}")

test_source = r'''import unittest

from feature_engine import extract_features


def sfh_value(action):
    if action is None:
        form = "<form><input name='q'></form>"
    else:
        form = f'<form action="{action}"><input name="q"></form>'
    html = f"<html><body>{form}</body></html>"
    features, _ = extract_features(
        "https://example.com/",
        html,
        original_url="https://example.com/",
    )
    return features["SFH"]


class SFHMappingTests(unittest.TestCase):
    def test_same_site_action_is_legitimate_value(self):
        self.assertEqual(sfh_value("/submit"), 1)

    def test_external_form_handler_is_neutral(self):
        self.assertEqual(sfh_value("https://outside.net/submit"), 0)

    def test_empty_action_is_suspicious_value(self):
        self.assertEqual(sfh_value(""), -1)

    def test_about_blank_action_is_suspicious_value(self):
        self.assertEqual(sfh_value("about:blank"), -1)

    def test_placeholder_action_is_suspicious_value(self):
        self.assertEqual(sfh_value("#"), -1)

    def test_form_without_action_retains_suspicious_heuristic(self):
        self.assertEqual(sfh_value(None), -1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
'''

TEST.write_text(test_source, encoding="utf-8")
print(f"Added tests: {TEST.name}")
print("No model weights, scoring formula, thresholds, or UI logic were changed.")

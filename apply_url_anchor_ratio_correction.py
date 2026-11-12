from __future__ import annotations

from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent
ENGINE = ROOT / "feature_engine.py"
TEST = ROOT / "test_url_anchor_mapping.py"
BACKUP = ROOT / "feature_engine.py.before_anchor_ratio_correction.bak"

if not ENGINE.exists():
    raise FileNotFoundError(f"Cannot find {ENGINE}")
if not TEST.exists():
    raise FileNotFoundError(f"Cannot find {TEST}")

source = ENGINE.read_text(encoding="utf-8")

old_count_rule = '''        if is_external or href.lower().startswith(("#", "javascript:")):
            anchor_problem_links += 1'''
new_count_rule = '''        is_placeholder = (not href) or href.lower().startswith(("#", "javascript:"))
        if is_external or is_placeholder:
            anchor_problem_links += 1'''

old_thresholds = '''        external_anchor_ratio = ext_links / len(links)
        problematic_anchor_ratio = anchor_problem_links / len(links)
        if problematic_anchor_ratio > 0.67:
            f["URL_of_Anchor"] = -1
        elif 0.31 <= external_anchor_ratio <= 0.67:
            f["URL_of_Anchor"] = 0
        else:
            f["URL_of_Anchor"] = 1'''

new_thresholds = '''        problematic_anchor_ratio = anchor_problem_links / len(links)
        if problematic_anchor_ratio > 0.67:
            f["URL_of_Anchor"] = -1
        elif 0.31 <= problematic_anchor_ratio <= 0.67:
            f["URL_of_Anchor"] = 0
        else:
            f["URL_of_Anchor"] = 1'''

old_comment = '''    # Closer approximation to the UCI {-1, 0, 1} definition:
    # -1 if >67% of anchors are external or placeholder links;
    # 0 if external anchors are between 31% and 67%;
    # 1 otherwise. With no anchors, use 0 rather than assuming legitimacy.'''

new_comment = '''    # -1 if >67% of anchors are external or non-functional;
    # 0 if the same combined proportion is between 31% and 67%;
    # 1 if it is below 31%. With no anchors, use 0 (unknown).'''


if (
    new_count_rule in source
    and new_thresholds in source
    and new_comment in source
):
    print("Anchor-ratio correction already appears to be applied; source unchanged.")
else:
    for old, desc in [
        (old_count_rule, "anchor count rule"),
        (old_thresholds, "anchor threshold rules"),
        (old_comment, "anchor feature comment"),
    ]:
        if old not in source:
            raise RuntimeError(
                f"Expected {desc} was not found. No files changed; inspect current source."
            )
    patched = source.replace(old_count_rule, new_count_rule, 1)
    patched = patched.replace(old_thresholds, new_thresholds, 1)
    patched = patched.replace(old_comment, new_comment, 1)
    if patched == source:
        raise RuntimeError("No source change detected; no files changed.")
    if not BACKUP.exists():
        shutil.copy2(ENGINE, BACKUP)
    ENGINE.write_text(patched, encoding="utf-8")
    print("Anchor-ratio correction applied to feature_engine.py.")
    print(f"Backup created: {BACKUP.name}")

test_source = TEST.read_text(encoding="utf-8")
new_tests = '''    def test_medium_problematic_ratio_from_placeholder_links_is_neutral(self):
        hrefs = ["#section"] * 4 + [
            f"https://example.com/page{i}" for i in range(6)
        ]
        self.assertEqual(anchor_feature(hrefs), 0)

    def test_empty_href_counts_as_nonfunctional(self):
        html = "<html><body>" + (
            '<a href="">no link</a>' * 7
            + ''.join(
                f'<a href="https://example.com/page{i}">internal</a>'
                for i in range(3)
            )
        ) + "</body></html>"
        features, _ = extract_features(
            "https://example.com/",
            html,
            original_url="https://example.com/",
        )
        self.assertEqual(features["URL_of_Anchor"], -1)

'''
if "test_medium_problematic_ratio_from_placeholder_links_is_neutral" in test_source and "test_empty_href_counts_as_nonfunctional" in test_source:
    print("Additional anchor threshold tests already exist; tests unchanged.")
else:
    sentinel = '\n\nif __name__ == "__main__":'
    if sentinel not in test_source:
        raise RuntimeError(
            "Could not find the test-file insertion point. feature_engine.py may have been corrected; inspect tests manually."
        )
    test_source = test_source.replace(sentinel, "\n\n" + new_tests.rstrip() + sentinel, 1)
    TEST.write_text(test_source, encoding="utf-8")
    print("Added two focused tests for threshold and empty-href semantics.")

print("No model weights, risk formula, thresholds, or UI logic were changed.")

from __future__ import annotations

from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent
ENGINE = ROOT / "feature_engine.py"
TEST = ROOT / "test_url_anchor_mapping.py"
BACKUP = ROOT / "feature_engine.py.before_anchor_feature_alignment.bak"

if not ENGINE.exists():
    raise FileNotFoundError(f"Cannot find {ENGINE}")

source = ENGINE.read_text(encoding="utf-8")

old_link_block = '''    ext_links = 0
    for a in links:
        u = abs_url(a.get("href",""))
        h = (urlparse(u).hostname or "").lower()
        if h and registered and is_external_host(h, registered):
            ext_links += 1'''

new_link_block = '''    ext_links = 0
    anchor_problem_links = 0
    for a in links:
        href = (a.get("href") or "").strip()
        u = abs_url(href)
        h = (urlparse(u).hostname or "").lower()
        is_external = bool(h and registered and is_external_host(h, registered))
        if is_external:
            ext_links += 1
        # The UCI feature treats placeholder (# / javascript:) and external
        # anchors as potentially problematic. Keep this separate from ext_links
        # because other HTML evidence still uses the external-link count.
        if is_external or href.lower().startswith(("#", "javascript:")):
            anchor_problem_links += 1'''

old_feature_line = '    f["URL_of_Anchor"] = -1 if links and ext_links / max(len(links),1) > 0.35 else 1'
new_feature_line = '''    # Closer approximation to the UCI {-1, 0, 1} definition:
    # -1 if >67% of anchors are external or placeholder links;
    # 0 if external anchors are between 31% and 67%;
    # 1 otherwise. With no anchors, use 0 rather than assuming legitimacy.
    if not links:
        f["URL_of_Anchor"] = 0
    else:
        external_anchor_ratio = ext_links / len(links)
        problematic_anchor_ratio = anchor_problem_links / len(links)
        if problematic_anchor_ratio > 0.67:
            f["URL_of_Anchor"] = -1
        elif 0.31 <= external_anchor_ratio <= 0.67:
            f["URL_of_Anchor"] = 0
        else:
            f["URL_of_Anchor"] = 1'''

if new_feature_line in source and "anchor_problem_links = 0" in source:
    print("Anchor feature alignment patch already appears to be applied; no files changed.")
    raise SystemExit(0)

if old_link_block not in source:
    raise RuntimeError(
        "Could not find the expected anchor-link extraction block in feature_engine.py. "
        "No files changed; inspect the current function before patching."
    )
if old_feature_line not in source:
    raise RuntimeError(
        "Could not find the expected URL_of_Anchor feature rule in feature_engine.py. "
        "No files changed; inspect the current function before patching."
    )

patched = source.replace(old_link_block, new_link_block, 1).replace(
    old_feature_line, new_feature_line, 1
)

if patched == source:
    raise RuntimeError("No code changed; patch was not applied.")
if patched.count("anchor_problem_links = 0") != 1:
    raise RuntimeError("Unexpected number of anchor block insertions; no files changed.")
if patched.count('    if not links:\n        f["URL_of_Anchor"] = 0') != 1:
    raise RuntimeError("Unexpected number of URL_of_Anchor rule insertions; no files changed.")

if not BACKUP.exists():
    shutil.copy2(ENGINE, BACKUP)

ENGINE.write_text(patched, encoding="utf-8")

test_source = r'''import unittest

from feature_engine import extract_features


def html_with_anchors(hrefs):
    return "<html><body>" + "".join(
        f'<a href="{href}">link</a>' for href in hrefs
    ) + "</body></html>"


def anchor_feature(hrefs):
    features, _ = extract_features(
        "https://example.com/",
        html_with_anchors(hrefs),
        original_url="https://example.com/",
    )
    return features["URL_of_Anchor"]


class URLOfAnchorAlignmentTests(unittest.TestCase):
    def test_mostly_internal_links_are_legitimate_value(self):
        hrefs = [f"https://example.com/page{i}" for i in range(9)]
        hrefs.append("https://outside.net/page")
        self.assertEqual(anchor_feature(hrefs), 1)

    def test_medium_external_link_ratio_is_neutral(self):
        hrefs = [f"https://example.com/page{i}" for i in range(6)]
        hrefs.extend(f"https://outside.net/page{i}" for i in range(4))
        self.assertEqual(anchor_feature(hrefs), 0)

    def test_more_than_67_percent_external_links_is_suspicious(self):
        hrefs = [f"https://outside.net/page{i}" for i in range(8)]
        hrefs.extend(f"https://example.com/page{i}" for i in range(2))
        self.assertEqual(anchor_feature(hrefs), -1)

    def test_placeholder_anchors_count_toward_problematic_ratio(self):
        hrefs = ["#section"] * 7 + [
            f"https://example.com/page{i}" for i in range(3)
        ]
        self.assertEqual(anchor_feature(hrefs), -1)

    def test_no_anchors_is_neutral_not_assumed_legitimate(self):
        self.assertEqual(anchor_feature([]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
'''

TEST.write_text(test_source, encoding="utf-8")

print("URL_of_Anchor alignment patch applied.")
print("Updated feature: URL_of_Anchor now uses tri-state {-1, 0, 1} thresholds closer to the UCI definition.")
print("No model weights, risk formula, thresholds, or brand-warning behavior were changed.")
print(f"Backup created: {BACKUP.name}")
print(f"Added tests: {TEST.name}")

from __future__ import annotations

from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent
ENGINE = ROOT / "feature_engine.py"
TEST = ROOT / "test_links_in_tags_mapping.py"
BACKUP = ROOT / "feature_engine.py.before_links_in_tags_alignment.bak"

if not ENGINE.exists():
    raise FileNotFoundError(f"Cannot find {ENGINE}")
source = ENGINE.read_text(encoding="utf-8")

old_count_anchor = '''    ext_res = 0
    for u in all_res:
        h = (urlparse(u).hostname or "").lower()
        if h and registered and is_external_host(h, registered):
            ext_res += 1'''

new_count_anchor = r'''    ext_res = 0
    for u in all_res:
        h = (urlparse(u).hostname or "").lower()
        if h and registered and is_external_host(h, registered):
            ext_res += 1

    # Links_in_tags is distinct from Request_URL: only inspect URL-bearing
    # attributes in <meta>, <script>, and <link> tags.
    tag_link_urls = []
    for tag in soup.find_all(["meta", "script", "link"]):
        for attr in ("src", "href"):
            value = (tag.get(attr) or "").strip()
            if value:
                tag_link_urls.append(abs_url(value))

        if tag.name == "meta":
            content = (tag.get("content") or "").strip()
            if content:
                # Include URL-valued metadata and refresh URLs, not descriptions.
                if content.lower().startswith(("http://", "https://", "//")):
                    tag_link_urls.append(abs_url(content))
                else:
                    refresh_match = re.search(r"url\s*=\s*(.+)$", content, re.I)
                    if refresh_match:
                        target = refresh_match.group(1).split(";", 1)[0]
                        target = target.strip().strip(chr(34) + chr(39))
                        if target:
                            tag_link_urls.append(abs_url(target))

    tag_external_links = 0
    for tag_url in tag_link_urls:
        tag_host = (urlparse(tag_url).hostname or "").lower()
        if tag_host and registered and is_external_host(tag_host, registered):
            tag_external_links += 1'''

old_feature = '    f["Links_in_tags"] = -1 if all_res and ext_res / max(len(all_res),1) > 0.25 else 1'
new_feature = '''    # Dataset-compatible tri-state approximation: <17% external = +1,
    # 17%-81% = neutral (0), >81% external = -1. With no relevant URL
    # references, use 0 (unknown) instead of assuming the page is legitimate.
    if not tag_link_urls:
        f["Links_in_tags"] = 0
    else:
        tag_external_ratio = tag_external_links / len(tag_link_urls)
        if tag_external_ratio < 0.17:
            f["Links_in_tags"] = 1
        elif tag_external_ratio > 0.81:
            f["Links_in_tags"] = -1
        else:
            f["Links_in_tags"] = 0'''

if new_feature in source and "tag_link_urls = []" in source:
    print("Links_in_tags alignment patch already appears to be applied; source unchanged.")
else:
    if old_count_anchor not in source:
        raise RuntimeError(
            "Expected external-resource counting block was not found. No files changed."
        )
    if old_feature not in source:
        raise RuntimeError(
            "Expected Links_in_tags rule was not found. No files changed."
        )
    patched = source.replace(old_count_anchor, new_count_anchor, 1)
    patched = patched.replace(old_feature, new_feature, 1)
    if patched == source:
        raise RuntimeError("No source change detected; no files changed.")
    if not BACKUP.exists():
        shutil.copy2(ENGINE, BACKUP)
    ENGINE.write_text(patched, encoding="utf-8")
    print("Links_in_tags feature-alignment patch applied.")
    print(f"Backup created: {BACKUP.name}")

test_source = r'''import unittest

from feature_engine import extract_features


def extract_links_feature(body):
    html = "<html><head>" + body + "</head><body></body></html>"
    features, _ = extract_features(
        "https://example.com/",
        html,
        original_url="https://example.com/",
    )
    return features["Links_in_tags"]


class LinksInTagsMappingTests(unittest.TestCase):
    def test_low_external_ratio_is_legitimate_value(self):
        html = (
            '<link rel="stylesheet" href="https://example.com/a.css">'
            '<script src="https://outside.net/a.js"></script>'
            + ''.join(
                f'<link rel="stylesheet" href="https://example.com/{i}.css">'
                for i in range(8)
            )
        )
        self.assertEqual(extract_links_feature(html), 1)

    def test_middle_external_ratio_is_neutral(self):
        html = (
            '<link href="https://outside.net/a.css">'
            '<script src="https://outside.net/a.js"></script>'
            + ''.join(
                f'<link href="https://example.com/{i}.css">'
                for i in range(8)
            )
        )
        self.assertEqual(extract_links_feature(html), 0)

    def test_high_external_ratio_is_suspicious_value(self):
        html = (
            ''.join(
                f'<script src="https://outside.net/{i}.js"></script>'
                for i in range(9)
            )
            + '<link href="https://example.com/local.css">'
        )
        self.assertEqual(extract_links_feature(html), -1)

    def test_no_relevant_tag_urls_is_neutral(self):
        html = '<meta name="description" content="Example site description">'
        self.assertEqual(extract_links_feature(html), 0)

    def test_anchor_hrefs_are_not_counted_as_links_in_tags(self):
        html = (
            '<meta name="description" content="Example site">'
            + ''.join(
                f'<a href="https://outside.net/{i}">external</a>'
                for i in range(12)
            )
        )
        self.assertEqual(extract_links_feature(html), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
'''

TEST.write_text(test_source, encoding="utf-8")

print(f"Added tests: {TEST.name}")
print("No model weights, risk formula, score thresholds, or UI logic were changed.")

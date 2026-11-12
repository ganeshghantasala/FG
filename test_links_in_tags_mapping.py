import unittest

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

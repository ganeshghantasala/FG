import unittest

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


    def test_medium_problematic_ratio_from_placeholder_links_is_neutral(self):
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

if __name__ == "__main__":
    unittest.main(verbosity=2)

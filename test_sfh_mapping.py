import unittest

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

import unittest

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

import unittest

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

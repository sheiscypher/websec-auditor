import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checks.headers import evaluate_headers, is_permissions_policy_restrictive
from enums import ControlResult

GOOD_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=()",
}


class TestHeadersCheck(unittest.TestCase):
    def test_all_six_correct_gives_observed_and_100(self):
        outcome = evaluate_headers(GOOD_HEADERS)
        self.assertEqual(outcome.result, ControlResult.OBSERVED)
        self.assertEqual(outcome.score_contribution, 100.0)

    def test_no_headers_dict_is_not_testable(self):
        outcome = evaluate_headers(None)
        self.assertEqual(outcome.result, ControlResult.NOT_TESTABLE)
        self.assertIsNone(outcome.score_contribution)

    def test_empty_headers_gives_absent_and_zero(self):
        outcome = evaluate_headers({})
        self.assertEqual(outcome.result, ControlResult.ABSENT)
        self.assertEqual(outcome.score_contribution, 0.0)

    def test_partial_headers_gives_partial_and_proportional_score(self):
        partial = dict(GOOD_HEADERS)
        del partial["Permissions-Policy"]
        del partial["Referrer-Policy"]
        outcome = evaluate_headers(partial)
        self.assertEqual(outcome.result, ControlResult.PARTIAL)
        # 4/6 corrects
        self.assertAlmostEqual(outcome.score_contribution, (4 / 6) * 100)

    def test_hsts_below_threshold_is_incorrect(self):
        headers = dict(GOOD_HEADERS)
        headers["Strict-Transport-Security"] = "max-age=100"
        outcome = evaluate_headers(headers)
        self.assertEqual(outcome.result, ControlResult.PARTIAL)

    def test_csp_with_unsafe_inline_is_incorrect(self):
        headers = dict(GOOD_HEADERS)
        headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline'"
        outcome = evaluate_headers(headers)
        self.assertEqual(outcome.result, ControlResult.PARTIAL)

    def test_csp_wildcard_script_src_is_incorrect(self):
        headers = dict(GOOD_HEADERS)
        headers["Content-Security-Policy"] = "script-src *"
        outcome = evaluate_headers(headers)
        self.assertEqual(outcome.result, ControlResult.PARTIAL)


class TestPermissionsPolicyParsing(unittest.TestCase):
    """Mission section 9 — cas explicitement demandés."""

    def test_explicit_restriction_camera_and_microphone(self):
        self.assertTrue(is_permissions_policy_restrictive("camera=(), microphone=()"))

    def test_permissive_wildcard_is_unfavorable(self):
        self.assertFalse(is_permissions_policy_restrictive("*"))

    def test_header_absent_is_unfavorable(self):
        self.assertFalse(is_permissions_policy_restrictive(None))

    def test_wildcard_on_sensitive_feature_does_not_count_as_restriction(self):
        self.assertFalse(is_permissions_policy_restrictive("camera=*"))

    def test_non_sensitive_feature_only_does_not_count(self):
        # "gyroscope" n'est pas dans la liste V1 des fonctionnalités sensibles
        self.assertFalse(is_permissions_policy_restrictive("gyroscope=()"))

    def test_restriction_to_self_counts_as_restriction(self):
        self.assertTrue(is_permissions_policy_restrictive("geolocation=(self)"))


if __name__ == "__main__":
    unittest.main()

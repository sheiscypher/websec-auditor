import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checks.cookies import (
    evaluate_samesite_distribution,
    evaluate_secure_httponly,
    parse_set_cookie_headers,
)
from enums import ControlResult


class TestParseSetCookieHeaders(unittest.TestCase):
    def test_parses_secure_httponly_samesite(self):
        headers = ("session=abc123; Secure; HttpOnly; SameSite=Strict",)
        cookies = parse_set_cookie_headers(headers)
        self.assertEqual(len(cookies), 1)
        self.assertTrue(cookies[0].secure)
        self.assertTrue(cookies[0].httponly)
        self.assertEqual(cookies[0].samesite, "Strict")

    def test_missing_attributes_are_false_or_none(self):
        headers = ("tracker=xyz",)
        cookies = parse_set_cookie_headers(headers)
        self.assertFalse(cookies[0].secure)
        self.assertFalse(cookies[0].httponly)
        self.assertIsNone(cookies[0].samesite)

    def test_case_insensitive_attributes(self):
        headers = ("a=1; secure; httponly; samesite=lax",)
        cookies = parse_set_cookie_headers(headers)
        self.assertTrue(cookies[0].secure)
        self.assertTrue(cookies[0].httponly)
        self.assertEqual(cookies[0].samesite, "lax")


class TestSecureHttpOnlyScoring(unittest.TestCase):
    def test_none_headers_is_not_testable(self):
        outcome = evaluate_secure_httponly(None)
        self.assertEqual(outcome.result, ControlResult.NOT_TESTABLE)

    def test_no_cookies_is_not_applicable(self):
        outcome = evaluate_secure_httponly(())
        self.assertEqual(outcome.result, ControlResult.NOT_APPLICABLE)
        self.assertIsNone(outcome.score_contribution)

    def test_all_compliant_is_observed_100(self):
        headers = (
            "a=1; Secure; HttpOnly",
            "b=2; Secure; HttpOnly; SameSite=Strict",
        )
        outcome = evaluate_secure_httponly(headers)
        self.assertEqual(outcome.result, ControlResult.OBSERVED)
        self.assertEqual(outcome.score_contribution, 100.0)

    def test_none_compliant_is_absent_0(self):
        headers = ("a=1", "b=2; Secure")  # ni l'un ni l'autre pleinement conforme
        outcome = evaluate_secure_httponly(headers)
        self.assertEqual(outcome.result, ControlResult.ABSENT)
        self.assertEqual(outcome.score_contribution, 0.0)

    def test_partial_compliance_is_proportional(self):
        headers = (
            "a=1; Secure; HttpOnly",
            "b=2",
            "c=3",
            "d=4",
        )
        outcome = evaluate_secure_httponly(headers)
        self.assertEqual(outcome.result, ControlResult.PARTIAL)
        self.assertEqual(outcome.score_contribution, 25.0)

    def test_wording_never_claims_session_hijack_vulnerability(self):
        """Rappel cadrage : ne jamais conclure sur une vulnérabilité
        applicative réelle à partir de la seule présence des attributs."""
        outcome = evaluate_secure_httponly(("a=1",))
        for forbidden in ("vulnérable", "détournement de session confirmé", "faille"):
            self.assertNotIn(forbidden, outcome.evidence.lower())


class TestSameSiteDistribution(unittest.TestCase):
    def test_no_headers_gives_no_finding(self):
        self.assertIsNone(evaluate_samesite_distribution(None))
        self.assertIsNone(evaluate_samesite_distribution(()))

    def test_distribution_is_informative_never_scored(self):
        headers = ("a=1; SameSite=Strict", "b=2; SameSite=None; Secure")
        outcome = evaluate_samesite_distribution(headers)
        self.assertIsNotNone(outcome)
        self.assertEqual(outcome.result, ControlResult.OBSERVED)
        self.assertIsNone(outcome.score_contribution)


if __name__ == "__main__":
    unittest.main()

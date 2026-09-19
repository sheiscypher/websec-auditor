import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checks.dns_security import evaluate_dnssec
from checks.email_security import EmailSecurityEvidence, evaluate_email_security
from checks.supply_chain import ExternalResource, evaluate_sri
from checks.privacy import LegalPageEvidence, evaluate_legal_notice, evaluate_privacy_policy
from enums import ControlResult


class TestDNSSEC(unittest.TestCase):
    def test_none_is_not_testable(self):
        self.assertEqual(evaluate_dnssec(None).result, ControlResult.NOT_TESTABLE)

    def test_true_is_observed(self):
        outcome = evaluate_dnssec(True)
        self.assertEqual(outcome.result, ControlResult.OBSERVED)
        self.assertEqual(outcome.score_contribution, 100.0)

    def test_false_is_absent(self):
        outcome = evaluate_dnssec(False)
        self.assertEqual(outcome.result, ControlResult.ABSENT)
        self.assertEqual(outcome.score_contribution, 0.0)


class TestEmailSecurity(unittest.TestCase):
    def test_no_mx_is_not_applicable(self):
        outcome = evaluate_email_security(EmailSecurityEvidence(has_mx_record=False))
        self.assertEqual(outcome.result, ControlResult.NOT_APPLICABLE)
        self.assertIsNone(outcome.score_contribution)

    def test_dns_failure_is_not_testable(self):
        outcome = evaluate_email_security(EmailSecurityEvidence(has_mx_record=None))
        self.assertEqual(outcome.result, ControlResult.NOT_TESTABLE)

    def test_spf_and_strict_dmarc_is_observed(self):
        outcome = evaluate_email_security(
            EmailSecurityEvidence(has_mx_record=True, spf_present=True, dmarc_present=True, dmarc_policy="reject")
        )
        self.assertEqual(outcome.result, ControlResult.OBSERVED)
        self.assertEqual(outcome.score_contribution, 100.0)

    def test_dmarc_policy_none_is_partial(self):
        outcome = evaluate_email_security(
            EmailSecurityEvidence(has_mx_record=True, spf_present=True, dmarc_present=True, dmarc_policy="none")
        )
        self.assertEqual(outcome.result, ControlResult.PARTIAL)

    def test_nothing_present_is_absent(self):
        outcome = evaluate_email_security(
            EmailSecurityEvidence(has_mx_record=True, spf_present=False, dmarc_present=False)
        )
        self.assertEqual(outcome.result, ControlResult.ABSENT)
        self.assertEqual(outcome.score_contribution, 0.0)


class TestSupplyChainSRI(unittest.TestCase):
    def test_no_external_resources_is_not_applicable(self):
        outcome = evaluate_sri([])
        self.assertEqual(outcome.result, ControlResult.NOT_APPLICABLE)

    def test_none_is_not_testable(self):
        outcome = evaluate_sri(None)
        self.assertEqual(outcome.result, ControlResult.NOT_TESTABLE)

    def test_all_with_sri_is_observed_100(self):
        resources = [ExternalResource("https://cdn.example.com/a.js", True), ExternalResource("https://cdn.example.com/b.js", True)]
        outcome = evaluate_sri(resources)
        self.assertEqual(outcome.result, ControlResult.OBSERVED)
        self.assertEqual(outcome.score_contribution, 100.0)

    def test_partial_sri_gives_proportional_score(self):
        resources = [
            ExternalResource("https://cdn.example.com/a.js", True),
            ExternalResource("https://cdn.example.com/b.js", False),
            ExternalResource("https://cdn.example.com/c.js", False),
            ExternalResource("https://cdn.example.com/d.js", False),
        ]
        outcome = evaluate_sri(resources)
        self.assertEqual(outcome.result, ControlResult.PARTIAL)
        self.assertEqual(outcome.score_contribution, 25.0)


class TestLegalPages(unittest.TestCase):
    def test_found_is_observed(self):
        outcome = evaluate_privacy_policy(LegalPageEvidence(found=True))
        self.assertEqual(outcome.result, ControlResult.OBSERVED)
        self.assertEqual(outcome.score_contribution, 100.0)

    def test_not_found_on_regular_site_is_absent(self):
        outcome = evaluate_legal_notice(LegalPageEvidence(found=False, is_client_side_rendered_site=False))
        self.assertEqual(outcome.result, ControlResult.ABSENT)
        self.assertEqual(outcome.score_contribution, 0.0)

    def test_not_found_on_spa_is_not_testable(self):
        outcome = evaluate_privacy_policy(LegalPageEvidence(found=False, is_client_side_rendered_site=True))
        self.assertEqual(outcome.result, ControlResult.NOT_TESTABLE)
        self.assertIsNone(outcome.score_contribution)


if __name__ == "__main__":
    unittest.main()

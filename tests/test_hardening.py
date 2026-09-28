"""
tests/test_hardening.py — Non-régression sur les valeurs issues de la CIBLE
et sur l'identification de l'appelant.

Couvre :
- security/sanitize.py : listes blanches et nettoyages ;
- les trois chemins d'injection identifiés (politique DMARC, SameSite d'un
  cookie, nom du CMS) : aucune valeur brute ne doit atteindre `evidence` ;
- api/rate_limit.py : IP client non falsifiable, mémoire bornée ;
- api/static/index.html : toute valeur issue de l'API est échappée avant
  d'être écrite dans innerHTML.
"""

import re
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import api.rate_limit as rate_limit
from api.rate_limit import RateLimitExceeded, check_and_register_request, select_client_ip
from checks.cms import CMSDetectionEvidence, evaluate_cms_detection, evaluate_cve_mapping
from checks.cookies import evaluate_samesite_distribution, parse_set_cookie_headers
from checks.email_security import EmailSecurityEvidence, evaluate_email_security
from enums import ControlResult
from security.sanitize import (
    DMARC_POLICY_UNRECOGNIZED,
    SAMESITE_UNRECOGNIZED,
    normalize_dmarc_policy,
    normalize_samesite,
    redact_url_for_log,
    safe_for_log,
    sanitize_technology_name,
)

PAYLOAD = "<img src=x onerror=alert(1)>"


class TestSanitizers(unittest.TestCase):
    def test_dmarc_valid_values_pass_case_insensitively(self):
        self.assertEqual(normalize_dmarc_policy("reject"), "reject")
        self.assertEqual(normalize_dmarc_policy(" Quarantine "), "quarantine")
        self.assertEqual(normalize_dmarc_policy("NONE"), "none")

    def test_dmarc_unknown_value_never_returned_raw(self):
        self.assertEqual(normalize_dmarc_policy(PAYLOAD), DMARC_POLICY_UNRECOGNIZED)
        self.assertEqual(normalize_dmarc_policy("rejectt"), DMARC_POLICY_UNRECOGNIZED)

    def test_dmarc_absent_stays_none(self):
        self.assertIsNone(normalize_dmarc_policy(None))

    def test_samesite_valid_values_keep_original_case(self):
        self.assertEqual(normalize_samesite("Strict"), "Strict")
        self.assertEqual(normalize_samesite("lax"), "lax")
        self.assertEqual(normalize_samesite(" None "), "None")

    def test_samesite_unknown_value_never_returned_raw(self):
        self.assertEqual(normalize_samesite(PAYLOAD), SAMESITE_UNRECOGNIZED)
        self.assertIsNone(normalize_samesite(None))

    def test_technology_name_keeps_legitimate_generators(self):
        self.assertEqual(sanitize_technology_name("WordPress 6.4.2"), "WordPress 6.4.2")
        self.assertEqual(
            sanitize_technology_name("Joomla! - Open Source Content Management"),
            "Joomla! - Open Source Content Management",
        )
        self.assertEqual(sanitize_technology_name("Drupal 10 (https://www.drupal.org)"), "Drupal 10 (https://www.drupal.org)")

    def test_technology_name_strips_markup_and_control_characters(self):
        cleaned = sanitize_technology_name(PAYLOAD + "\u202e\u200b")
        for forbidden in ('<', '>', '"', "'", "=", "&", "\u202e", "\u200b"):
            self.assertNotIn(forbidden, cleaned)

    def test_technology_name_unusable_becomes_none_and_is_truncated(self):
        self.assertIsNone(sanitize_technology_name("<<<>>>"))
        self.assertIsNone(sanitize_technology_name(None))
        self.assertLessEqual(len(sanitize_technology_name("a" * 500)), 60)

    def test_safe_for_log_neutralizes_line_breaks_and_truncates(self):
        self.assertNotIn("\n", safe_for_log("ligne\nFAUSSE ENTREE"))
        self.assertEqual(len(safe_for_log("x" * 1000, max_len=50)), 51)  # 50 + « … »

    def test_redact_url_removes_credentials_query_and_fragment(self):
        out = redact_url_for_log("https://user:secret@example.com:8443/a/b?token=abc#frag")
        self.assertEqual(out, "https://example.com:8443/a/b")
        self.assertNotIn("secret", out)

    def test_redact_url_keeps_ipv6_brackets_and_handles_invalid_port(self):
        self.assertEqual(redact_url_for_log("http://[2001:db8::1]/x"), "http://[2001:db8::1]/x")
        self.assertEqual(redact_url_for_log("http://user:pw@host:notaport/"), "<url invalide>")


class TestNoRawTargetValueReachesEvidence(unittest.TestCase):
    """Les trois chemins d'injection : la valeur hostile ne doit jamais
    apparaître brute dans `evidence` ni dans phrasing_context."""

    def test_hostile_samesite_is_neutralized(self):
        cookies = parse_set_cookie_headers((f"a=1; SameSite={PAYLOAD}",))
        self.assertEqual(cookies[0].samesite, SAMESITE_UNRECOGNIZED)
        outcome = evaluate_samesite_distribution((f"a=1; SameSite={PAYLOAD}",))
        self.assertNotIn("<", outcome.evidence)

    def test_hostile_dmarc_policy_is_neutralized_and_result_unchanged(self):
        hostile = evaluate_email_security(
            EmailSecurityEvidence(
                has_mx_record=True, spf_present=True, dmarc_present=True,
                dmarc_policy=normalize_dmarc_policy(PAYLOAD),
            )
        )
        baseline = evaluate_email_security(
            EmailSecurityEvidence(has_mx_record=True, spf_present=True, dmarc_present=True, dmarc_policy="none")
        )
        self.assertNotIn("<", hostile.evidence)
        self.assertEqual(hostile.result, baseline.result)  # une politique inconnue reste « non stricte »
        self.assertEqual(hostile.result, ControlResult.PARTIAL)

    def test_hostile_cms_name_is_neutralized(self):
        outcome = evaluate_cms_detection(CMSDetectionEvidence(name=PAYLOAD))
        self.assertNotIn("<", outcome.evidence)
        self.assertNotIn(">", outcome.evidence)
        self.assertNotIn("<", outcome.phrasing_context["name"])

    def test_unusable_cms_name_is_not_testable(self):
        outcome = evaluate_cms_detection(CMSDetectionEvidence(name="<<<>>>"))
        self.assertEqual(outcome.result, ControlResult.NOT_TESTABLE)

    def test_legitimate_cms_still_detected(self):
        outcome = evaluate_cms_detection(CMSDetectionEvidence(name="WordPress 6.4.2"))
        self.assertEqual(outcome.result, ControlResult.OBSERVED)
        self.assertIn("WordPress 6.4.2", outcome.evidence)

    def test_hostile_cms_name_in_cve_mapping_is_neutralized(self):
        outcome = evaluate_cve_mapping(
            CMSDetectionEvidence(name=PAYLOAD, version=PAYLOAD, version_confidence="high"),
            known_cves=["CVE-0000-0000"],
        )
        self.assertNotIn("<", outcome.evidence)


class TestClientIpSelection(unittest.TestCase):
    def test_without_header_uses_connection_address(self):
        self.assertEqual(select_client_ip(None, "10.1.1.1", 1), "10.1.1.1")

    def test_reads_from_the_right_not_the_left(self):
        self.assertEqual(select_client_ip("6.6.6.6, 203.0.113.9", "10.1.1.1", 1), "203.0.113.9")

    def test_caller_cannot_choose_its_key_by_prepending_values(self):
        keys = {
            select_client_ip(f"1.1.{i}.{i}, 203.0.113.9", "10.1.1.1", 1) for i in range(1, 50)
        }
        self.assertEqual(keys, {"203.0.113.9"})

    def test_two_trusted_hops(self):
        self.assertEqual(select_client_ip("6.6.6.6, 203.0.113.9, 198.51.100.4", "10.1.1.1", 2), "203.0.113.9")

    def test_header_shorter_than_expected_falls_back_to_connection(self):
        self.assertEqual(select_client_ip("203.0.113.9", "10.1.1.1", 2), "10.1.1.1")

    def test_non_ip_value_falls_back_to_connection(self):
        self.assertEqual(select_client_ip("6.6.6.6, <script>", "10.1.1.1", 1), "10.1.1.1")

    def test_zero_hops_ignores_the_header(self):
        self.assertEqual(select_client_ip("203.0.113.9", "10.1.1.1", 0), "10.1.1.1")

    def test_ipv6_is_normalized(self):
        self.assertEqual(select_client_ip("2001:0db8:0000:0000:0000:0000:0000:0001", None, 1), "2001:db8::1")

    def test_no_information_at_all(self):
        self.assertEqual(select_client_ip(None, None, 1), "unknown")


class TestRateLimiterMemoryIsBounded(unittest.TestCase):
    def setUp(self):
        rate_limit._request_log.clear()

    def test_saturation_refuses_new_addresses_instead_of_growing(self):
        with mock.patch.object(rate_limit, "MAX_TRACKED_IPS", 5):
            for i in range(5):
                check_and_register_request(f"10.0.0.{i}", now=0.0)
            with self.assertRaises(RateLimitExceeded):
                check_and_register_request("10.0.0.99", now=1.0)
            self.assertEqual(len(rate_limit._request_log), 5)

    def test_known_address_still_served_when_saturated(self):
        with mock.patch.object(rate_limit, "MAX_TRACKED_IPS", 5):
            for i in range(5):
                check_and_register_request(f"10.0.0.{i}", now=0.0)
            check_and_register_request("10.0.0.0", now=1.0)  # ne doit pas lever

    def test_expired_entries_are_purged_when_saturated(self):
        with mock.patch.object(rate_limit, "MAX_TRACKED_IPS", 5):
            for i in range(5):
                check_and_register_request(f"10.0.0.{i}", now=0.0)
            later = rate_limit.WINDOW_SECONDS + 10.0
            check_and_register_request("10.0.0.99", now=later)  # purge puis accepte
            self.assertLessEqual(len(rate_limit._request_log), 5)
            self.assertIn("10.0.0.99", rate_limit._request_log)

    def test_rejected_requests_do_not_grow_state(self):
        for i in range(rate_limit.MAX_REQUESTS_PER_WINDOW):
            check_and_register_request("1.2.3.4", now=float(i))
        for _ in range(50):
            with self.assertRaises(RateLimitExceeded):
                check_and_register_request("1.2.3.4", now=10.0)
        self.assertEqual(len(rate_limit._request_log["1.2.3.4"]), rate_limit.MAX_REQUESTS_PER_WINDOW)

    def test_no_empty_entry_is_ever_stored(self):
        check_and_register_request("1.2.3.4", now=0.0)
        check_and_register_request("1.2.3.4", now=rate_limit.WINDOW_SECONDS + 100.0)
        self.assertTrue(all(rate_limit._request_log.values()))


class TestFrontendEscapesEverythingFromTheApi(unittest.TestCase):
    """Test statique : le rendu ne doit concaténer AUCUN champ issu de l'API
    sans esc(). Le comportement réel a été vérifié séparément en exécutant le
    code de rendu avec des valeurs hostiles."""

    # Concaténation directe (« + f.evidence ») d'un champ non enveloppé dans esc().
    UNESCAPED = re.compile(
        r"\+\s*\(?\s*(?:f|kf)\."
        r"(?:evidence|evidence_level|resolved_label|constat|recommendation|limitation|"
        r"reference|detection_method|report_label|control_id|risk_category|domain)\b(?!\s*\?)"
    )

    @classmethod
    def setUpClass(cls):
        html = (ROOT / "api" / "static" / "index.html").read_text(encoding="utf-8")
        cls.script = re.search(r"<script>(.*?)</script>", html, re.S).group(1)

    def test_esc_helper_is_defined(self):
        self.assertIn("function esc(", self.script)

    def test_no_api_field_is_concatenated_without_esc(self):
        self.assertEqual(self.UNESCAPED.findall(self.script), [])

    def test_methodology_notes_and_axis_values_are_escaped(self):
        self.assertIn("esc(n)", self.script)
        self.assertIn("esc(axis.signal_level)", self.script)

    def test_the_check_itself_detects_the_original_flaw(self):
        # Garde-fou : le motif ci-dessus doit bien attraper l'ancien code.
        vulnerable = "'<div class=\"evidence-row\"><b>Preuve :</b> ' + (f.evidence || \"—\") + '</div>'"
        self.assertTrue(self.UNESCAPED.search(vulnerable))


if __name__ == "__main__":
    unittest.main()

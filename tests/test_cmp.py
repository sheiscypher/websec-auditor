import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checks.privacy import CMPDetectionStatus, CMPPageEvidence, detect_cmp, evaluate_cmp_presence
from enums import ControlResult


class TestCMPDetection(unittest.TestCase):
    def test_didomi_detected_via_script_src(self):
        evidence = CMPPageEvidence(script_srcs=("https://sdk.privacy-center.org/loader.js",))
        result = detect_cmp(evidence)
        self.assertEqual(result.status, CMPDetectionStatus.RECOGNIZED)
        self.assertEqual(result.provider_name, "Didomi")

    def test_onetrust_detected_via_cookie(self):
        evidence = CMPPageEvidence(cookie_names=("OptanonConsent",))
        result = detect_cmp(evidence)
        self.assertEqual(result.status, CMPDetectionStatus.RECOGNIZED)
        self.assertEqual(result.provider_name, "OneTrust")

    def test_onetrust_detected_via_js_var(self):
        evidence = CMPPageEvidence(global_js_vars_present=("OneTrust",))
        result = detect_cmp(evidence)
        self.assertEqual(result.provider_name, "OneTrust")

    def test_generic_cmp_detected_via_html_marker(self):
        evidence = CMPPageEvidence(html_markers=("cookie-banner",))
        result = detect_cmp(evidence)
        self.assertEqual(result.status, CMPDetectionStatus.GENERIC)
        self.assertIsNone(result.provider_name)

    def test_generic_cmp_detected_via_consent_link(self):
        """Régression du faux négatif corrigé : une bannière sans id/class
        reconnaissable, mais avec un lien 'Gérer mes préférences cookies'
        en pied de page, doit être détectée en CMP générique."""
        evidence = CMPPageEvidence(consent_link_detected=True)
        result = detect_cmp(evidence)
        self.assertEqual(result.status, CMPDetectionStatus.GENERIC)

    def test_consent_link_alone_is_scored_same_as_html_marker(self):
        via_link = evaluate_cmp_presence(CMPPageEvidence(consent_link_detected=True))
        via_marker = evaluate_cmp_presence(CMPPageEvidence(html_markers=("cookie-banner",)))
        self.assertEqual(via_link.result, via_marker.result)
        self.assertEqual(via_link.score_contribution, via_marker.score_contribution)

    def test_no_match_but_detection_uncertain_is_not_testable_not_absent(self):
        """Régression : une page tronquée/SPA ne doit jamais faire conclure
        à une absence de CMP — même règle que priv.legal_pages.*."""
        outcome = evaluate_cmp_presence(CMPPageEvidence(detection_uncertain=True))
        self.assertEqual(outcome.result, ControlResult.NOT_TESTABLE)
        self.assertIsNone(outcome.score_contribution)

    def test_no_match_and_detection_reliable_is_absent(self):
        outcome = evaluate_cmp_presence(CMPPageEvidence(detection_uncertain=False))
        self.assertEqual(outcome.result, ControlResult.ABSENT)
        self.assertEqual(outcome.score_contribution, 0.0)

    def test_recognized_cmp_wins_even_if_detection_uncertain(self):
        """L'incertitude ne doit jamais masquer une détection positive
        réelle — elle ne s'applique qu'en l'absence de tout signal."""
        evidence = CMPPageEvidence(cookie_names=("OptanonConsent",), detection_uncertain=True)
        outcome = evaluate_cmp_presence(evidence)
        self.assertEqual(outcome.result, ControlResult.OBSERVED)

    def test_no_cmp_when_nothing_matches(self):
        evidence = CMPPageEvidence()
        result = detect_cmp(evidence)
        self.assertEqual(result.status, CMPDetectionStatus.NONE)

    def test_generic_is_never_confused_with_no_cmp(self):
        """Mission section 8 : CMP_GENERIC != NO_CMP."""
        generic = detect_cmp(CMPPageEvidence(html_markers=("gdpr-banner",)))
        none = detect_cmp(CMPPageEvidence())
        self.assertNotEqual(generic.status, none.status)


class TestCMPScoring(unittest.TestCase):
    """Recognized ET generic comptent tous les deux comme OBSERVED pour le
    scoring : le contrôle mesure la PRÉSENCE d'un mécanisme, pas
    l'identification du fournisseur (SPEC.md §8.3)."""

    def test_recognized_cmp_is_observed(self):
        outcome = evaluate_cmp_presence(CMPPageEvidence(cookie_names=("didomi_token",)))
        self.assertEqual(outcome.result, ControlResult.OBSERVED)
        self.assertEqual(outcome.score_contribution, 100.0)

    def test_generic_cmp_is_also_observed(self):
        outcome = evaluate_cmp_presence(CMPPageEvidence(html_markers=("cookie-consent",)))
        self.assertEqual(outcome.result, ControlResult.OBSERVED)
        self.assertEqual(outcome.score_contribution, 100.0)

    def test_no_cmp_is_absent(self):
        outcome = evaluate_cmp_presence(CMPPageEvidence())
        self.assertEqual(outcome.result, ControlResult.ABSENT)
        self.assertEqual(outcome.score_contribution, 0.0)


if __name__ == "__main__":
    unittest.main()

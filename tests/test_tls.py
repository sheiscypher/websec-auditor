import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checks.tls import TLSEvidence, evaluate_tls
from enums import ControlResult


class TestTLSNoHardCap(unittest.TestCase):
    """Mission section 7 + section 12 : vérifier explicitement l'ABSENCE de
    hard cap. Un TLS critique contribue à 0.0 pour CE contrôle, sans plafond
    imposé au score d'un AUTRE contrôle ni au score d'axe au-delà de sa
    propre pondération normale (1/7)."""

    def test_expired_certificate_is_critical_but_only_this_control_scores_zero(self):
        evidence = TLSEvidence(
            connection_succeeded=True,
            certificate_expired=True,
            negotiated_protocol="TLSv1.3",
            tls13_available=True,
            hostname_matches=True,
            is_self_signed=False,
        )
        outcome = evaluate_tls(evidence)
        self.assertEqual(outcome.result, ControlResult.ABSENT)
        self.assertEqual(outcome.score_contribution, 0.0)
        # Pas de champ / mécanisme de hard cap dans le CheckOutcome lui-même :
        # aucun attribut du type "cap" ou "global_penalty" n'existe.
        self.assertFalse(hasattr(outcome, "hard_cap"))
        self.assertFalse(hasattr(outcome, "cap"))

    def test_obsolete_protocol_is_critical(self):
        evidence = TLSEvidence(connection_succeeded=True, negotiated_protocol="TLSv1.0")
        outcome = evaluate_tls(evidence)
        self.assertEqual(outcome.result, ControlResult.ABSENT)
        self.assertEqual(outcome.score_contribution, 0.0)

    def test_hostname_mismatch_is_critical(self):
        evidence = TLSEvidence(
            connection_succeeded=True, negotiated_protocol="TLSv1.3", hostname_matches=False
        )
        outcome = evaluate_tls(evidence)
        self.assertEqual(outcome.result, ControlResult.ABSENT)

    def test_self_signed_public_cert_is_critical(self):
        evidence = TLSEvidence(
            connection_succeeded=True, negotiated_protocol="TLSv1.3", is_self_signed=True
        )
        outcome = evaluate_tls(evidence)
        self.assertEqual(outcome.result, ControlResult.ABSENT)

    def test_expiring_soon_is_partial_not_critical(self):
        evidence = TLSEvidence(
            connection_succeeded=True,
            negotiated_protocol="TLSv1.3",
            tls13_available=True,
            days_until_expiry=10,
        )
        outcome = evaluate_tls(evidence)
        self.assertEqual(outcome.result, ControlResult.PARTIAL)
        self.assertEqual(outcome.score_contribution, 50.0)

    def test_tls12_only_without_tls13_is_partial(self):
        evidence = TLSEvidence(
            connection_succeeded=True,
            negotiated_protocol="TLSv1.2",
            tls13_available=False,
            days_until_expiry=200,
        )
        outcome = evaluate_tls(evidence)
        self.assertEqual(outcome.result, ControlResult.PARTIAL)

    def test_fully_favorable_case(self):
        evidence = TLSEvidence(
            connection_succeeded=True,
            negotiated_protocol="TLSv1.3",
            tls13_available=True,
            days_until_expiry=200,
            hostname_matches=True,
            is_self_signed=False,
        )
        outcome = evaluate_tls(evidence)
        self.assertEqual(outcome.result, ControlResult.OBSERVED)
        self.assertEqual(outcome.score_contribution, 100.0)

    def test_network_timeout_is_not_testable_not_absent(self):
        evidence = TLSEvidence(connection_succeeded=False, negotiation_explicitly_failed=False)
        outcome = evaluate_tls(evidence)
        self.assertEqual(outcome.result, ControlResult.NOT_TESTABLE)
        self.assertIsNone(outcome.score_contribution)

    def test_explicit_negotiation_refusal_is_absent_not_not_testable(self):
        evidence = TLSEvidence(connection_succeeded=False, negotiation_explicitly_failed=True)
        outcome = evaluate_tls(evidence)
        self.assertEqual(outcome.result, ControlResult.ABSENT)
        self.assertEqual(outcome.score_contribution, 0.0)


if __name__ == "__main__":
    unittest.main()

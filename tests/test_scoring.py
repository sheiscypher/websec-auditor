"""
Tests du moteur de scoring.

Volontairement indépendants de Pydantic : on simule un catalogue avec une
dataclass minimale portant les seuls attributs que scoring.py est autorisé
à lire (control_id, domain, scoring_status, weight) — exactement ce que la
mission section 11 impose ("le moteur ne connaît que ...").
"""

import sys
import unittest
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from enums import AxisStatus, ControlResult, Domain, ScoringStatus
from results import CheckOutcome
from scoring import ScoringContractError, compute_axis_score, grade_from_score, signal_level_from_score


@dataclass(frozen=True)
class FakeControl:
    control_id: str
    domain: Domain
    scoring_status: ScoringStatus
    weight: float | None


def make_outcome(control_id, result, score_contribution=None):
    return CheckOutcome(
        control_id=control_id,
        result=result,
        evidence="evidence",
        detection_method="method",
        score_contribution=score_contribution,
    )


class TestComputeAxisScore(unittest.TestCase):
    def setUp(self):
        # 4 contrôles Security INCLUDED, équipondérés à 0.25, + 1 EXCLUDED
        self.catalog = [
            FakeControl("s1", Domain.SECURITY, ScoringStatus.INCLUDED, 0.25),
            FakeControl("s2", Domain.SECURITY, ScoringStatus.INCLUDED, 0.25),
            FakeControl("s3", Domain.SECURITY, ScoringStatus.INCLUDED, 0.25),
            FakeControl("s4", Domain.SECURITY, ScoringStatus.INCLUDED, 0.25),
            FakeControl("s5_info", Domain.SECURITY, ScoringStatus.EXCLUDED, None),
        ]

    def test_all_pass_gives_100(self):
        outcomes = {
            "s1": make_outcome("s1", ControlResult.OBSERVED, 100.0),
            "s2": make_outcome("s2", ControlResult.OBSERVED, 100.0),
            "s3": make_outcome("s3", ControlResult.OBSERVED, 100.0),
            "s4": make_outcome("s4", ControlResult.OBSERVED, 100.0),
            "s5_info": make_outcome("s5_info", ControlResult.OBSERVED, None),
        }
        status, score, contributing, excluded = compute_axis_score(
            self.catalog, Domain.SECURITY, outcomes
        )
        self.assertEqual(status, AxisStatus.COMPUTED)
        self.assertEqual(score, 100.0)
        self.assertEqual(len(contributing), 4)  # jamais le contrôle EXCLUDED
        self.assertEqual(excluded, [])

    def test_one_fail_lowers_score_proportionally(self):
        outcomes = {
            "s1": make_outcome("s1", ControlResult.ABSENT, 0.0),
            "s2": make_outcome("s2", ControlResult.OBSERVED, 100.0),
            "s3": make_outcome("s3", ControlResult.OBSERVED, 100.0),
            "s4": make_outcome("s4", ControlResult.OBSERVED, 100.0),
        }
        status, score, _, _ = compute_axis_score(self.catalog, Domain.SECURITY, outcomes)
        self.assertEqual(status, AxisStatus.COMPUTED)
        self.assertAlmostEqual(score, 75.0)

    def test_several_fails(self):
        outcomes = {
            "s1": make_outcome("s1", ControlResult.ABSENT, 0.0),
            "s2": make_outcome("s2", ControlResult.ABSENT, 0.0),
            "s3": make_outcome("s3", ControlResult.OBSERVED, 100.0),
            "s4": make_outcome("s4", ControlResult.OBSERVED, 100.0),
        }
        status, score, _, _ = compute_axis_score(self.catalog, Domain.SECURITY, outcomes)
        self.assertAlmostEqual(score, 50.0)

    def test_unknown_is_excluded_and_weight_redistributed(self):
        """1 contrôle NOT_TESTABLE (UNKNOWN) sur 4 : le poids doit être
        redistribué entre les 3 restants, pas ignoré silencieusement ni
        transformé en FAIL."""
        outcomes = {
            "s1": make_outcome("s1", ControlResult.NOT_TESTABLE),  # UNKNOWN
            "s2": make_outcome("s2", ControlResult.OBSERVED, 100.0),
            "s3": make_outcome("s3", ControlResult.OBSERVED, 100.0),
            "s4": make_outcome("s4", ControlResult.OBSERVED, 100.0),
        }
        status, score, contributing, excluded = compute_axis_score(
            self.catalog, Domain.SECURITY, outcomes
        )
        self.assertEqual(status, AxisStatus.COMPUTED)
        self.assertAlmostEqual(score, 100.0)  # les 3 évaluables sont tous à 100
        self.assertEqual(len(contributing), 3)
        self.assertEqual(excluded, ["s1"])
        # Le poids appliqué à chaque contrôle évaluable doit être 1/3, pas 1/4
        for c in contributing:
            self.assertAlmostEqual(c["weight_applied"], 1 / 3)

    def test_not_applicable_also_excluded_from_denominator(self):
        outcomes = {
            "s1": make_outcome("s1", ControlResult.NOT_APPLICABLE),
            "s2": make_outcome("s2", ControlResult.OBSERVED, 100.0),
            "s3": make_outcome("s3", ControlResult.OBSERVED, 100.0),
            "s4": make_outcome("s4", ControlResult.OBSERVED, 100.0),
        }
        status, score, _, excluded = compute_axis_score(self.catalog, Domain.SECURITY, outcomes)
        self.assertEqual(status, AxisStatus.COMPUTED)
        self.assertEqual(excluded, ["s1"])
        self.assertAlmostEqual(score, 100.0)

    def test_all_unknown_gives_not_computable(self):
        outcomes = {
            "s1": make_outcome("s1", ControlResult.NOT_TESTABLE),
            "s2": make_outcome("s2", ControlResult.NOT_APPLICABLE),
            "s3": make_outcome("s3", ControlResult.NOT_TESTABLE),
            "s4": make_outcome("s4", ControlResult.NOT_APPLICABLE),
        }
        status, score, contributing, excluded = compute_axis_score(
            self.catalog, Domain.SECURITY, outcomes
        )
        self.assertEqual(status, AxisStatus.NOT_COMPUTABLE)
        self.assertIsNone(score)
        self.assertEqual(contributing, [])
        self.assertEqual(len(excluded), 4)

    def test_excluded_control_never_influences_score_even_if_present_in_outcomes(self):
        """Un contrôle EXCLUDED avec un résultat très défavorable ne doit
        JAMAIS faire bouger le score, quel que soit son score_contribution."""
        outcomes = {
            "s1": make_outcome("s1", ControlResult.OBSERVED, 100.0),
            "s2": make_outcome("s2", ControlResult.OBSERVED, 100.0),
            "s3": make_outcome("s3", ControlResult.OBSERVED, 100.0),
            "s4": make_outcome("s4", ControlResult.OBSERVED, 100.0),
            "s5_info": make_outcome("s5_info", ControlResult.ABSENT, 0.0),  # ne doit rien changer
        }
        status, score, contributing, _ = compute_axis_score(self.catalog, Domain.SECURITY, outcomes)
        self.assertEqual(score, 100.0)
        self.assertNotIn("s5_info", [c["control_id"] for c in contributing])

    def test_missing_outcome_for_included_control_raises_contract_error(self):
        outcomes = {
            "s1": make_outcome("s1", ControlResult.OBSERVED, 100.0),
            # s2, s3, s4 manquants
        }
        with self.assertRaises(ScoringContractError):
            compute_axis_score(self.catalog, Domain.SECURITY, outcomes)

    def test_included_control_with_evaluable_result_but_no_score_raises(self):
        outcomes = {
            "s1": make_outcome("s1", ControlResult.OBSERVED, None),  # manque score_contribution
            "s2": make_outcome("s2", ControlResult.OBSERVED, 100.0),
            "s3": make_outcome("s3", ControlResult.OBSERVED, 100.0),
            "s4": make_outcome("s4", ControlResult.OBSERVED, 100.0),
        }
        with self.assertRaises(ScoringContractError):
            compute_axis_score(self.catalog, Domain.SECURITY, outcomes)

    def test_wrong_domain_is_ignored_by_axis_computation(self):
        catalog_mixed = self.catalog + [
            FakeControl("p1", Domain.PRIVACY, ScoringStatus.INCLUDED, 1 / 3),
        ]
        outcomes = {
            "s1": make_outcome("s1", ControlResult.OBSERVED, 100.0),
            "s2": make_outcome("s2", ControlResult.OBSERVED, 100.0),
            "s3": make_outcome("s3", ControlResult.OBSERVED, 100.0),
            "s4": make_outcome("s4", ControlResult.OBSERVED, 100.0),
            "p1": make_outcome("p1", ControlResult.ABSENT, 0.0),
        }
        status, score, contributing, _ = compute_axis_score(
            catalog_mixed, Domain.SECURITY, outcomes
        )
        # Le score Security ne doit pas être affecté par p1 (autre domaine)
        self.assertEqual(score, 100.0)
        self.assertEqual(len(contributing), 4)


class TestGradeAndSignalLevel(unittest.TestCase):
    def test_grade_boundaries(self):
        self.assertEqual(grade_from_score(95), "A")
        self.assertEqual(grade_from_score(75), "B")
        self.assertEqual(grade_from_score(60), "C")
        self.assertEqual(grade_from_score(40), "D")
        self.assertEqual(grade_from_score(10), "F")

    def test_signal_level_never_uses_letters(self):
        from enums import PrivacySignalLevel

        for score in (10, 50, 90):
            level = signal_level_from_score(score)
            self.assertIsInstance(level, PrivacySignalLevel)
            self.assertNotIn(level.name, ("A", "B", "C", "D", "F"))


if __name__ == "__main__":
    unittest.main()

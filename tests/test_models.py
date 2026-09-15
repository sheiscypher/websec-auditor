"""
Tests des validateurs Pydantic (mission section 12).

ATTENTION : nécessite Pydantic installé (voir PROBLÈME n°1 du compte rendu).
    pip install -r requirements.txt
    python -m pytest tests/test_models.py -v
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pydantic import ValidationError

from enums import AxisStatus, ControlResult, Domain, EvidenceLevel, ScoringStatus
from models import (
    AiGovernancePanel,
    ControlDefinition,
    ControlPhrasing,
    PrivacySignalsScore,
    ScoreBreakdown,
    SecurityPostureScore,
)


class TestControlDefinitionWeightValidation(unittest.TestCase):
    def test_included_without_weight_is_rejected(self):
        with self.assertRaises(ValidationError):
            ControlDefinition(
                control_id="x",
                domain=Domain.SECURITY,
                evidence_level=EvidenceLevel.A,
                scoring_status=ScoringStatus.INCLUDED,
                weight=None,
                report_label="X",
                phrasing=ControlPhrasing(observed="ok"),
            )

    def test_excluded_with_weight_is_rejected(self):
        with self.assertRaises(ValidationError):
            ControlDefinition(
                control_id="x",
                domain=Domain.SECURITY,
                evidence_level=EvidenceLevel.A,
                scoring_status=ScoringStatus.EXCLUDED,
                weight=0.5,
                report_label="X",
                phrasing=ControlPhrasing(observed="ok"),
            )

    def test_included_with_weight_is_valid(self):
        cd = ControlDefinition(
            control_id="x",
            domain=Domain.SECURITY,
            evidence_level=EvidenceLevel.A,
            scoring_status=ScoringStatus.INCLUDED,
            weight=1 / 7,
            report_label="X",
            phrasing=ControlPhrasing(observed="ok"),
        )
        self.assertAlmostEqual(cd.weight, 1 / 7)

    def test_excluded_without_weight_is_valid(self):
        cd = ControlDefinition(
            control_id="x",
            domain=Domain.SECURITY,
            evidence_level=EvidenceLevel.B,
            scoring_status=ScoringStatus.EXCLUDED,
            weight=None,
            report_label="X",
            phrasing=ControlPhrasing(observed="ok"),
        )
        self.assertIsNone(cd.weight)


class TestScoreBreakdownNoGlobalScore(unittest.TestCase):
    def _valid_breakdown_kwargs(self):
        return dict(
            security_posture=SecurityPostureScore(status=AxisStatus.COMPUTED, score=80.0, grade="B"),
            privacy_signals=PrivacySignalsScore(
                status=AxisStatus.COMPUTED, score=60.0, signal_level=None
            ),
            ai_governance=AiGovernancePanel(signals_observed_count=2, signals_total_count=5),
        )

    def test_valid_score_breakdown_builds(self):
        sb = ScoreBreakdown(**self._valid_breakdown_kwargs())
        self.assertEqual(sb.security_posture.score, 80.0)

    def test_privacy_signals_score_has_no_grade_field_in_schema(self):
        """PrivacySignalsScore ne doit structurellement pas exposer de champ
        `grade` (SPEC.md §7.4) — pas de lettre A-F pour Privacy. Vérifié au
        niveau du schéma plutôt qu'en testant le rejet d'un extra kwarg,
        car models.py n'impose pas extra="forbid" (non modifié ici, cf.
        décisions méthodologiques du compte rendu)."""
        self.assertNotIn("grade", PrivacySignalsScore.model_fields)
        self.assertIn("signal_level", PrivacySignalsScore.model_fields)

    def test_not_computable_axis_rejects_numeric_score(self):
        with self.assertRaises(ValidationError):
            SecurityPostureScore(status=AxisStatus.NOT_COMPUTABLE, score=50.0)

    def test_computed_axis_requires_score(self):
        with self.assertRaises(ValidationError):
            SecurityPostureScore(status=AxisStatus.COMPUTED, score=None)


if __name__ == "__main__":
    unittest.main()

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checks.security_txt import evaluate_security_txt
from enums import ControlResult


class TestSecurityTxt(unittest.TestCase):
    def test_found_at_canonical_path_is_observed(self):
        outcome = evaluate_security_txt("/.well-known/security.txt")
        self.assertEqual(outcome.result, ControlResult.OBSERVED)
        self.assertIsNone(outcome.score_contribution)  # jamais scoré

    def test_not_found_is_absent(self):
        outcome = evaluate_security_txt(None)
        self.assertEqual(outcome.result, ControlResult.ABSENT)
        self.assertIsNone(outcome.score_contribution)

    def test_wording_never_implies_maturity_certification(self):
        outcome = evaluate_security_txt(None)
        for forbidden in ("immature", "non sécurisé", "mauvaise pratique"):
            self.assertNotIn(forbidden, outcome.evidence.lower())


if __name__ == "__main__":
    unittest.main()

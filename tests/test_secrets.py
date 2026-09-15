import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checks.secrets import ScannedResource, evaluate_corroborated_signal, evaluate_secret_patterns
from enums import ControlResult


class TestSecretPatternDetection(unittest.TestCase):
    def test_no_resources_is_not_testable(self):
        outcome = evaluate_secret_patterns(None)
        self.assertEqual(outcome.result, ControlResult.NOT_TESTABLE)

    def test_no_match_is_absent_with_full_score(self):
        resources = [ScannedResource(path="/index.html", content="<html>hello</html>")]
        outcome = evaluate_secret_patterns(resources)
        self.assertEqual(outcome.result, ControlResult.ABSENT)
        self.assertEqual(outcome.score_contribution, 100.0)

    def test_match_is_observed_with_zero_score(self):
        resources = [ScannedResource(path="/app.js", content="const key = 'AKIAABCD1234EFGH5678';")]
        outcome = evaluate_secret_patterns(resources)
        self.assertEqual(outcome.result, ControlResult.OBSERVED)
        self.assertEqual(outcome.score_contribution, 0.0)

    def test_wording_never_confirms_secret(self):
        resources = [ScannedResource(path="/app.js", content="sk_live_abcdefghijklmnopqrst")]
        outcome = evaluate_secret_patterns(resources)
        for forbidden in ("secret exposé", "secret confirmé", "confirmée"):
            self.assertNotIn(forbidden, outcome.evidence.lower())


class TestCorroboratedSignal(unittest.TestCase):
    def test_no_pattern_gives_no_finding_at_all(self):
        resources = [ScannedResource(path="/index.html", content="nothing here")]
        outcome = evaluate_corroborated_signal(resources)
        self.assertIsNone(outcome)

    def test_pattern_in_test_path_is_not_corroborated(self):
        resources = [ScannedResource(path="/test/fixtures/app.js", content="AKIAABCD1234EFGH5678")]
        outcome = evaluate_corroborated_signal(resources)
        self.assertIsNone(outcome)

    def test_pattern_with_placeholder_marker_is_not_corroborated(self):
        resources = [ScannedResource(path="/app.js", content="AKIAxxxxxxxxxxxxxxxx")]
        outcome = evaluate_corroborated_signal(resources)
        self.assertIsNone(outcome)

    def test_pattern_in_production_path_without_placeholder_is_corroborated(self):
        resources = [ScannedResource(path="/static/bundle.js", content="AKIAABCD1234EFGH5678")]
        outcome = evaluate_corroborated_signal(resources)
        self.assertIsNotNone(outcome)
        self.assertEqual(outcome.result, ControlResult.OBSERVED)
        # Informatif : ne doit jamais porter de score_contribution
        self.assertIsNone(outcome.score_contribution)


if __name__ == "__main__":
    unittest.main()

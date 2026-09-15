import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checks.exposure import PathProbeResult, evaluate_exposed_files
from enums import ControlResult


class TestExposedFiles(unittest.TestCase):
    def test_no_probes_is_not_testable(self):
        outcome = evaluate_exposed_files([])
        self.assertEqual(outcome.result, ControlResult.NOT_TESTABLE)

    def test_all_blocked_is_not_testable(self):
        probes = [PathProbeResult(path="/.env", http_status=None)]
        outcome = evaluate_exposed_files(probes)
        self.assertEqual(outcome.result, ControlResult.NOT_TESTABLE)

    def test_html_error_page_is_filtered_as_false_positive(self):
        probes = [
            PathProbeResult(
                path="/.env", http_status=200, content_type="text/html", body_snippet="<html>404</html>"
            )
        ]
        outcome = evaluate_exposed_files(probes)
        self.assertEqual(outcome.result, ControlResult.ABSENT)

    def test_genuine_env_file_is_observed(self):
        probes = [
            PathProbeResult(
                path="/.env",
                http_status=200,
                content_type="text/plain",
                body_snippet="DB_PASSWORD=secret123",
            )
        ]
        outcome = evaluate_exposed_files(probes)
        self.assertEqual(outcome.result, ControlResult.OBSERVED)
        self.assertEqual(outcome.score_contribution, 0.0)

    def test_wording_never_claims_file_exposed(self):
        """Mission section 3 : jamais 'fichier sensible exposé'."""
        probes = [
            PathProbeResult(
                path="/.git/config",
                http_status=200,
                content_type="text/plain",
                body_snippet="[core]\nrepositoryformatversion = 0",
            )
        ]
        outcome = evaluate_exposed_files(probes)
        self.assertNotIn("fichier sensible exposé", outcome.evidence.lower())
        self.assertIn("chemin", outcome.evidence.lower())

    def test_no_accessible_path_is_absent_with_100(self):
        probes = [
            PathProbeResult(path="/.env", http_status=404),
            PathProbeResult(path="/backup.zip", http_status=403),
        ]
        outcome = evaluate_exposed_files(probes)
        self.assertEqual(outcome.result, ControlResult.ABSENT)
        self.assertEqual(outcome.score_contribution, 100.0)


if __name__ == "__main__":
    unittest.main()

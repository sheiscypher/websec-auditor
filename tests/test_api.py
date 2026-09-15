"""
tests/test_api.py — Vérifie que l'application démarre et que les endpoints
répondent (mission §10 "Test HTTP").

ATTENTION : nécessite fastapi + httpx installés. Non exécutable dans ce
sandbox. À lancer avec :
    pip install -r requirements.txt
    python -m pytest tests/test_api.py -v
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient


class TestHealthEndpoint(unittest.TestCase):
    def test_health_returns_ok(self):
        from api.main import app

        client = TestClient(app)
        response = client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})


class TestAuditEndpoint(unittest.TestCase):
    def test_invalid_scheme_returns_400(self):
        from api.main import app

        client = TestClient(app)
        response = client.post("/audit", json={"url": "file:///etc/passwd"})
        self.assertEqual(response.status_code, 400)

    @patch("api.main.run_audit")
    def test_unexpected_exception_returns_500_not_raw_trace(self, mock_run_audit):
        from api.main import app

        mock_run_audit.side_effect = RuntimeError("boom")
        client = TestClient(app)
        response = client.post("/audit", json={"url": "https://example.com"})
        self.assertEqual(response.status_code, 500)
        self.assertNotIn("boom", response.text)  # pas de fuite de la trace brute

    def test_index_serves_html(self):
        from api.main import app

        client = TestClient(app)
        response = client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("WebSec Auditor", response.text)


class TestFindingEnrichment(unittest.TestCase):
    """Mission section 4 : le frontend doit recevoir domaine/niveau de
    preuve/statut de scoring déjà résolus — vérifie que l'enrichissement
    API ajoute ces champs sans toucher au contenu du Finding d'origine."""

    def test_enrich_finding_adds_catalog_metadata(self):
        from api.main import _enrich_finding
        from unittest.mock import MagicMock

        fake_finding = MagicMock()
        fake_finding.control_id = "sec.headers"
        fake_finding.model_dump.return_value = {
            "control_id": "sec.headers",
            "result": "OBSERVED",
            "resolved_label": "6/6 en-têtes corrects.",
        }

        enriched = _enrich_finding(fake_finding)

        self.assertEqual(enriched["domain"], "SECURITY")
        self.assertEqual(enriched["evidence_level"], "A")
        self.assertEqual(enriched["scoring_status"], "INCLUDED")
        self.assertAlmostEqual(enriched["weight"], 1 / 8)
        self.assertIn("resolved_label", enriched)  # contenu d'origine préservé

    def test_enrich_finding_on_excluded_control_has_no_weight(self):
        from api.main import _enrich_finding
        from unittest.mock import MagicMock

        fake_finding = MagicMock()
        fake_finding.control_id = "sec.cms_detection"
        fake_finding.model_dump.return_value = {"control_id": "sec.cms_detection", "result": "OBSERVED"}

        enriched = _enrich_finding(fake_finding)

        self.assertEqual(enriched["scoring_status"], "EXCLUDED")
        self.assertIsNone(enriched["weight"])


if __name__ == "__main__":
    unittest.main()

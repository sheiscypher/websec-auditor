"""
tests/test_audit_service.py — Test d'intégration avec collectors mockés.

ATTENTION : nécessite Pydantic + httpx + dnspython installés (import de
services.audit_service -> control_catalog -> models -> pydantic, et
collectors/*.py -> httpx/dnspython). Non exécutable dans le sandbox
d'implémentation (voir compte rendu). À lancer avec :

    pip install -r requirements.txt
    python -m pytest tests/test_audit_service.py -v

Objectif : vérifier que le pipeline Evidence → Check → Score fonctionne de
bout en bout SANS dépendre d'un accès réseau réel, en mockant uniquement
la couche collectors (http_collector.safe_get, tls_collector, dns_collector).
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class TestAuditServiceIntegration(unittest.TestCase):
    def _make_fetch_result(self, url, status=200, body="<html><body>hello world "
                            + "word " * 60 + "</body></html>", headers=None):
        from collectors.http import FetchResult

        return FetchResult(
            url=url,
            status_code=status,
            headers=headers or {
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "camera=(), microphone=()",
            },
            body=body,
            content_type="text/html",
        )

    @patch("collectors.dns.get_dmarc_record", return_value=(True, "reject"))
    @patch("collectors.dns.get_spf_record", return_value="v=spf1 -all")
    @patch("collectors.dns.has_mx_record", return_value=True)
    @patch("collectors.dns.check_dnssec", return_value=True)
    @patch("collectors.tls.collect_tls_evidence")
    @patch("services.audit_service.http_collector.safe_get")
    @patch("services.audit_service.ensure_url_is_safe")
    def test_full_pipeline_with_favorable_evidence_gives_high_scores(
        self, mock_ssrf, mock_safe_get, mock_tls, *_
    ):
        from checks.tls import TLSEvidence
        from security.ssrf import ParsedTarget

        mock_ssrf.return_value = ParsedTarget(
            scheme="https", hostname="example.com", port=None, original_url="https://example.com"
        )
        mock_tls.return_value = TLSEvidence(
            connection_succeeded=True,
            negotiated_protocol="TLSv1.3",
            tls13_available=True,
            days_until_expiry=200,
            hostname_matches=True,
            is_self_signed=False,
        )
        # Page d'accueil réellement favorable sur TOUS les axes scorés, pas
        # seulement Security : footer avec liens légaux + bandeau cookie
        # identifiable, sinon Privacy/CMP restent ABSENT même dans un test
        # censé représenter un site entièrement conforme (bug de mock
        # découvert à la première exécution réelle avec Pydantic — ce test
        # n'avait jamais tourné avant, cf. compte rendu).
        favorable_body = (
            "<html><body>"
            + ("word " * 60)
            + '<div id="cookie-banner">Bandeau de consentement</div>'
            + '<footer><a href="/mentions-legales">Mentions légales</a>'
            + '<a href="/politique-de-confidentialite">Politique de confidentialité</a></footer>'
            + "</body></html>"
        )
        favorable_homepage = self._make_fetch_result("https://example.com", body=favorable_body)

        # Toute requête HTTP (homepage, chemins sensibles, llms.txt,
        # robots.txt...) retourne un 404 sauf la racine, pour isoler le
        # test sur les contrôles qui dépendent de la page d'accueil.
        def fake_safe_get(u, timeout=8.0):
            if u.rstrip("/") in ("https://example.com",):
                return favorable_homepage
            return self._make_fetch_result(u, status=404, body="")

        mock_safe_get.side_effect = fake_safe_get

        from services.audit_service import run_audit

        payload, key_findings = run_audit("https://example.com")

        self.assertEqual(payload.score_breakdown.security_posture.grade, "A")
        self.assertIsNotNone(payload.score_breakdown.security_posture.score)
        self.assertGreaterEqual(payload.score_breakdown.security_posture.score, 85)
        self.assertEqual(key_findings, [])  # tout favorable -> aucun key finding

    @patch("collectors.dns.get_dmarc_record", return_value=(True, "reject"))
    @patch("collectors.dns.get_spf_record", return_value="v=spf1 -all")
    @patch("collectors.dns.has_mx_record", return_value=True)
    @patch("collectors.dns.check_dnssec", return_value=False)  # défavorable, volontairement
    @patch("collectors.tls.collect_tls_evidence")
    @patch("services.audit_service.http_collector.safe_get")
    @patch("services.audit_service.ensure_url_is_safe")
    def test_unfavorable_result_appears_in_key_findings_with_risk_category(
        self, mock_ssrf, mock_safe_get, mock_tls, *_
    ):
        from checks.tls import TLSEvidence
        from security.ssrf import ParsedTarget

        mock_ssrf.return_value = ParsedTarget(
            scheme="https", hostname="example.com", port=None, original_url="https://example.com"
        )
        mock_tls.return_value = TLSEvidence(
            connection_succeeded=True, negotiated_protocol="TLSv1.3", tls13_available=True,
            days_until_expiry=200, hostname_matches=True, is_self_signed=False,
        )

        def fake_safe_get(u, timeout=8.0):
            if u.rstrip("/") == "https://example.com":
                return self._make_fetch_result(u)
            return self._make_fetch_result(u, status=404, body="")

        mock_safe_get.side_effect = fake_safe_get

        from services.audit_service import run_audit

        payload, key_findings = run_audit("https://example.com")

        dnssec_findings = [kf for kf in key_findings if kf["control_id"] == "sec.dns.dnssec"]
        self.assertEqual(len(dnssec_findings), 1)
        self.assertEqual(dnssec_findings[0]["risk_category"], "Intégrité de la résolution DNS")
        self.assertLessEqual(len(key_findings), 5)

    @patch("collectors.dns.get_dmarc_record", return_value=(True, "reject"))
    @patch("collectors.dns.get_spf_record", return_value="v=spf1 -all")
    @patch("collectors.dns.has_mx_record", return_value=True)
    @patch("collectors.dns.check_dnssec", return_value=True)
    @patch("collectors.tls.collect_tls_evidence")
    @patch("services.audit_service.http_collector.safe_get")
    @patch("services.audit_service.ensure_url_is_safe")
    def test_legal_notice_found_via_footer_link_with_atypical_url(
        self, mock_ssrf, mock_safe_get, mock_tls, *_
    ):
        """Régression du faux négatif corrigé (cf. compte rendu, cas
        Castorama) : la page légale est liée depuis le pied de page avec
        un texte explicite, mais une URL qui ne correspond à AUCUN des
        chemins devinés par PRIVACY_POLICY_PATHS/LEGAL_NOTICE_PATHS.
        Doit être trouvée via l'extraction de lien, sans sonder aucun
        chemin spécifique à un site précis (pas de hardcoding)."""
        from checks.tls import TLSEvidence
        from security.ssrf import ParsedTarget

        mock_ssrf.return_value = ParsedTarget(
            scheme="https", hostname="example.com", port=None, original_url="https://example.com"
        )
        mock_tls.return_value = TLSEvidence(
            connection_succeeded=True, negotiated_protocol="TLSv1.3", tls13_available=True,
            days_until_expiry=200, hostname_matches=True, is_self_signed=False,
        )

        homepage_with_atypical_footer = self._make_fetch_result(
            "https://example.com",
            body=(
                "<html><body>"
                + ("word " * 60)
                + '<footer><a href="/page-info-42.html">Mentions légales</a>'
                + '<a href="/rgpd-details">Politique de protection des données</a></footer>'
                + "</body></html>"
            ),
        )

        def fake_safe_get(u, timeout=8.0):
            if u.rstrip("/") == "https://example.com":
                return homepage_with_atypical_footer
            return self._make_fetch_result(u, status=404, body="")

        mock_safe_get.side_effect = fake_safe_get

        from services.audit_service import run_audit

        payload, _ = run_audit("https://example.com")

        findings_by_id = {f.control_id: f for f in payload.findings}
        self.assertEqual(findings_by_id["priv.legal_pages.legal_notice"].result, "OBSERVED")
        self.assertEqual(findings_by_id["priv.legal_pages.privacy_policy"].result, "OBSERVED")

    @patch("collectors.dns.get_dmarc_record", return_value=(True, "reject"))
    @patch("collectors.dns.get_spf_record", return_value="v=spf1 -all")
    @patch("collectors.dns.has_mx_record", return_value=True)
    @patch("collectors.dns.check_dnssec", return_value=True)
    @patch("collectors.tls.collect_tls_evidence")
    @patch("services.audit_service.http_collector.safe_get")
    @patch("services.audit_service.ensure_url_is_safe")
    def test_legal_notice_genuinely_absent_is_absent_not_false_positive(
        self, mock_ssrf, mock_safe_get, mock_tls, *_
    ):
        """Contrôle négatif : aucun lien légal nulle part, aucun chemin
        connu ne répond -> ABSENT, pas OBSERVED par erreur (pas de faux
        positif introduit par la correction)."""
        from checks.tls import TLSEvidence
        from security.ssrf import ParsedTarget

        mock_ssrf.return_value = ParsedTarget(
            scheme="https", hostname="example.com", port=None, original_url="https://example.com"
        )
        mock_tls.return_value = TLSEvidence(
            connection_succeeded=True, negotiated_protocol="TLSv1.3", tls13_available=True,
            days_until_expiry=200, hostname_matches=True, is_self_signed=False,
        )

        homepage_without_legal_links = self._make_fetch_result(
            "https://example.com",
            body=(
                "<html><body>"
                + ("word " * 60)
                + '<footer><a href="/promotions">Nos promotions</a>'
                + '<a href="/contact">Nous contacter</a></footer>'
                + "</body></html>"
            ),
        )

        def fake_safe_get(u, timeout=8.0):
            if u.rstrip("/") == "https://example.com":
                return homepage_without_legal_links
            return self._make_fetch_result(u, status=404, body="")

        mock_safe_get.side_effect = fake_safe_get

        from services.audit_service import run_audit

        payload, _ = run_audit("https://example.com")

        findings_by_id = {f.control_id: f for f in payload.findings}
        self.assertEqual(findings_by_id["priv.legal_pages.legal_notice"].result, "ABSENT")
        self.assertEqual(findings_by_id["priv.legal_pages.privacy_policy"].result, "ABSENT")

    @patch("collectors.dns.get_dmarc_record", return_value=(True, "reject"))
    @patch("collectors.dns.get_spf_record", return_value="v=spf1 -all")
    @patch("collectors.dns.has_mx_record", return_value=True)
    @patch("collectors.dns.check_dnssec", return_value=True)
    @patch("collectors.tls.collect_tls_evidence")
    @patch("services.audit_service.http_collector.safe_get")
    @patch("services.audit_service.ensure_url_is_safe")
    def test_legal_notice_blocked_by_waf_is_not_testable_not_absent(
        self, mock_ssrf, mock_safe_get, mock_tls, *_
    ):
        """Cas où la page n'est pas trouvable via les liens de la page
        d'accueil (ex: mega-menu sans lien direct visible) ET où le
        sondage direct du chemin est bloqué (403, simulant un WAF) ->
        NOT_TESTABLE, jamais ABSENT (mission §3/§15)."""
        from checks.tls import TLSEvidence
        from security.ssrf import ParsedTarget

        mock_ssrf.return_value = ParsedTarget(
            scheme="https", hostname="example.com", port=None, original_url="https://example.com"
        )
        mock_tls.return_value = TLSEvidence(
            connection_succeeded=True, negotiated_protocol="TLSv1.3", tls13_available=True,
            days_until_expiry=200, hostname_matches=True, is_self_signed=False,
        )

        homepage_without_footer_links = self._make_fetch_result("https://example.com")

        def fake_safe_get(u, timeout=8.0):
            if u.rstrip("/") == "https://example.com":
                return homepage_without_footer_links
            if "mentions-legales" in u or "confidentialite" in u or "privacy" in u or "legal" in u:
                return self._make_fetch_result(u, status=403, body="Forbidden")
            return self._make_fetch_result(u, status=404, body="")

        mock_safe_get.side_effect = fake_safe_get

        from services.audit_service import run_audit

        payload, _ = run_audit("https://example.com")

        findings_by_id = {f.control_id: f for f in payload.findings}
        self.assertEqual(findings_by_id["priv.legal_pages.legal_notice"].result, "NOT_TESTABLE")
        self.assertEqual(findings_by_id["priv.legal_pages.privacy_policy"].result, "NOT_TESTABLE")

    @patch("services.audit_service.ensure_url_is_safe")
    def test_invalid_url_raises_audit_input_error_before_any_collector_call(self, mock_ssrf):
        from security.ssrf import URLValidationError
        from services.audit_service import AuditInputError, run_audit

        mock_ssrf.side_effect = URLValidationError("Schéma non autorisé.")

        with self.assertRaises(AuditInputError):
            run_audit("file:///etc/passwd")


if __name__ == "__main__":
    unittest.main()

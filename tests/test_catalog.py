"""
Tests d'invariants du catalogue (mission section 12 / 17 étape 8).

ATTENTION : ce fichier importe control_catalog.py -> models.py -> pydantic.
Il NE PEUT PAS s'exécuter dans un environnement sans Pydantic installé
(voir compte rendu d'implémentation, PROBLÈME n°1). À lancer avec :

    pip install -r requirements.txt
    python -m pytest tests/test_catalog.py -v
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from control_catalog import FULL_CATALOG, AI_GOVERNANCE
from enums import Domain, EvidenceLevel, ScoringStatus


# Référentiel exact attendu (mission complément — étape 1/2). Toute
# modification de cette table doit être justifiée par un changement dans
# SPEC.md §8 en premier — jamais l'inverse. C'est ce qui permet de détecter
# un contrôle manquant, un contrôle en trop, un mauvais scoring_status ou
# un mauvais evidence_level, même si les COMPTEURS globaux restent corrects
# par coïncidence (ex: un contrôle remplacé par un autre sans changer le
# total).
EXPECTED_CATALOG = {
    "sec.headers": (Domain.SECURITY, ScoringStatus.INCLUDED, EvidenceLevel.A),
    "sec.tls": (Domain.SECURITY, ScoringStatus.INCLUDED, EvidenceLevel.A),
    "sec.exposed_files": (Domain.SECURITY, ScoringStatus.INCLUDED, EvidenceLevel.A),
    "sec.secrets.pattern_detected": (Domain.SECURITY, ScoringStatus.INCLUDED, EvidenceLevel.A),
    "sec.dns.dnssec": (Domain.SECURITY, ScoringStatus.INCLUDED, EvidenceLevel.A),
    "sec.email_security": (Domain.SECURITY, ScoringStatus.INCLUDED, EvidenceLevel.A),
    "sec.supply_chain.sri": (Domain.SECURITY, ScoringStatus.INCLUDED, EvidenceLevel.A),
    "sec.cookies.secure_httponly": (Domain.SECURITY, ScoringStatus.INCLUDED, EvidenceLevel.A),
    "sec.cookies.samesite_distribution": (Domain.SECURITY, ScoringStatus.EXCLUDED, EvidenceLevel.B),
    "sec.security_txt.presence": (Domain.SECURITY, ScoringStatus.EXCLUDED, EvidenceLevel.A),
    "sec.cms_detection": (Domain.SECURITY, ScoringStatus.EXCLUDED, EvidenceLevel.A),
    "sec.cms_cve_mapping": (Domain.SECURITY, ScoringStatus.EXCLUDED, EvidenceLevel.B),
    "sec.secrets.corroborated_signal": (Domain.SECURITY, ScoringStatus.EXCLUDED, EvidenceLevel.B),
    "sec.supply_chain.outdated_library": (Domain.SECURITY, ScoringStatus.EXCLUDED, EvidenceLevel.B),
    "priv.legal_pages.privacy_policy": (Domain.PRIVACY, ScoringStatus.INCLUDED, EvidenceLevel.A),
    "priv.legal_pages.legal_notice": (Domain.PRIVACY, ScoringStatus.INCLUDED, EvidenceLevel.A),
    "priv.cmp.presence": (Domain.PRIVACY, ScoringStatus.INCLUDED, EvidenceLevel.A),
    "priv.trackers.third_party_detected": (Domain.PRIVACY, ScoringStatus.EXCLUDED, EvidenceLevel.B),
    "ai.llms_txt.presence": (Domain.AI_GOVERNANCE, ScoringStatus.EXCLUDED, EvidenceLevel.A),
    "ai.robots_bot_directives": (Domain.AI_GOVERNANCE, ScoringStatus.EXCLUDED, EvidenceLevel.A),
    "ai.chatbot_detected": (Domain.AI_GOVERNANCE, ScoringStatus.EXCLUDED, EvidenceLevel.B),
    "ai.public_ai_usage_mention": (Domain.AI_GOVERNANCE, ScoringStatus.EXCLUDED, EvidenceLevel.B),
    "ai.governance_documentation_public": (Domain.AI_GOVERNANCE, ScoringStatus.EXCLUDED, EvidenceLevel.C),
}


class TestCatalogMatchesSpecExactly(unittest.TestCase):
    """Vérification par ID exact — détecte un contrôle manquant, un
    contrôle en trop, un mauvais scoring_status ou un mauvais
    evidence_level, même si les compteurs globaux restent accidentellement
    corrects (mission complément, étape 2)."""

    def test_no_control_id_missing_from_catalog(self):
        actual_ids = {c.control_id for c in FULL_CATALOG}
        expected_ids = set(EXPECTED_CATALOG.keys())
        missing = expected_ids - actual_ids
        self.assertEqual(missing, set(), f"Contrôle(s) attendu(s) par SPEC.md mais absent(s) du catalogue : {missing}")

    def test_no_unexpected_control_in_catalog(self):
        actual_ids = {c.control_id for c in FULL_CATALOG}
        expected_ids = set(EXPECTED_CATALOG.keys())
        extra = actual_ids - expected_ids
        self.assertEqual(extra, set(), f"Contrôle(s) présent(s) dans le catalogue mais absent(s) de SPEC.md : {extra}")

    def test_each_control_has_the_expected_domain_status_and_evidence_level(self):
        by_id = {c.control_id: c for c in FULL_CATALOG}
        mismatches = []
        for control_id, (expected_domain, expected_status, expected_level) in EXPECTED_CATALOG.items():
            actual = by_id.get(control_id)
            if actual is None:
                continue  # déjà signalé par test_no_control_id_missing_from_catalog
            if actual.domain != expected_domain:
                mismatches.append(f"{control_id}: domain={actual.domain} attendu {expected_domain}")
            if actual.scoring_status != expected_status:
                mismatches.append(f"{control_id}: scoring_status={actual.scoring_status} attendu {expected_status}")
            if actual.evidence_level != expected_level:
                mismatches.append(f"{control_id}: evidence_level={actual.evidence_level} attendu {expected_level}")
        self.assertEqual(mismatches, [], "\n".join(mismatches))


class TestCatalogInvariants(unittest.TestCase):
    def test_catalog_has_exactly_23_controls(self):
        """23, pas 20 ni 16 : historique documenté dans control_catalog.py —
        16 (coquille des premiers briefs) -> 20 (verrouillé après comparaison
        exacte SPEC.md/catalogue) -> 23 (ajout cookies + security.txt validé
        lors du red team GRC/UX, poids Security recalculé à 1/8)."""
        self.assertEqual(len(FULL_CATALOG), 23)

    def test_exactly_11_controls_are_included(self):
        included = [c for c in FULL_CATALOG if c.scoring_status == ScoringStatus.INCLUDED]
        self.assertEqual(len(included), 11)

    def test_exactly_12_controls_are_excluded(self):
        excluded = [c for c in FULL_CATALOG if c.scoring_status == ScoringStatus.EXCLUDED]
        self.assertEqual(len(excluded), 12)

    def test_all_included_controls_have_a_weight(self):
        for c in FULL_CATALOG:
            if c.scoring_status == ScoringStatus.INCLUDED:
                self.assertIsNotNone(c.weight, f"{c.control_id} INCLUDED sans poids")

    def test_no_excluded_control_has_a_weight(self):
        for c in FULL_CATALOG:
            if c.scoring_status == ScoringStatus.EXCLUDED:
                self.assertIsNone(c.weight, f"{c.control_id} EXCLUDED mais porte un poids")

    def test_security_weights_sum_to_one(self):
        security_included = [
            c for c in FULL_CATALOG
            if c.domain == Domain.SECURITY and c.scoring_status == ScoringStatus.INCLUDED
        ]
        self.assertEqual(len(security_included), 8)
        self.assertAlmostEqual(sum(c.weight for c in security_included), 1.0)
        # Uniformité explicitement vérifiée (mission complément — pas de
        # pondération différenciée, même après ajout des cookies).
        for c in security_included:
            self.assertAlmostEqual(c.weight, 1 / 8)

    def test_privacy_weights_sum_to_one(self):
        privacy_included = [
            c for c in FULL_CATALOG
            if c.domain == Domain.PRIVACY and c.scoring_status == ScoringStatus.INCLUDED
        ]
        self.assertEqual(len(privacy_included), 3)
        self.assertAlmostEqual(sum(c.weight for c in privacy_included), 1.0)

    def test_ai_governance_has_no_included_control(self):
        ai_included = [c for c in AI_GOVERNANCE if c.scoring_status == ScoringStatus.INCLUDED]
        self.assertEqual(len(ai_included), 0)

    def test_no_control_id_duplicated(self):
        ids = [c.control_id for c in FULL_CATALOG]
        self.assertEqual(len(ids), len(set(ids)))

    def test_sec_cms_detection_is_excluded(self):
        """Verrou explicite validé avec l'utilisateur : la détection de
        techno n'a pas de notion de favorable/défavorable."""
        cms = next(c for c in FULL_CATALOG if c.control_id == "sec.cms_detection")
        self.assertEqual(cms.scoring_status, ScoringStatus.EXCLUDED)
        self.assertIsNone(cms.weight)


if __name__ == "__main__":
    unittest.main()

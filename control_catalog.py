"""
WebSec Auditor V2 — Catalogue des contrôles
==============================================

Instanciation figée du catalogue validé dans SPEC.md §8.
Ce fichier est une DÉCLARATION DE DONNÉES, pas une implémentation de check.
Aucun module de contrôle ne doit dupliquer ces informations : il importe
la ControlDefinition correspondante depuis ce catalogue.

Modifier une pondération, un statut de scoring ou un niveau de preuve
se fait UNIQUEMENT ici — jamais dans scoring.py ni dans un module de check.

DÉCISION DE RÉFÉRENCE — vérifiée par comparaison exacte SPEC.md ↔ ce
fichier (ID par ID, domain, scoring_status, evidence_level ; voir
tests/test_catalog.py::TestCatalogMatchesSpecExactly et
scripts/verify_catalog_static.py) :

    Le catalogue fonctionnel contient 23 contrôles, dont 11 INCLUDED et
    12 EXCLUDED. SPEC.md constitue la source de vérité fonctionnelle.
    Historique : le catalogue est passé de 16 (chiffre obsolète des premiers
    briefs) à 20 (verrouillé après comparaison exacte SPEC.md ↔ catalogue),
    puis à 23 après l'ajout des contrôles cookies (Secure/HttpOnly/SameSite)
    et security.txt (RFC 9116), validés lors du red team GRC/UX (cf. compte
    rendu — poids Security recalculé à 1/8 par contrôle scoré, uniformité
    préservée, aucune pondération différenciée introduite).
"""

from models import (
    ControlDefinition,
    ControlPhrasing,
    Domain,
    EvidenceLevel,
    ScoringStatus,
)

# ---------------------------------------------------------------------------
# SECURITY POSTURE — scoré (8 contrôles, poids 1/8 chacun)
# ---------------------------------------------------------------------------

SECURITY_SCORED: list[ControlDefinition] = [
    ControlDefinition(
        control_id="sec.headers",
        domain=Domain.SECURITY,
        evidence_level=EvidenceLevel.A,
        scoring_status=ScoringStatus.INCLUDED,
        weight=1 / 8,
        report_label="En-têtes de sécurité HTTP",
        phrasing=ControlPhrasing(
            observed="{n}/6 en-têtes de sécurité critiques correctement configurés (score maximal).",
            partial="{n}/6 en-têtes de sécurité critiques correctement configurés.",
            absent="Aucun en-tête de sécurité critique correctement configuré.",
            not_testable="Contrôle non concluant : connexion impossible avant lecture des en-têtes.",
        ),
    ),
    ControlDefinition(
        control_id="sec.tls",
        domain=Domain.SECURITY,
        evidence_level=EvidenceLevel.A,
        scoring_status=ScoringStatus.INCLUDED,
        weight=1 / 8,
        report_label="Configuration TLS",
        phrasing=ControlPhrasing(
            observed="Certificat valide, protocole TLS1.3 disponible, aucune anomalie détectée.",
            partial="Anomalie TLS non critique détectée : {detail}.",
            absent="Anomalie TLS critique détectée : {detail}.",
            not_testable="Contrôle non concluant : échec de connexion/handshake TLS.",
        ),
    ),
    ControlDefinition(
        control_id="sec.exposed_files",
        domain=Domain.SECURITY,
        evidence_level=EvidenceLevel.A,
        scoring_status=ScoringStatus.INCLUDED,
        weight=1 / 8,
        report_label="Chemins sensibles testés",
        phrasing=ControlPhrasing(
            absent="Aucun chemin sensible testé n'est accessible.",
            observed="Chemin accessible détecté parmi les chemins sensibles testés : {path} — vérification recommandée.",
            not_testable="Contrôle non concluant : requêtes bloquées par la cible.",
        ),
    ),
    ControlDefinition(
        control_id="sec.secrets.pattern_detected",
        domain=Domain.SECURITY,
        evidence_level=EvidenceLevel.A,
        scoring_status=ScoringStatus.INCLUDED,
        weight=1 / 8,
        report_label="Motifs de secrets potentiels",
        phrasing=ControlPhrasing(
            absent="Aucun motif correspondant à un format de secret connu détecté.",
            observed="Motif correspondant à un format de secret potentiel détecté — vérification recommandée, non confirmé comme secret actif.",
            not_testable="Contrôle non concluant : contenu inaccessible.",
        ),
    ),
    ControlDefinition(
        control_id="sec.dns.dnssec",
        domain=Domain.SECURITY,
        evidence_level=EvidenceLevel.A,
        scoring_status=ScoringStatus.INCLUDED,
        weight=1 / 8,
        report_label="DNSSEC",
        phrasing=ControlPhrasing(
            observed="Enregistrements DNSSEC présents.",
            absent="DNSSEC non configuré.",
            not_testable="Contrôle non concluant : résolution DNS impossible.",
        ),
    ),
    ControlDefinition(
        control_id="sec.email_security",
        domain=Domain.SECURITY,
        evidence_level=EvidenceLevel.A,
        scoring_status=ScoringStatus.INCLUDED,
        weight=1 / 8,
        report_label="Sécurité e-mail (SPF/DMARC)",
        phrasing=ControlPhrasing(
            observed="SPF et DMARC configurés avec une politique stricte.",
            partial="Configuration partielle : {detail}.",
            absent="Aucun enregistrement SPF ni DMARC détecté.",
            not_applicable="Contrôle non applicable : aucun service e-mail détecté sur ce domaine.",
            not_testable="Contrôle non concluant : résolution DNS impossible ou délai dépassé.",
        ),
    ),
    ControlDefinition(
        control_id="sec.supply_chain.sri",
        domain=Domain.SECURITY,
        evidence_level=EvidenceLevel.A,
        scoring_status=ScoringStatus.INCLUDED,
        weight=1 / 8,
        report_label="Intégrité des ressources tierces (SRI)",
        phrasing=ControlPhrasing(
            observed="Attribut SRI présent sur {n}/{total} ressources externes.",
            partial="Attribut SRI présent sur {n}/{total} ressources externes.",
            absent="Aucune ressource externe testée ne porte d'attribut SRI.",
            not_applicable="Contrôle non applicable : aucune ressource externe déclarée statiquement dans le HTML (les ressources chargées via JavaScript ne sont pas visibles).",
            not_testable="Contrôle non concluant : page d'accueil inaccessible pour analyse.",
        ),
    ),
    ControlDefinition(
        control_id="sec.cookies.secure_httponly",
        domain=Domain.SECURITY,
        evidence_level=EvidenceLevel.A,
        scoring_status=ScoringStatus.INCLUDED,
        weight=1 / 8,
        report_label="Attributs de sécurité des cookies (Secure/HttpOnly)",
        phrasing=ControlPhrasing(
            observed="Attributs Secure et HttpOnly présents sur {n}/{total} cookies posés.",
            partial="Attributs Secure et HttpOnly présents sur {n}/{total} cookies posés.",
            absent="Aucun des cookies posés ne porte les attributs Secure et HttpOnly.",
            not_applicable="Contrôle non applicable : aucun cookie posé par la page d'accueil.",
            not_testable="Contrôle non concluant : page d'accueil inaccessible pour analyse.",
        ),
    ),
]

# ---------------------------------------------------------------------------
# SECURITY POSTURE — informatif (jamais scoré)
# ---------------------------------------------------------------------------

SECURITY_INFORMATIVE: list[ControlDefinition] = [
    ControlDefinition(
        control_id="sec.cookies.samesite_distribution",
        domain=Domain.SECURITY,
        evidence_level=EvidenceLevel.B,
        scoring_status=ScoringStatus.EXCLUDED,
        weight=None,
        report_label="Répartition SameSite des cookies",
        phrasing=ControlPhrasing(
            observed="Répartition SameSite observée sur {n} cookie(s) : {detail}.",
            not_applicable="Contrôle non applicable : aucun cookie posé par la page d'accueil.",
        ),
    ),
    ControlDefinition(
        control_id="sec.security_txt.presence",
        domain=Domain.SECURITY,
        evidence_level=EvidenceLevel.A,
        scoring_status=ScoringStatus.EXCLUDED,
        weight=None,
        report_label="Fichier security.txt (RFC 9116)",
        phrasing=ControlPhrasing(
            observed="Fichier security.txt détecté à {path}.",
            absent="Aucun fichier security.txt détecté.",
            not_testable="Contrôle non concluant : requête non exécutée (délai global de l'audit dépassé).",
        ),
    ),
    ControlDefinition(
        control_id="sec.cms_detection",
        domain=Domain.SECURITY,
        evidence_level=EvidenceLevel.A,
        scoring_status=ScoringStatus.EXCLUDED,
        weight=None,
        report_label="Technologie/CMS détectée",
        phrasing=ControlPhrasing(
            observed="Technologie identifiée : {name} — aucune conclusion sur la sécurité associée.",
            not_testable="Technologie non identifiable de manière fiable.",
        ),
    ),
    ControlDefinition(
        control_id="sec.cms_cve_mapping",
        domain=Domain.SECURITY,
        evidence_level=EvidenceLevel.B,
        scoring_status=ScoringStatus.EXCLUDED,
        weight=None,
        report_label="CVE potentiellement associée(s)",
        phrasing=ControlPhrasing(
            observed="CVE potentiellement applicable à la version détectée — non confirmée, vérification manuelle requise.",
            not_testable="Version non déterminée avec suffisamment de fiabilité pour un rattachement CVE.",
        ),
    ),
    ControlDefinition(
        control_id="sec.secrets.corroborated_signal",
        domain=Domain.SECURITY,
        evidence_level=EvidenceLevel.B,
        scoring_status=ScoringStatus.EXCLUDED,
        weight=None,
        report_label="Signal renforcé sur un secret potentiel",
        phrasing=ControlPhrasing(
            observed="Indices supplémentaires renforçant la probabilité d'un secret actif — analyse humaine recommandée, aucune confirmation possible en passif.",
        ),
    ),
    ControlDefinition(
        control_id="sec.supply_chain.outdated_library",
        domain=Domain.SECURITY,
        evidence_level=EvidenceLevel.B,
        scoring_status=ScoringStatus.EXCLUDED,
        weight=None,
        report_label="Bibliothèque potentiellement obsolète",
        phrasing=ControlPhrasing(
            observed="Version de bibliothèque ancienne détectée — l'ancienneté ne constitue pas à elle seule une preuve de vulnérabilité exploitable.",
        ),
    ),
]

# ---------------------------------------------------------------------------
# PRIVACY TECHNICAL SIGNALS — scoré (3 contrôles, poids 1/3 chacun) / informatif
# ---------------------------------------------------------------------------

PRIVACY_SCORED: list[ControlDefinition] = [
    ControlDefinition(
        control_id="priv.legal_pages.privacy_policy",
        domain=Domain.PRIVACY,
        evidence_level=EvidenceLevel.A,
        scoring_status=ScoringStatus.INCLUDED,
        weight=1 / 3,
        report_label="Politique de confidentialité",
        phrasing=ControlPhrasing(
            observed="Page de politique de confidentialité détectée.",
            absent="Aucune page de politique de confidentialité détectée.",
            not_testable="Non déterminable : contenu potentiellement généré côté client.",
        ),
    ),
    ControlDefinition(
        control_id="priv.legal_pages.legal_notice",
        domain=Domain.PRIVACY,
        evidence_level=EvidenceLevel.A,
        scoring_status=ScoringStatus.INCLUDED,
        weight=1 / 3,
        report_label="Mentions légales",
        phrasing=ControlPhrasing(
            observed="Mentions légales détectées.",
            absent="Aucune mention légale détectée.",
            not_testable="Non déterminable : contenu potentiellement généré côté client.",
        ),
    ),
    ControlDefinition(
        control_id="priv.cmp.presence",
        domain=Domain.PRIVACY,
        evidence_level=EvidenceLevel.A,
        scoring_status=ScoringStatus.INCLUDED,
        weight=1 / 3,
        report_label="Plateforme de gestion du consentement (CMP)",
        phrasing=ControlPhrasing(
            observed="CMP reconnue détectée : {name}.",
            absent="Aucune CMP reconnue détectée.",
            not_testable="Non déterminable : chargement dynamique non couvert par la liste de détection.",
        ),
    ),
]

PRIVACY_INFORMATIVE: list[ControlDefinition] = [
    ControlDefinition(
        control_id="priv.trackers.third_party_detected",
        domain=Domain.PRIVACY,
        evidence_level=EvidenceLevel.B,
        scoring_status=ScoringStatus.EXCLUDED,
        weight=None,
        report_label="Trackers tiers détectés",
        phrasing=ControlPhrasing(
            absent="Aucun tracker tiers identifié avant interaction.",
            observed="{n} trackers tiers détectés : {categories}.",
        ),
    ),
]

# ---------------------------------------------------------------------------
# AI & GOVERNANCE SIGNALS — tous informatifs, tous EXCLUDED
# ---------------------------------------------------------------------------

AI_GOVERNANCE: list[ControlDefinition] = [
    ControlDefinition(
        control_id="ai.llms_txt.presence",
        domain=Domain.AI_GOVERNANCE,
        evidence_level=EvidenceLevel.A,
        scoring_status=ScoringStatus.EXCLUDED,
        weight=None,
        report_label="Fichier llms.txt",
        phrasing=ControlPhrasing(
            observed="Fichier llms.txt détecté.",
            absent="Aucun fichier llms.txt détecté.",
            not_testable="Contrôle non concluant : requête non exécutée (délai global de l'audit dépassé).",
        ),
    ),
    ControlDefinition(
        control_id="ai.robots_bot_directives",
        domain=Domain.AI_GOVERNANCE,
        evidence_level=EvidenceLevel.A,
        scoring_status=ScoringStatus.EXCLUDED,
        weight=None,
        report_label="Directives bots IA (robots.txt)",
        phrasing=ControlPhrasing(
            observed="Directives spécifiques aux bots IA présentes dans robots.txt.",
            absent="Aucune directive spécifique aux bots IA détectée.",
            not_testable="Contrôle non concluant : requête non exécutée (délai global de l'audit dépassé).",
        ),
    ),
    ControlDefinition(
        control_id="ai.chatbot_detected",
        domain=Domain.AI_GOVERNANCE,
        evidence_level=EvidenceLevel.B,
        scoring_status=ScoringStatus.EXCLUDED,
        weight=None,
        report_label="Interface conversationnelle détectée",
        phrasing=ControlPhrasing(
            observed="Interface de type chatbot/assistant détectée.",
            absent="Aucune interface conversationnelle détectée.",
            not_testable="Interface potentiellement chargée dynamiquement — détection incertaine.",
        ),
    ),
    ControlDefinition(
        control_id="ai.public_ai_usage_mention",
        domain=Domain.AI_GOVERNANCE,
        evidence_level=EvidenceLevel.B,
        scoring_status=ScoringStatus.EXCLUDED,
        weight=None,
        report_label="Mention publique d'usage de l'IA",
        phrasing=ControlPhrasing(
            observed="Mention publique relative à l'usage de systèmes d'IA détectée.",
            absent="Aucune mention publique détectée — l'absence ne permet pas de conclure à l'absence d'usage de l'IA.",
        ),
    ),
    ControlDefinition(
        control_id="ai.governance_documentation_public",
        domain=Domain.AI_GOVERNANCE,
        evidence_level=EvidenceLevel.C,
        scoring_status=ScoringStatus.EXCLUDED,
        weight=None,
        report_label="Documentation de gouvernance IA publique",
        phrasing=ControlPhrasing(
            observed="Document(s) identifié(s) : {documents} — à examiner par un consultant.",
            absent="Aucun document de gouvernance IA publique identifié.",
            not_testable="Analyse de la qualité du document hors périmètre de l'outil.",
        ),
    ),
]

# ---------------------------------------------------------------------------
# Catalogue complet — point d'import unique pour scoring.py et les checks
# ---------------------------------------------------------------------------

FULL_CATALOG: list[ControlDefinition] = (
    SECURITY_SCORED
    + SECURITY_INFORMATIVE
    + PRIVACY_SCORED
    + PRIVACY_INFORMATIVE
    + AI_GOVERNANCE
)

CATALOG_BY_ID: dict[str, ControlDefinition] = {c.control_id: c for c in FULL_CATALOG}

# Garde-fou de cohérence, à exécuter en CI (pas à l'exécution d'un audit) :
# la somme des poids INCLUDED de chaque axe doit valoir 1.0 (tolérance flottante).
def _assert_weights_sum_to_one() -> None:
    for domain in (Domain.SECURITY, Domain.PRIVACY):
        included = [
            c for c in FULL_CATALOG
            if c.domain == domain and c.scoring_status == ScoringStatus.INCLUDED
        ]
        total = sum(c.weight for c in included)
        assert abs(total - 1.0) < 1e-9, f"{domain}: somme des poids = {total}, attendu 1.0"
    ai_included = [
        c for c in FULL_CATALOG
        if c.domain == Domain.AI_GOVERNANCE and c.scoring_status == ScoringStatus.INCLUDED
    ]
    assert not ai_included, "AI_GOVERNANCE ne doit contenir aucun contrôle INCLUDED."


if __name__ == "__main__":
    _assert_weights_sum_to_one()
    print(f"Catalogue valide : {len(FULL_CATALOG)} contrôles, "
          f"{sum(1 for c in FULL_CATALOG if c.scoring_status == ScoringStatus.INCLUDED)} scorés.")

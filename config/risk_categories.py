"""config/risk_categories.py — Étiquettes catégorielles de domaine de
risque pour les Key Findings (cadrage red team GRC/UX).

Principe verrouillé : une CATÉGORIE reconnue (type CIS Controls/ISO 27001
Annexe A), jamais un score de risque, jamais une matrice Vraisemblance ×
Impact, jamais un niveau Critique/Élevé/Moyen/Faible assigné sans base
empirique. Rattacher un constat à une famille de risque connue est un
exercice de classification, pas une prétention de calcul de risque réel.

Uniquement pour les contrôles scorés dont le rattachement est direct et
non ambigu — un contrôle absent de ce dict n'apparaît simplement pas avec
une catégorie dans les Key Findings (pas de valeur par défaut inventée).
"""

RISK_CATEGORY_BY_CONTROL_ID: dict[str, str] = {
    "sec.headers": "Exposition via configuration HTTP",
    "sec.tls": "Confidentialité des échanges en transit",
    "sec.exposed_files": "Exposition de fichiers ou informations sensibles",
    "sec.secrets.pattern_detected": "Exposition d'identifiants",
    "sec.dns.dnssec": "Intégrité de la résolution DNS",
    "sec.email_security": "Usurpation d'identité / hameçonnage par e-mail",
    "sec.supply_chain.sri": "Intégrité de la chaîne d'approvisionnement (scripts tiers)",
    "sec.cookies.secure_httponly": "Détournement de session",
    "priv.legal_pages.privacy_policy": "Transparence envers les personnes concernées",
    "priv.legal_pages.legal_notice": "Transparence envers les personnes concernées",
    "priv.cmp.presence": "Gestion du consentement",
}

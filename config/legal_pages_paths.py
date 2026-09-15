"""Chemins, mots-clés d'URL et marqueurs de texte pour priv.legal_pages.*
(mission complément — collectors/checks séparés, mais listes centralisées
ici pour éviter toute dispersion, cf. décision déjà appliquée pour CMP).

Trois listes distinctes par contrôle, avec un rôle précis :
- *_PATHS : chemins complets à sonder directement par requête HTTP séparée
  (mécanisme secondaire, vulnérable au blocage WAF sur un chemin précis —
  voir compte rendu du faux négatif corrigé).
- *_HREF_KEYWORDS : sous-chaînes de chemin recherchées dans le HREF de
  chaque lien réellement extrait de la page (collectors/html_parse.py) —
  mécanisme PRIMAIRE, sans coût réseau, insensible au blocage par chemin.
- *_LINK_TEXT_MARKERS : texte visible d'un lien, pour le cas où l'URL est
  atypique mais le texte du lien reste explicite (mission : "lien dont le
  texte indique 'Mentions légales' mais dont l'URL est atypique").

Toutes les comparaisons sont normalisées (accents/casse/tiret-underscore)
par collectors/html_parse.py — inutile de dupliquer les variantes
accentuées/non-accentuées ici, une seule graphie suffit par variante.
"""

PRIVACY_POLICY_PATHS: tuple[str, ...] = (
    "/politique-de-confidentialite",
    "/confidentialite",
    "/donnees-personnelles",
    "/privacy-policy",
    "/privacy",
)

LEGAL_NOTICE_PATHS: tuple[str, ...] = (
    "/mentions-legales",
    "/legal-notice",
    "/legal",
    "/imprint",
)

# Mots-clés recherchés dans le CHEMIN d'un lien réellement extrait de la
# page (href), pas dans une liste de chemins à deviner à l'aveugle.
PRIVACY_POLICY_HREF_KEYWORDS: tuple[str, ...] = (
    "politique-de-confidentialite",
    "confidentialite",
    "donnees-personnelles",
    "protection-des-donnees",
    "privacy-policy",
    "privacy",
)

LEGAL_NOTICE_HREF_KEYWORDS: tuple[str, ...] = (
    "mentions-legales",
    "informations-legales",
    "legal-notice",
    "legal",
    "imprint",
)

# Texte visible d'un lien (span/texte brut à l'intérieur de <a>...</a>),
# pour le cas où l'URL ne contient aucun mot-clé reconnaissable.
PRIVACY_POLICY_LINK_TEXT_MARKERS: tuple[str, ...] = (
    "politique de confidentialité",
    "politique de protection des données",
    "confidentialité",
    "données personnelles",
    "protection des données",
    "privacy policy",
    "privacy notice",
)

LEGAL_NOTICE_LINK_TEXT_MARKERS: tuple[str, ...] = (
    "mentions légales",
    "informations légales",
    "legal notice",
    "imprint",
    "terms of service",
    "cgu",
)

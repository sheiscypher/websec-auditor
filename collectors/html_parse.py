"""
collectors/html_parse.py — Extraction de liens réels (href + texte visible)
depuis une page déjà récupérée. Aucune requête réseau ici.

CAUSE RACINE CORRIGÉE PAR CE MODULE (cf. compte rendu) : la détection des
pages légales et de la CMP s'appuyait jusqu'ici sur deux mécanismes
fragiles :
  1. une liste fixe de chemins à sonder par requête HTTP séparée
     (vulnérable au blocage WAF sur un chemin précis) ;
  2. une recherche de sous-chaîne AVEUGLE sur tout le HTML brut (le
     commentaire affirmait à tort "à proximité d'une balise <a>", ce
     n'était pas le cas — n'importe quelle occurrence du texte n'importe
     où sur la page comptait, y compris hors d'un lien, et aucune
     normalisation des accents n'était appliquée).

Ce module introduit un VRAI mécanisme d'extraction de liens (href + texte
visible de chaque balise <a>), utilisable sur le HTML déjà en mémoire —
donc sans coût réseau supplémentaire et insensible au blocage WAF d'un
chemin précis (contrairement au sondage direct).

Analyse par expressions régulières, pas de dépendance BeautifulSoup —
cohérent avec la décision de simplicité déjà actée pour
collectors/http.py::fetch_external_resources.
"""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import urlparse

_ANCHOR_PATTERN = re.compile(r"<a\b([^>]*)>(.*?)</a>", re.IGNORECASE | re.DOTALL)
_HREF_PATTERN = re.compile(r'href\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
_TAG_STRIP_PATTERN = re.compile(r"<[^>]+>")


def normalize_text(text: str) -> str:
    """Minuscule + suppression des accents (NFKD), pour un matching robuste
    aux variantes orthographiques ("légales" doit matcher "legales").
    Stdlib uniquement (unicodedata), aucune dépendance."""
    decomposed = unicodedata.normalize("NFKD", text)
    without_accents = "".join(c for c in decomposed if not unicodedata.combining(c))
    return without_accents.lower()


def extract_anchor_links(html: str) -> list[tuple[str, str]]:
    """Retourne une liste de (href, texte_visible) pour chaque balise <a>
    trouvée dans le HTML. Le texte visible a ses sous-balises retirées
    (ex: <a href="..."><span>Mentions légales</span></a> -> texte =
    "Mentions légales"). href peut être relatif, absolu, vide, ou une
    ancre (#) — la normalisation/le filtrage sont laissés à l'appelant."""
    links: list[tuple[str, str]] = []
    for match in _ANCHOR_PATTERN.finditer(html):
        attrs, inner_html = match.group(1), match.group(2)
        href_match = _HREF_PATTERN.search(attrs)
        href = href_match.group(1).strip() if href_match else ""
        visible_text = _TAG_STRIP_PATTERN.sub(" ", inner_html)
        visible_text = " ".join(visible_text.split())  # normalise les espaces
        links.append((href, visible_text))
    return links


def href_path_matches(href: str, keywords: tuple[str, ...]) -> bool:
    """Compare le CHEMIN d'un href (sans domaine/query/fragment) à une
    liste de mots-clés — insensible à la casse, aux accents, et à la
    distinction tiret/underscore. Fonctionne aussi bien sur un lien
    relatif ("/mentions-legales") qu'absolu
    ("https://exemple.fr/mentions-legales?ref=footer")."""
    if not href or href.startswith("#") or href.lower().startswith(("mailto:", "tel:", "javascript:")):
        return False

    if "://" in href or href.startswith("//"):
        path = urlparse(href if "://" in href else f"https:{href}").path
    else:
        path = href.split("?")[0].split("#")[0]

    normalized_path = normalize_text(path).replace("_", "-")
    return any(normalize_text(kw).replace("_", "-") in normalized_path for kw in keywords)


def link_text_matches(text: str, markers: tuple[str, ...]) -> bool:
    """Compare le texte visible d'un lien à une liste de marqueurs —
    insensible à la casse et aux accents."""
    if not text:
        return False
    normalized = normalize_text(text)
    return any(normalize_text(marker) in normalized for marker in markers)

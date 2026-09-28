"""
security/sanitize.py — Assainissement des valeurs issues de la CIBLE.

Toute valeur lue chez le site audité (enregistrement DNS, en-tête HTTP,
contenu HTML) est contrôlée par son propriétaire. Elle ne doit jamais
atteindre un rapport, un log ou une interface telle quelle : un audit ne doit
pas devenir un vecteur d'injection contre celui qui le lance.

Ce module regroupe les listes blanches et les nettoyages utilisés aux
frontières de collecte. Il est volontairement PUR (bibliothèque standard
uniquement) pour rester testable isolément.

Défense en profondeur : le frontend échappe AUSSI tout ce qu'il affiche
(api/static/index.html, fonction esc()). Ces deux couches sont indépendantes :
l'une ne dispense pas de l'autre.
"""

from __future__ import annotations

from typing import Optional
from urllib.parse import urlsplit

# --- DMARC : RFC 7489, valeurs valides du tag p= ---------------------------
DMARC_POLICIES = frozenset({"none", "quarantine", "reject"})
DMARC_POLICY_UNRECOGNIZED = "non reconnue"

# --- Cookies : valeurs valides de l'attribut SameSite -----------------------
SAMESITE_VALUES = frozenset({"strict", "lax", "none"})
SAMESITE_UNRECOGNIZED = "valeur non reconnue"

# Caractères conservés dans un nom de technologie (ex. « WordPress 6.4.2 »,
# « Joomla! - Open Source Content Management », « Drupal 10 (https://…) »).
# Tout le reste est retiré, notamment < > " ' & ` = ; { } et les caractères
# de contrôle ou bidirectionnels.
_TECH_NAME_EXTRA = " ._+-!()/:,"


def normalize_dmarc_policy(raw: Optional[str]) -> Optional[str]:
    """Liste blanche : « none », « quarantine » ou « reject ». Toute autre
    valeur devient « non reconnue » (jamais la chaîne brute). Le résultat
    du contrôle ne change pas : une politique inconnue n'est pas stricte,
    comme avant."""
    if raw is None:
        return None
    value = raw.strip().lower()
    return value if value in DMARC_POLICIES else DMARC_POLICY_UNRECOGNIZED


def normalize_samesite(raw: Optional[str]) -> Optional[str]:
    """Liste blanche : Strict, Lax ou None (casse d'origine conservée, pour
    ne pas modifier la répartition informative). Toute autre valeur devient
    « valeur non reconnue »."""
    if raw is None:
        return None
    value = raw.strip()
    return value if value.lower() in SAMESITE_VALUES else SAMESITE_UNRECOGNIZED


def sanitize_technology_name(raw: Optional[str], max_len: int = 60) -> Optional[str]:
    """Nettoie un nom ou une version de technologie lu dans le HTML de la
    cible. Retire tout caractère hors lettres, chiffres et ponctuation
    inoffensive, replie les espaces, tronque. Retourne None si rien
    d'exploitable ne subsiste."""
    if raw is None:
        return None
    kept = "".join(c for c in raw if c.isalnum() or c in _TECH_NAME_EXTRA)
    kept = " ".join(kept.split())[:max_len].strip()
    return kept or None


def safe_for_log(value: object, max_len: int = 200) -> str:
    """Rend une valeur non fiable inoffensive pour un journal : les
    caractères non imprimables (dont les sauts de ligne, qui permettent de
    falsifier une entrée de log) deviennent « ? », et la longueur est bornée."""
    text = "".join(c if c.isprintable() else "?" for c in str(value))
    return text[:max_len] + ("…" if len(text) > max_len else "")


def redact_url_for_log(url: object, max_len: int = 200) -> str:
    """URL cible prête pour un journal : identifiants (user:pass@), requête
    et fragment retirés, caractères de contrôle neutralisés, longueur bornée."""
    text = str(url)
    try:
        parts = urlsplit(text)
        host = parts.hostname or ""
        if parts.scheme and host:
            if ":" in host:  # IPv6 : urlsplit retire les crochets
                host = f"[{host}]"
            port = f":{parts.port}" if parts.port else ""
            text = f"{parts.scheme}://{host}{port}{parts.path}"
    except ValueError:
        # URL malformée : on ne journalise rien de la chaîne d'origine
        # (elle pourrait contenir des identifiants).
        text = "<url invalide>"
    return safe_for_log(text, max_len)

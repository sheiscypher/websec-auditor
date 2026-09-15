"""checks/cookies.py — sec.cookies.secure_httponly (scoré) et
sec.cookies.samesite_distribution (informatif, EXCLUDED).

Décision verrouillée (cadrage red team GRC/UX) :
- Secure + HttpOnly : binaires, sans ambiguïté de lecture -> scorables,
  sur le modèle exact de sec.supply_chain.sri (proportion conforme).
- SameSite : sa valeur "None" est légitime dans de nombreux contextes
  (intégrations cross-site autorisées, avec Secure) -> jamais scoré,
  seulement une répartition observée, informative.

Aucun des deux ne permet de conclure à une vulnérabilité de détournement
de session réelle — seulement à une pratique de configuration observée.
"""

from __future__ import annotations

from dataclasses import dataclass

from enums import ControlResult
from results import CheckOutcome

CONTROL_ID_SECURE_HTTPONLY = "sec.cookies.secure_httponly"
CONTROL_ID_SAMESITE = "sec.cookies.samesite_distribution"


@dataclass(frozen=True)
class ParsedCookie:
    name: str
    secure: bool
    httponly: bool
    samesite: str | None  # "Strict" | "Lax" | "None" | None si absent


def parse_set_cookie_headers(set_cookie_headers: tuple[str, ...]) -> list[ParsedCookie]:
    """Analyse déterministe des attributs d'un en-tête Set-Cookie. Ne
    dépend d'aucune bibliothèque tierce — attributs recherchés par
    correspondance insensible à la casse, seule la présence des jetons
    compte (pas de tentative d'interpréter une valeur ambiguë)."""
    cookies = []
    for header in set_cookie_headers:
        parts = [p.strip() for p in header.split(";")]
        if not parts:
            continue
        name = parts[0].split("=", 1)[0].strip()
        secure = False
        httponly = False
        samesite = None
        for attr in parts[1:]:
            lowered = attr.lower()
            if lowered == "secure":
                secure = True
            elif lowered == "httponly":
                httponly = True
            elif lowered.startswith("samesite"):
                if "=" in attr:
                    samesite = attr.split("=", 1)[1].strip()
                else:
                    samesite = None
        cookies.append(ParsedCookie(name=name, secure=secure, httponly=httponly, samesite=samesite))
    return cookies


def evaluate_secure_httponly(
    set_cookie_headers: tuple[str, ...] | None,
) -> CheckOutcome:
    if set_cookie_headers is None:
        return CheckOutcome(
            control_id=CONTROL_ID_SECURE_HTTPONLY,
            result=ControlResult.NOT_TESTABLE,
            evidence="Page d'accueil inaccessible pour analyse.",
            detection_method="Analyse des attributs des en-têtes Set-Cookie de la réponse HTTP.",
            phrasing_context={},
        )

    cookies = parse_set_cookie_headers(set_cookie_headers)
    if not cookies:
        return CheckOutcome(
            control_id=CONTROL_ID_SECURE_HTTPONLY,
            result=ControlResult.NOT_APPLICABLE,
            evidence="Aucun cookie posé par la page d'accueil.",
            detection_method="Analyse des attributs des en-têtes Set-Cookie de la réponse HTTP.",
            phrasing_context={},
        )

    compliant = [c for c in cookies if c.secure and c.httponly]
    total = len(cookies)
    proportion = (len(compliant) / total) * 100

    if len(compliant) == total:
        result = ControlResult.OBSERVED
    elif len(compliant) == 0:
        result = ControlResult.ABSENT
    else:
        result = ControlResult.PARTIAL

    return CheckOutcome(
        control_id=CONTROL_ID_SECURE_HTTPONLY,
        result=result,
        evidence=f"{len(compliant)}/{total} cookies portent Secure et HttpOnly.",
        detection_method="Analyse des attributs des en-têtes Set-Cookie de la réponse HTTP.",
        score_contribution=proportion,
        phrasing_context={"n": len(compliant), "total": total},
    )


def evaluate_samesite_distribution(
    set_cookie_headers: tuple[str, ...] | None,
) -> CheckOutcome | None:
    """Informatif, EXCLUDED. Retourne None si aucun cookie n'est posé (rien
    à décrire) — pas de finding NOT_APPLICABLE artificiel pour un contrôle
    déjà non scoré."""
    if not set_cookie_headers:
        return None

    cookies = parse_set_cookie_headers(set_cookie_headers)
    if not cookies:
        return None

    counts: dict[str, int] = {}
    for c in cookies:
        key = c.samesite or "non défini"
        counts[key] = counts.get(key, 0) + 1
    detail = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))

    return CheckOutcome(
        control_id=CONTROL_ID_SAMESITE,
        result=ControlResult.OBSERVED,
        evidence=f"Répartition sur {len(cookies)} cookie(s) : {detail}.",
        detection_method="Analyse de l'attribut SameSite des en-têtes Set-Cookie.",
        score_contribution=None,
        phrasing_context={"n": len(cookies), "detail": detail},
    )

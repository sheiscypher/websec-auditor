"""
checks/exposure.py — sec.exposed_files

Reformulation imposée (SPEC.md §8.7 / mission section 3) : ce check ne dit
jamais "fichier sensible exposé". Il constate un "chemin accessible parmi
les chemins sensibles testés". Le filtrage anti-faux-positif (content-type
+ mots-clés) réduit le bruit de détection, il n'est jamais présenté comme
une preuve de compromission.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from enums import ControlResult
from results import CheckOutcome

CONTROL_ID = "sec.exposed_files"

# Mots-clés attendus dans le contenu pour confirmer qu'une réponse 200 sur un
# chemin sensible n'est pas une page d'erreur générique custom.
CONFIRMATION_KEYWORDS_BY_PATH_HINT = {
    ".env": ("=",),
    ".git/config": ("[core]", "repositoryformatversion"),
    "wp-config.php": ("DB_NAME", "DB_PASSWORD"),
    "phpinfo.php": ("PHP Version", "phpinfo()"),
}


@dataclass(frozen=True)
class PathProbeResult:
    path: str
    http_status: Optional[int]  # None si la requête a été bloquée/a échoué
    content_type: Optional[str] = None
    body_snippet: str = ""


def _is_genuine_exposure(probe: PathProbeResult) -> bool:
    """Filtre anti-faux-positif : un 200 ne suffit pas si le contenu
    ressemble à une page HTML générique (page d'erreur custom)."""
    if probe.http_status != 200:
        return False
    if probe.content_type and "text/html" in probe.content_type.lower():
        # Une page HTML sur un chemin type .env est presque toujours une
        # page d'erreur custom du site, pas le fichier réel.
        return False

    for hint, keywords in CONFIRMATION_KEYWORDS_BY_PATH_HINT.items():
        if hint in probe.path:
            return any(kw in probe.body_snippet for kw in keywords)

    # Chemin non couvert par une règle de confirmation spécifique : un 200
    # non-HTML est retenu tel quel (ex: fichier de backup binaire).
    return True


def evaluate_exposed_files(probes: list[PathProbeResult]) -> CheckOutcome:
    if not probes:
        return CheckOutcome(
            control_id=CONTROL_ID,
            result=ControlResult.NOT_TESTABLE,
            evidence="Aucune requête n'a pu être exécutée.",
            detection_method="Requêtes GET/HEAD sur une liste de chemins sensibles connus.",
            phrasing_context={},
        )

    blocked = [p for p in probes if p.http_status is None]
    if len(blocked) == len(probes):
        return CheckOutcome(
            control_id=CONTROL_ID,
            result=ControlResult.NOT_TESTABLE,
            evidence="Toutes les requêtes ont été bloquées par la cible.",
            detection_method="Requêtes GET/HEAD sur une liste de chemins sensibles connus.",
            phrasing_context={},
        )

    genuine_hits = [p for p in probes if _is_genuine_exposure(p)]

    if genuine_hits:
        first = genuine_hits[0]
        return CheckOutcome(
            control_id=CONTROL_ID,
            result=ControlResult.OBSERVED,
            evidence=(
                f"{len(genuine_hits)} chemin(s) accessible(s) parmi les chemins testés : "
                f"{', '.join(p.path for p in genuine_hits)}."
            ),
            detection_method="Requêtes GET/HEAD + filtrage content-type/mots-clés (anti-faux-positif).",
            score_contribution=0.0,
            phrasing_context={"path": first.path},
        )

    return CheckOutcome(
        control_id=CONTROL_ID,
        result=ControlResult.ABSENT,
        evidence=f"Aucun chemin sensible accessible parmi les {len(probes)} chemins testés.",
        detection_method="Requêtes GET/HEAD + filtrage content-type/mots-clés (anti-faux-positif).",
        score_contribution=100.0,
        phrasing_context={},
    )

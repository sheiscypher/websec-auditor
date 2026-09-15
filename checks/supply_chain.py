"""checks/supply_chain.py — sec.supply_chain.sri (scoré) et
sec.supply_chain.outdated_library (informatif, EXCLUDED)."""

from __future__ import annotations

from dataclasses import dataclass

from enums import ControlResult
from results import CheckOutcome

CONTROL_ID_SRI = "sec.supply_chain.sri"
CONTROL_ID_OUTDATED = "sec.supply_chain.outdated_library"


@dataclass(frozen=True)
class ExternalResource:
    url: str
    has_sri: bool


@dataclass(frozen=True)
class DetectedLibrary:
    name: str
    version: str
    is_outdated: bool  # déterminé par comparaison à une liste de référence


def evaluate_sri(resources: list[ExternalResource] | None) -> CheckOutcome:
    if resources is None:
        return CheckOutcome(
            control_id=CONTROL_ID_SRI,
            result=ControlResult.NOT_TESTABLE,
            evidence="Analyse des ressources externes impossible.",
            detection_method="Analyse des balises <script>/<link> pointant vers des domaines tiers.",
            phrasing_context={},
        )

    if not resources:
        return CheckOutcome(
            control_id=CONTROL_ID_SRI,
            result=ControlResult.NOT_APPLICABLE,
            evidence=(
                "Aucune ressource externe déclarée statiquement dans le HTML analysé. "
                "Les ressources chargées dynamiquement via JavaScript (ex: gestionnaire "
                "de tags) ne sont pas visibles par une analyse passive sans exécution JS."
            ),
            detection_method="Analyse des balises <script>/<link> pointant vers des domaines tiers (HTML statique uniquement, sans exécution JavaScript).",
            phrasing_context={},
        )

    with_sri = [r for r in resources if r.has_sri]
    total = len(resources)
    proportion = (len(with_sri) / total) * 100

    if len(with_sri) == total:
        result = ControlResult.OBSERVED
    elif len(with_sri) == 0:
        result = ControlResult.ABSENT
    else:
        result = ControlResult.PARTIAL

    return CheckOutcome(
        control_id=CONTROL_ID_SRI,
        result=result,
        evidence=f"Attribut SRI présent sur {len(with_sri)}/{total} ressources externes.",
        detection_method="Analyse des balises <script>/<link> pointant vers des domaines tiers.",
        score_contribution=proportion,
        phrasing_context={"n": len(with_sri), "total": total},
    )


def evaluate_outdated_libraries(libraries: list[DetectedLibrary] | None) -> CheckOutcome | None:
    """Informatif, EXCLUDED. Retourne None si aucune bibliothèque obsolète
    n'est détectée — l'absence de détection ne prouve rien (liste de
    référence statique, cf. limitation)."""
    if not libraries:
        return None

    outdated = [lib for lib in libraries if lib.is_outdated]
    if not outdated:
        return None

    return CheckOutcome(
        control_id=CONTROL_ID_OUTDATED,
        result=ControlResult.OBSERVED,
        evidence=(
            f"{len(outdated)} bibliothèque(s) potentiellement obsolète(s) : "
            f"{', '.join(f'{lib.name} {lib.version}' for lib in outdated)}."
        ),
        detection_method="Comparaison des versions détectées à une liste de référence statique.",
        limitation="La liste de référence est statique et peut ne pas refléter les dernières versions publiées.",
        score_contribution=None,
        phrasing_context={},
    )

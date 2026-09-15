"""
checks/secrets.py — sec.secrets.pattern_detected (scoré) et
sec.secrets.corroborated_signal (informatif, EXCLUDED).

Séparation imposée (mission section 3 / SPEC.md §8.7) :
- pattern_detected = fait brut (un motif regex a matché) ;
- corroborated_signal = indices additionnels renforçant la probabilité
  d'un secret réellement actif — jamais une confirmation.

Aucun des deux niveaux ne permet d'affirmer "secret exposé"/"confirmé".
"""

from __future__ import annotations

from dataclasses import dataclass

from config.secret_patterns import (
    NON_PRODUCTION_PATH_MARKERS,
    PLACEHOLDER_MARKERS,
    SECRET_PATTERNS,
)
from enums import ControlResult
from results import CheckOutcome

CONTROL_ID_PATTERN = "sec.secrets.pattern_detected"
CONTROL_ID_CORROBORATED = "sec.secrets.corroborated_signal"


@dataclass(frozen=True)
class ScannedResource:
    path: str
    content: str


@dataclass(frozen=True)
class SecretMatch:
    pattern_name: str
    resource_path: str
    matched_text: str


def _scan_resource(resource: ScannedResource) -> list[SecretMatch]:
    matches = []
    for pattern in SECRET_PATTERNS:
        for m in pattern.regex.finditer(resource.content):
            matches.append(
                SecretMatch(
                    pattern_name=pattern.name,
                    resource_path=resource.path,
                    matched_text=m.group(0),
                )
            )
    return matches


def evaluate_secret_patterns(resources: list[ScannedResource] | None) -> CheckOutcome:
    if resources is None:
        return CheckOutcome(
            control_id=CONTROL_ID_PATTERN,
            result=ControlResult.NOT_TESTABLE,
            evidence="Contenu inaccessible pour analyse.",
            detection_method="Analyse par expressions régulières du contenu HTML/JS accessible.",
            phrasing_context={},
        )

    all_matches: list[SecretMatch] = []
    for resource in resources:
        all_matches.extend(_scan_resource(resource))

    if not all_matches:
        return CheckOutcome(
            control_id=CONTROL_ID_PATTERN,
            result=ControlResult.ABSENT,
            evidence=f"Aucun motif détecté sur {len(resources)} ressource(s) analysée(s).",
            detection_method="Analyse par expressions régulières du contenu HTML/JS accessible.",
            score_contribution=100.0,
            phrasing_context={},
        )

    return CheckOutcome(
        control_id=CONTROL_ID_PATTERN,
        result=ControlResult.OBSERVED,
        evidence=(
            f"{len(all_matches)} motif(s) détecté(s) : "
            f"{', '.join(sorted({m.pattern_name for m in all_matches}))}."
        ),
        detection_method="Analyse par expressions régulières du contenu HTML/JS accessible.",
        score_contribution=0.0,
        phrasing_context={},
    )


def _is_corroborated(match: SecretMatch) -> bool:
    lowered_path = match.resource_path.lower()
    lowered_text = match.matched_text.lower()

    if any(marker in lowered_path for marker in NON_PRODUCTION_PATH_MARKERS):
        return False
    if any(marker in lowered_text for marker in PLACEHOLDER_MARKERS):
        return False
    return True


def evaluate_corroborated_signal(resources: list[ScannedResource] | None) -> CheckOutcome | None:
    """Informatif, EXCLUDED du score. Retourne None si aucun motif n'a été
    détecté (rien à corroborer) — pas de finding "ABSENT" artificiel."""
    if resources is None:
        return None

    all_matches: list[SecretMatch] = []
    for resource in resources:
        all_matches.extend(_scan_resource(resource))

    if not all_matches:
        return None

    corroborated = [m for m in all_matches if _is_corroborated(m)]
    if not corroborated:
        return None

    return CheckOutcome(
        control_id=CONTROL_ID_CORROBORATED,
        result=ControlResult.OBSERVED,
        evidence=(
            f"{len(corroborated)} motif(s) hors contexte de test/exemple, "
            f"sans marqueur de placeholder."
        ),
        detection_method="Filtrage contextuel (chemin, marqueurs de placeholder) sur les motifs détectés.",
        score_contribution=None,  # informatif, jamais utilisé par le scoring
        phrasing_context={},
    )

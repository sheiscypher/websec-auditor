"""
WebSec Auditor V1 — Contrat de sortie d'un check
====================================================

Un check (checks/*.py) ne construit jamais directement un `Finding` Pydantic.
Il retourne un `CheckOutcome` : une structure stdlib (dataclass), sans
dépendance à Pydantic, ce qui la rend testable sans installer Pydantic.

`CheckOutcome` porte volontairement `score_contribution` : la traduction
"ce résultat vaut X/100 pour CE contrôle précis" est une décision qui
appartient au check (il connaît la sémantique du contrôle), jamais au
moteur de scoring (scoring.py), qui ne doit rien savoir des headers, de
TLS, du DNS, etc. (SPEC.md §11 de la mission / §7.3 du SPEC).

`score_contribution` est `None` quand `result` est `NOT_APPLICABLE` ou
`NOT_TESTABLE` — il n'y a alors rien à convertir en score, et le moteur
retire ce contrôle du dénominateur pour CET audit (SPEC.md §7.1).

Un `build_finding()` fait le pont vers le `Finding` Pydantic défini dans
models.py, en résolvant le wording depuis `ControlPhrasing` — jamais de
texte libre rédigé dans un check.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from enums import ControlResult


@dataclass(frozen=True)
class CheckOutcome:
    """Sortie brute d'un check, avant mise en forme pour le rapport."""

    control_id: str
    result: ControlResult
    evidence: str
    detection_method: str

    # Renseigné uniquement si ce contrôle est INCLUDED dans le catalogue et
    # que `result` n'est ni NOT_APPLICABLE ni NOT_TESTABLE. Un check pour un
    # contrôle EXCLUDED peut le laisser à None sans conséquence : le moteur
    # de scoring ne le lira jamais pour ces contrôles-là.
    score_contribution: Optional[float] = None  # 0-100

    limitation: Optional[str] = None
    reference: Optional[str] = None

    # Valeurs utilisées pour interpoler le template de ControlPhrasing
    # (ex: {"n": 4} pour "{n}/6 en-têtes ..."). Jamais de texte déjà formaté
    # ici — la formulation finale est toujours résolue depuis le catalogue.
    phrasing_context: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.result in (ControlResult.NOT_APPLICABLE, ControlResult.NOT_TESTABLE):
            if self.score_contribution is not None:
                raise ValueError(
                    f"{self.control_id}: score_contribution doit être None "
                    f"quand result={self.result} (rien à scorer)."
                )
        if self.score_contribution is not None:
            if not (0.0 <= self.score_contribution <= 100.0):
                raise ValueError(
                    f"{self.control_id}: score_contribution hors bornes "
                    f"[0, 100] : {self.score_contribution}"
                )


def resolve_phrasing(phrasing, result: ControlResult, context: dict) -> str:
    """Sélectionne le template correspondant au résultat dans un
    ControlPhrasing (models.py) et l'interpole avec `context`.

    Ne fait AUCUNE interprétation : si le template attendu n'existe pas
    pour ce résultat, c'est une erreur de catalogue à corriger dans
    control_catalog.py, pas un cas à deviner ici.
    """
    template_by_result = {
        ControlResult.OBSERVED: phrasing.observed,
        ControlResult.ABSENT: phrasing.absent,
        ControlResult.PARTIAL: phrasing.partial,
        ControlResult.NOT_APPLICABLE: phrasing.not_applicable,
        ControlResult.NOT_TESTABLE: phrasing.not_testable,
    }
    template = template_by_result[result]
    if template is None:
        raise ValueError(
            f"Aucun wording défini dans le catalogue pour result={result}. "
            f"Corriger control_catalog.py plutôt que de deviner un texte ici."
        )
    return template.format(**context)


def build_finding(outcome: CheckOutcome, control_definition):
    """Construit un Finding Pydantic à partir d'un CheckOutcome et de la
    ControlDefinition correspondante. Import de models.py fait ici (pas en
    tête de fichier) pour que results.py + checks/* + scoring.py restent
    utilisables sans Pydantic installé, tant qu'on ne construit pas de
    Finding réel."""
    from models import Finding  # import local : voir docstring du module

    recommendation = None
    if outcome.result in (ControlResult.OBSERVED, ControlResult.ABSENT, ControlResult.PARTIAL):
        if control_definition.evidence_level.value in ("A", "B"):
            recommendation = outcome.phrasing_context.get("recommendation")
            # Rappel SPEC §9 : jamais de recommandation pour C/D — non
            # applicable ici car AI_GOVERNANCE (seul domaine avec du C)
            # n'a pas vocation à produire de recommandations correctives.

    resolved_label = resolve_phrasing(
        control_definition.phrasing, outcome.result, outcome.phrasing_context
    )

    return Finding(
        control_id=outcome.control_id,
        result=outcome.result,
        evidence=outcome.evidence,
        detection_method=outcome.detection_method,
        limitation=outcome.limitation,
        recommendation=recommendation,
        reference=outcome.reference,
        resolved_label=resolved_label,
    )

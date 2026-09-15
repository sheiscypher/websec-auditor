"""
scoring.py — Moteur de scoring centralisé.

Respecte strictement SPEC.md §7 et la mission section 11 :

- Ne connaît QUE : ControlDefinition (domain, scoring_status, weight),
  ControlResult, et le score_contribution fourni par chaque CheckOutcome.
- Ne connaît RIEN des headers HTTP, de TLS, du DNS, des CMP, des
  fonctionnalités sensibles, etc. Toute cette sémantique vit dans checks/*.py.
- Ne calcule JAMAIS de score à partir d'un contrôle EXCLUDED.
- Ne convertit JAMAIS NOT_TESTABLE/NOT_APPLICABLE en une valeur de score :
  ces contrôles sortent du dénominateur et leur poids est redistribué.
- Si aucun contrôle INCLUDED n'est évaluable sur un axe → NOT_COMPUTABLE.
- Aucun score global (`global_score`/`overall_score`) n'est produit ici —
  ScoreBreakdown lui-même l'interdit via son validateur (models.py).
"""

from __future__ import annotations

from enums import AxisStatus, ControlResult, Domain, PrivacySignalLevel, ScoringStatus
from results import CheckOutcome

EVALUABLE_RESULTS = (ControlResult.OBSERVED, ControlResult.ABSENT, ControlResult.PARTIAL)
NON_EVALUABLE_RESULTS = (ControlResult.NOT_APPLICABLE, ControlResult.NOT_TESTABLE)


class ScoringContractError(Exception):
    """Levée quand un CheckOutcome viole le contrat attendu par le moteur
    (ex : contrôle INCLUDED avec un résultat évaluable mais sans
    score_contribution). Ce n'est jamais une situation à corriger
    silencieusement dans scoring.py — l'erreur vient du check appelant."""


def _axis_included_controls(catalog, domain: Domain) -> list:
    return [
        c for c in catalog
        if c.domain == domain and c.scoring_status == ScoringStatus.INCLUDED
    ]


def compute_axis_score(catalog, domain: Domain, outcomes: dict[str, CheckOutcome]):
    """Calcule le score d'un axe (Security ou Privacy) à partir du
    catalogue et des CheckOutcome produits pour cet audit.

    `outcomes` : dict control_id -> CheckOutcome, pour TOUS les contrôles
    (scorés ou non) — le moteur filtre lui-même sur scoring_status.

    Retourne un tuple (status, score, contributing, excluded_this_run)
    prêt à être injecté dans AxisScore/SecurityPostureScore/PrivacySignalsScore
    (la construction du modèle Pydantic reste à la charge de l'appelant,
    scoring.py ne dépend pas de Pydantic).
    """
    included = _axis_included_controls(catalog, domain)

    evaluable: list[tuple] = []  # (control, outcome)
    excluded_this_run: list[str] = []

    for control in included:
        outcome = outcomes.get(control.control_id)
        if outcome is None:
            raise ScoringContractError(
                f"Aucun CheckOutcome fourni pour le contrôle INCLUDED "
                f"'{control.control_id}'."
            )

        if outcome.result in NON_EVALUABLE_RESULTS:
            excluded_this_run.append(control.control_id)
            continue

        if outcome.result not in EVALUABLE_RESULTS:
            raise ScoringContractError(
                f"Résultat inattendu '{outcome.result}' pour '{control.control_id}'."
            )

        if outcome.score_contribution is None:
            raise ScoringContractError(
                f"Le contrôle INCLUDED '{control.control_id}' a un résultat "
                f"évaluable ({outcome.result}) mais aucun score_contribution. "
                f"C'est une erreur du check, pas du moteur de scoring."
            )

        evaluable.append((control, outcome))

    if not evaluable:
        return AxisStatus.NOT_COMPUTABLE, None, [], excluded_this_run

    # Poids lus EXCLUSIVEMENT depuis le catalogue (control.weight), jamais
    # réinventés ici. Redistribution proportionnelle (SPEC.md §7.1) entre les
    # seuls contrôles évaluables sur CET audit : si tous les poids déclarés
    # sont égaux (équipondération actuelle), ceci équivaut mathématiquement
    # à 1/len(evaluable) — mais la formule reste correcte si le catalogue
    # évolue un jour vers des poids différenciés (V2.1+, cf. SPEC.md §7.2).
    total_declared_weight = sum(control.weight for control, _ in evaluable)

    contributing = []
    score = 0.0
    for control, outcome in evaluable:
        weight_applied = control.weight / total_declared_weight
        score += outcome.score_contribution * weight_applied
        contributing.append(
            {
                "control_id": control.control_id,
                "result": outcome.result,
                "weight_applied": weight_applied,
            }
        )

    return AxisStatus.COMPUTED, score, contributing, excluded_this_run


def grade_from_score(score: float) -> str:
    """Grade A-F, réservé à Security Posture (SPEC.md §7.4). Jamais
    utilisé pour Privacy."""
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def signal_level_from_score(score: float) -> PrivacySignalLevel:
    """Échelle qualitative réservée à Privacy Technical Signals — jamais
    de lettre A-F pour cet axe (SPEC.md §7.4)."""
    if score >= 75:
        return PrivacySignalLevel.EXTENSIVE
    if score >= 40:
        return PrivacySignalLevel.PARTIAL
    return PrivacySignalLevel.LIMITED


def compute_ai_governance_panel(catalog, outcomes: dict[str, CheckOutcome]):
    """Panneau non scoré. Retourne uniquement un décompte — jamais un score
    ni un grade, quelle que soit l'évolution future du catalogue tant que
    ces contrôles restent EXCLUDED (SPEC.md §7.4)."""
    ai_controls = [c for c in catalog if c.domain == Domain.AI_GOVERNANCE]
    observed_count = sum(
        1
        for c in ai_controls
        if outcomes.get(c.control_id) is not None
        and outcomes[c.control_id].result == ControlResult.OBSERVED
    )
    return observed_count, len(ai_controls)

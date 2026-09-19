"""
WebSec Auditor V2 — Modèles de données
========================================

Ce fichier définit UNIQUEMENT les schémas de données (ControlDefinition,
Finding, ScoreBreakdown) tels que verrouillés dans SPEC.md.

Il ne contient AUCUNE logique de pipeline, AUCUN check, AUCUNE implémentation
de scoring — voir SPEC.md section 7.3 pour l'algorithme à implémenter
ultérieurement dans scoring.py.

Règle structurelle non négociable (SPEC.md §5) :
    `scoring_status` est déclaré explicitement dans le catalogue et n'est
    JAMAIS déduit de `evidence_level`. Aucune méthode de ce fichier ne doit
    dériver l'un de l'autre.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, model_validator

# ---------------------------------------------------------------------------
# Enums — déplacés vers enums.py (décision déclarée, voir compte rendu
# d'implémentation). Réexportés ici pour ne rien casser côté imports
# existants : `from models import ControlResult` continue de fonctionner.
# Aucun champ, aucune valeur, aucune sémantique n'a changé.
# ---------------------------------------------------------------------------

from enums import (  # noqa: F401  (réexport intentionnel)
    AxisStatus,
    ControlResult,
    Domain,
    EvidenceLevel,
    Grade,
    PrivacySignalLevel,
    ScoringStatus,
)


# ---------------------------------------------------------------------------
# Wording — la formulation est un champ structuré, jamais du texte libre
# rédigé au niveau du module de check (SPEC.md §10).
# ---------------------------------------------------------------------------

class ControlPhrasing(BaseModel):
    """Formulations imposées pour un contrôle, indexées par résultat.
    Un module de check ne rédige jamais son propre texte : il sélectionne
    la clé correspondant au ControlResult obtenu."""
    observed: Optional[str] = None
    absent: Optional[str] = None
    partial: Optional[str] = None
    not_applicable: Optional[str] = None
    not_testable: Optional[str] = None


# ---------------------------------------------------------------------------
# ControlDefinition — catalogue statique, indépendant des modules d'exécution
# ---------------------------------------------------------------------------

class ControlDefinition(BaseModel):
    """Entrée du catalogue de contrôles. Une instance par control_id,
    définie une fois pour toutes, jamais générée dynamiquement par un check.
    """

    control_id: str = Field(..., description="Identifiant stable, ex: 'sec.headers'")
    domain: Domain
    evidence_level: EvidenceLevel
    scoring_status: ScoringStatus
    weight: Optional[float] = Field(
        default=None,
        description=(
            "Renseigné uniquement si scoring_status == INCLUDED. "
            "Doit rester cohérent avec l'équipondération définie dans "
            "SPEC.md §7.2 (1 / nombre de contrôles INCLUDED de l'axe) ; "
            "ce champ n'est pas calculé ici, il est fixé par le catalogue "
            "et revalidé par scoring.py à l'exécution."
        ),
    )
    report_label: str = Field(..., description="Libellé affiché dans le rapport")
    phrasing: ControlPhrasing

    @model_validator(mode="after")
    def weight_requires_inclusion(self) -> "ControlDefinition":
        if self.scoring_status == ScoringStatus.EXCLUDED and self.weight is not None:
            raise ValueError(
                f"{self.control_id}: un contrôle EXCLUDED ne doit porter aucun poids."
            )
        if self.scoring_status == ScoringStatus.INCLUDED and self.weight is None:
            raise ValueError(
                f"{self.control_id}: un contrôle INCLUDED doit avoir un poids déclaré."
            )
        return self


# ---------------------------------------------------------------------------
# Finding — résultat d'exécution d'un contrôle pour un audit donné
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    """Produit par un module de check à l'exécution. Fait référence au
    catalogue via control_id mais ne duplique pas evidence_level/scoring_status
    (ils vivent uniquement dans ControlDefinition — source unique)."""

    control_id: str
    result: ControlResult
    evidence: str = Field(..., description="Preuve brute collectée (masquée si sensible)")
    detection_method: str = Field(..., description="Comment le contrôle a été exécuté")
    limitation: Optional[str] = Field(
        default=None, description="Limite propre à ce contrôle sur cet audit"
    )
    recommendation: Optional[str] = Field(
        default=None,
        description=(
            "Renseigné uniquement si le control_id référencé a "
            "evidence_level A ou B. Jamais pour C/D — la seule action "
            "possible y est déjà portée par le niveau de preuve lui-même."
        ),
    )
    reference: Optional[str] = Field(
        default=None, description="RFC / OWASP / RGPD-CNIL / etc., citée sans interprétation"
    )
    resolved_label: str = Field(
        ..., description="Formulation finale sélectionnée dans ControlPhrasing selon `result`"
    )


# ---------------------------------------------------------------------------
# ScoreBreakdown — agrégat par audit
# ---------------------------------------------------------------------------

class ContributingControl(BaseModel):
    control_id: str
    result: ControlResult
    weight_applied: float = Field(
        ..., description="Poids réellement appliqué pour CET audit, après redistribution"
    )


class AxisScore(BaseModel):
    status: AxisStatus
    score: Optional[float] = Field(default=None, ge=0, le=100)
    contributing_controls: list[ContributingControl] = Field(default_factory=list)
    excluded_from_this_run: list[str] = Field(
        default_factory=list,
        description="control_id des contrôles INCLUDED au catalogue mais "
        "NOT_APPLICABLE/NOT_TESTABLE sur cet audit précis",
    )

    @model_validator(mode="after")
    def score_consistency(self) -> "AxisScore":
        if self.status == AxisStatus.NOT_COMPUTABLE and self.score is not None:
            raise ValueError("Un axe NOT_COMPUTABLE ne doit porter aucun score numérique.")
        if self.status == AxisStatus.COMPUTED and self.score is None:
            raise ValueError("Un axe COMPUTED doit porter un score.")
        return self


class SecurityPostureScore(AxisScore):
    grade: Optional[Grade] = None

    @model_validator(mode="after")
    def grade_requires_score(self) -> "SecurityPostureScore":
        if self.status == AxisStatus.NOT_COMPUTABLE and self.grade is not None:
            raise ValueError("Un axe NOT_COMPUTABLE ne doit porter aucun grade.")
        return self


class PrivacySignalsScore(AxisScore):
    signal_level: Optional[PrivacySignalLevel] = Field(
        default=None,
        description="Échelle qualitative — jamais de lettre A-F pour cet axe (SPEC.md §7.4).",
    )

    @model_validator(mode="after")
    def signal_level_requires_score(self) -> "PrivacySignalsScore":
        if self.status == AxisStatus.NOT_COMPUTABLE and self.signal_level is not None:
            raise ValueError("Un axe NOT_COMPUTABLE ne doit porter aucun niveau de signal.")
        return self


class AiGovernancePanel(BaseModel):
    """Jamais un score. Uniquement un décompte de signaux observés."""
    signals_observed_count: int = Field(..., ge=0)
    signals_total_count: int = Field(..., ge=0)
    findings: list[Finding] = Field(default_factory=list)


class ScoreBreakdown(BaseModel):
    security_posture: SecurityPostureScore
    privacy_signals: PrivacySignalsScore
    ai_governance: AiGovernancePanel
    methodology_notes: list[str] = Field(
        default_factory=list,
        description="Limites méthodologiques injectées dans chaque rapport (SPEC.md §11)",
    )

    @model_validator(mode="after")
    def no_global_score_field(self) -> "ScoreBreakdown":
        # Garde-fou explicite : ce modèle ne doit jamais gagner de champ
        # "global_score" ou équivalent. Le test est ici pour documenter
        # l'intention, pas pour une validation runtime réelle.
        # NOTE : model_fields lu sur la CLASSE, pas sur l'instance (self) —
        # Pydantic 2.11 déprécie l'accès via l'instance (confirmé par un
        # warning réel obtenu à l'exécution, corrigé ici).
        forbidden_fields = {"global_score", "overall_score", "compliance_score"}
        present = forbidden_fields.intersection(type(self).model_fields.keys())
        if present:
            raise ValueError(
                f"Champ(s) interdit(s) détecté(s) sur ScoreBreakdown : {present}. "
                "SPEC.md §3 interdit tout score global fusionnant les trois domaines."
            )
        return self


# ---------------------------------------------------------------------------
# Enveloppe d'audit (payload renvoyé par /audit, jamais persisté)
# ---------------------------------------------------------------------------

class AuditPayload(BaseModel):
    audit_id: str
    url: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    findings: list[Finding] = Field(default_factory=list)
    score_breakdown: Optional[ScoreBreakdown] = None
    failed_modules: list[str] = Field(default_factory=list)

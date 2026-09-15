"""
WebSec Auditor V1 — Enums
===========================

Extraction déclarée depuis models.py (voir compte rendu d'implémentation,
section "Décisions méthodologiques").

Raison : permettre à la logique des checks (checks/*.py) et au moteur de
scoring (scoring.py) d'être importés et testés SANS dépendance à Pydantic,
puisque ces enums sont de simples (str, Enum) stdlib. models.py les importe
depuis ce fichier — aucun champ, aucune valeur, aucune sémantique n'a été
modifiée par ce déplacement.

Ce fichier ne contient aucune logique, uniquement des définitions de types.
"""

from enum import Enum


class Domain(str, Enum):
    SECURITY = "SECURITY"
    PRIVACY = "PRIVACY"
    AI_GOVERNANCE = "AI_GOVERNANCE"


class EvidenceLevel(str, Enum):
    """Qualité et portée de la preuve. N'influence JAMAIS directement le
    scoring — voir ScoringStatus pour la décision de scoring elle-même."""
    A = "A"  # Vérifiable techniquement
    B = "B"  # Indicateur, non probant seul
    C = "C"  # Analyse humaine requise
    D = "D"  # Non concluable depuis un site public (non implémenté en pratique)


class ScoringStatus(str, Enum):
    """Décision méthodologique, indépendante de EvidenceLevel."""
    INCLUDED = "INCLUDED"
    EXCLUDED = "EXCLUDED"


class ControlResult(str, Enum):
    OBSERVED = "OBSERVED"
    ABSENT = "ABSENT"
    PARTIAL = "PARTIAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_TESTABLE = "NOT_TESTABLE"


class AxisStatus(str, Enum):
    COMPUTED = "COMPUTED"
    NOT_COMPUTABLE = "NOT_COMPUTABLE"


class PrivacySignalLevel(str, Enum):
    """Échelle qualitative dédiée à Privacy Technical Signals.
    Volontairement distincte du grade A-F utilisé pour Security Posture
    (SPEC.md §7.4) — une lettre évoquerait une certification."""
    LIMITED = "Signaux limités"
    PARTIAL = "Signaux partiels"
    EXTENSIVE = "Signaux étendus"


class Grade(str, Enum):
    """Réservé à Security Posture uniquement. Jamais utilisé pour Privacy
    (voir PrivacySignalsScore dans models.py — pas de champ grade)."""
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"

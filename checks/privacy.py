"""checks/privacy.py — priv.legal_pages.privacy_policy, priv.legal_pages.legal_notice,
priv.cmp.presence (tous scorés) et priv.trackers.third_party_detected (informatif).

Rappel SPEC.md §8.3 : le contrôle CMP mesure la présence d'un mécanisme
observable de gestion du consentement — jamais une conformité RGPD.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from config.cmp_registry import CMP_REGISTRY, GENERIC_CONSENT_MARKERS
from enums import ControlResult
from results import CheckOutcome

CONTROL_ID_PRIVACY_POLICY = "priv.legal_pages.privacy_policy"
CONTROL_ID_LEGAL_NOTICE = "priv.legal_pages.legal_notice"
CONTROL_ID_CMP = "priv.cmp.presence"
CONTROL_ID_TRACKERS = "priv.trackers.third_party_detected"


# ---------------------------------------------------------------------------
# Pages légales
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LegalPageEvidence:
    found: bool
    is_client_side_rendered_site: bool = False  # SPA sans SSR


def _evaluate_legal_page(control_id: str, evidence: LegalPageEvidence) -> CheckOutcome:
    if evidence.found:
        return CheckOutcome(
            control_id=control_id,
            result=ControlResult.OBSERVED,
            evidence="Page détectée via lien direct ou navigation du site.",
            detection_method="Recherche de liens/chemins connus + navigation footer/menu principal.",
            score_contribution=100.0,
            phrasing_context={},
        )

    if evidence.is_client_side_rendered_site:
        return CheckOutcome(
            control_id=control_id,
            result=ControlResult.NOT_TESTABLE,
            evidence="Site à contenu potentiellement généré côté client — détection non fiable.",
            detection_method="Recherche de liens/chemins connus + navigation footer/menu principal.",
            phrasing_context={},
        )

    return CheckOutcome(
        control_id=control_id,
        result=ControlResult.ABSENT,
        evidence="Aucune page trouvée via les chemins connus ni la navigation.",
        detection_method="Recherche de liens/chemins connus + navigation footer/menu principal.",
        score_contribution=0.0,
        phrasing_context={},
    )


def evaluate_privacy_policy(evidence: LegalPageEvidence) -> CheckOutcome:
    return _evaluate_legal_page(CONTROL_ID_PRIVACY_POLICY, evidence)


def evaluate_legal_notice(evidence: LegalPageEvidence) -> CheckOutcome:
    return _evaluate_legal_page(CONTROL_ID_LEGAL_NOTICE, evidence)


# ---------------------------------------------------------------------------
# CMP — mission section 8 : distinguer CMP_RECOGNIZED / CMP_GENERIC / NO_CMP
# ---------------------------------------------------------------------------

class CMPDetectionStatus(str, Enum):
    RECOGNIZED = "CMP_RECOGNIZED"
    GENERIC = "CMP_GENERIC"
    NONE = "NO_CMP"


@dataclass(frozen=True)
class CMPDetectionResult:
    status: CMPDetectionStatus
    provider_name: Optional[str] = None  # renseigné uniquement si RECOGNIZED


@dataclass(frozen=True)
class CMPPageEvidence:
    script_srcs: tuple[str, ...] = ()
    global_js_vars_present: tuple[str, ...] = ()
    cookie_names: tuple[str, ...] = ()
    html_markers: tuple[str, ...] = ()  # ids/classes détectés dans le DOM
    consent_link_detected: bool = False  # texte de lien type "Gérer mes préférences cookies"
    detection_uncertain: bool = False  # page tronquée/SPA — cf. LegalPageEvidence.is_client_side_rendered_site


def detect_cmp(evidence: CMPPageEvidence) -> CMPDetectionResult:
    for fingerprint in CMP_REGISTRY:
        script_match = any(
            pattern in src for src in evidence.script_srcs for pattern in fingerprint.script_src_patterns
        )
        js_var_match = any(var in evidence.global_js_vars_present for var in fingerprint.global_js_vars)
        cookie_match = any(name in evidence.cookie_names for name in fingerprint.cookie_names)

        if script_match or js_var_match or cookie_match:
            return CMPDetectionResult(status=CMPDetectionStatus.RECOGNIZED, provider_name=fingerprint.name)

    generic_match = (
        any(marker in evidence.html_markers for marker in GENERIC_CONSENT_MARKERS)
        or evidence.consent_link_detected
    )
    if generic_match:
        return CMPDetectionResult(status=CMPDetectionStatus.GENERIC)

    return CMPDetectionResult(status=CMPDetectionStatus.NONE)


def evaluate_cmp_presence(evidence: CMPPageEvidence) -> CheckOutcome:
    detection = detect_cmp(evidence)

    if detection.status == CMPDetectionStatus.RECOGNIZED:
        return CheckOutcome(
            control_id=CONTROL_ID_CMP,
            result=ControlResult.OBSERVED,
            evidence=f"CMP reconnue détectée : {detection.provider_name}.",
            detection_method="Empreintes de script/variable JS/cookie contre un registre de CMP connues.",
            score_contribution=100.0,
            phrasing_context={"name": detection.provider_name},
        )

    if detection.status == CMPDetectionStatus.GENERIC:
        return CheckOutcome(
            control_id=CONTROL_ID_CMP,
            result=ControlResult.OBSERVED,
            evidence="Mécanisme de consentement détecté, fournisseur non identifié (CMP générique).",
            detection_method="Marqueurs structurels génériques (id/class de bandeau cookie) ou lien de gestion des préférences.",
            score_contribution=100.0,
            phrasing_context={"name": "non identifié (générique)"},
        )

    if evidence.detection_uncertain:
        return CheckOutcome(
            control_id=CONTROL_ID_CMP,
            result=ControlResult.NOT_TESTABLE,
            evidence="Page potentiellement tronquée ou générée côté client — détection non fiable.",
            detection_method="Empreintes de registre + marqueurs génériques + liens de préférences.",
            phrasing_context={},
        )

    return CheckOutcome(
        control_id=CONTROL_ID_CMP,
        result=ControlResult.ABSENT,
        evidence="Aucune CMP reconnue ni marqueur générique de consentement détecté.",
        detection_method="Empreintes de registre + marqueurs génériques + liens de préférences.",
        score_contribution=0.0,
        phrasing_context={},
    )


# ---------------------------------------------------------------------------
# Trackers tiers — informatif, EXCLUDED
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ThirdPartyTracker:
    domain: str
    category: str  # "analytics" | "advertising" | "social" | ...


def evaluate_third_party_trackers(trackers: list[ThirdPartyTracker] | None) -> CheckOutcome | None:
    if not trackers:
        return None

    categories = sorted({t.category for t in trackers})
    return CheckOutcome(
        control_id=CONTROL_ID_TRACKERS,
        result=ControlResult.OBSERVED,
        evidence=f"{len(trackers)} tracker(s) tiers détecté(s) avant interaction : {', '.join(categories)}.",
        detection_method="Analyse des ressources tierces chargées avant toute interaction utilisateur.",
        score_contribution=None,
        phrasing_context={"n": len(trackers), "categories": ", ".join(categories)},
    )

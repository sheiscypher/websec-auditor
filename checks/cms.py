"""checks/cms.py — sec.cms_detection et sec.cms_cve_mapping.

Les deux sont EXCLUDED du score (mission section 4, catalogue). Détection
et rattachement CVE restent deux findings distincts, jamais fusionnés
(SPEC.md §8.2/8.3 — une version incertaine ne doit jamais devenir une
"vulnérabilité confirmée").
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from enums import ControlResult
from results import CheckOutcome

CONTROL_ID_DETECTION = "sec.cms_detection"
CONTROL_ID_CVE = "sec.cms_cve_mapping"


@dataclass(frozen=True)
class CMSDetectionEvidence:
    name: Optional[str]  # None si non identifiable
    version: Optional[str] = None
    version_confidence: str = "low"  # "low" | "high"


def evaluate_cms_detection(evidence: CMSDetectionEvidence) -> CheckOutcome:
    if evidence.name is None:
        return CheckOutcome(
            control_id=CONTROL_ID_DETECTION,
            result=ControlResult.NOT_TESTABLE,
            evidence="Aucune technologie identifiée de manière fiable.",
            detection_method="Fingerprint (headers, meta generator, fichiers caractéristiques).",
            phrasing_context={},
        )

    return CheckOutcome(
        control_id=CONTROL_ID_DETECTION,
        result=ControlResult.OBSERVED,
        evidence=f"Technologie identifiée : {evidence.name}"
        + (f" (version {evidence.version})" if evidence.version else ""),
        detection_method="Fingerprint (headers, meta generator, fichiers caractéristiques).",
        score_contribution=None,  # informatif
        phrasing_context={"name": evidence.name},
    )


def evaluate_cve_mapping(
    evidence: CMSDetectionEvidence, known_cves: list[str] | None
) -> CheckOutcome | None:
    """Retourne None si la version n'est pas déterminée avec une confiance
    suffisante ET qu'aucune CVE n'est disponible (rien à dire de fiable).
    Ne dit jamais "aucune CVE" comme preuve de sécurité — l'absence de
    résultat est silencieuse, pas une conclusion favorable."""

    if evidence.version_confidence != "high" or not evidence.version:
        if known_cves:
            # Des CVE existent mais rattachées à une version incertaine :
            # on le dit explicitement, on ne les cache pas non plus.
            return CheckOutcome(
                control_id=CONTROL_ID_CVE,
                result=ControlResult.NOT_TESTABLE,
                evidence="Version non déterminée avec suffisamment de fiabilité pour un rattachement CVE.",
                detection_method="Rattachement CVE basé sur la version détectée (NVD ou liste statique).",
                score_contribution=None,
                phrasing_context={},
            )
        return None

    if not known_cves:
        return None

    return CheckOutcome(
        control_id=CONTROL_ID_CVE,
        result=ControlResult.OBSERVED,
        evidence=f"CVE potentiellement applicable(s) à {evidence.name} {evidence.version} : {', '.join(known_cves)}.",
        detection_method="Rattachement CVE basé sur la version détectée (NVD ou liste statique).",
        limitation="Le rattachement se base sur le numéro de version déclaré ; il ne confirme pas l'exploitabilité réelle.",
        score_contribution=None,
        phrasing_context={},
    )

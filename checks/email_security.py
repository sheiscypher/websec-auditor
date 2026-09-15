"""checks/email_security.py — sec.email_security"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from enums import ControlResult
from results import CheckOutcome

CONTROL_ID = "sec.email_security"

STRICT_DMARC_POLICIES = {"quarantine", "reject"}


@dataclass(frozen=True)
class EmailSecurityEvidence:
    has_mx_record: Optional[bool]  # None = résolution DNS échouée
    spf_present: Optional[bool] = None
    dmarc_present: Optional[bool] = None
    dmarc_policy: Optional[str] = None  # "none" | "quarantine" | "reject"


def evaluate_email_security(evidence: EmailSecurityEvidence) -> CheckOutcome:
    if evidence.has_mx_record is None:
        return CheckOutcome(
            control_id=CONTROL_ID,
            result=ControlResult.NOT_TESTABLE,
            evidence="Résolution DNS impossible.",
            detection_method="Requêtes DNS (MX, TXT SPF, TXT _dmarc).",
            phrasing_context={},
        )

    if evidence.has_mx_record is False:
        return CheckOutcome(
            control_id=CONTROL_ID,
            result=ControlResult.NOT_APPLICABLE,
            evidence="Aucun enregistrement MX détecté sur ce domaine.",
            detection_method="Requêtes DNS (MX, TXT SPF, TXT _dmarc).",
            phrasing_context={},
        )

    spf_ok = bool(evidence.spf_present)
    dmarc_strict = bool(evidence.dmarc_present) and evidence.dmarc_policy in STRICT_DMARC_POLICIES
    dmarc_present_only = bool(evidence.dmarc_present)

    if spf_ok and dmarc_strict:
        return CheckOutcome(
            control_id=CONTROL_ID,
            result=ControlResult.OBSERVED,
            evidence=f"SPF présent, DMARC présent avec politique '{evidence.dmarc_policy}'.",
            detection_method="Requêtes DNS (MX, TXT SPF, TXT _dmarc).",
            score_contribution=100.0,
            phrasing_context={},
        )

    if spf_ok or dmarc_present_only:
        detail_parts = []
        if not spf_ok:
            detail_parts.append("SPF absent")
        if dmarc_present_only and not dmarc_strict:
            detail_parts.append(f"DMARC en politique '{evidence.dmarc_policy}' (non stricte)")
        if not dmarc_present_only:
            detail_parts.append("DMARC absent")
        return CheckOutcome(
            control_id=CONTROL_ID,
            result=ControlResult.PARTIAL,
            evidence="; ".join(detail_parts),
            detection_method="Requêtes DNS (MX, TXT SPF, TXT _dmarc).",
            score_contribution=50.0,
            phrasing_context={"detail": "; ".join(detail_parts)},
        )

    return CheckOutcome(
        control_id=CONTROL_ID,
        result=ControlResult.ABSENT,
        evidence="Aucun enregistrement SPF ni DMARC détecté.",
        detection_method="Requêtes DNS (MX, TXT SPF, TXT _dmarc).",
        score_contribution=0.0,
        phrasing_context={},
    )

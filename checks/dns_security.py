"""checks/dns_security.py — sec.dns.dnssec"""

from __future__ import annotations

from typing import Optional

from enums import ControlResult
from results import CheckOutcome

CONTROL_ID = "sec.dns.dnssec"


def evaluate_dnssec(dnssec_present: Optional[bool]) -> CheckOutcome:
    """`dnssec_present` = None signifie que la résolution DNS a échoué
    (evidence non obtenue), pas que DNSSEC est absent."""

    if dnssec_present is None:
        return CheckOutcome(
            control_id=CONTROL_ID,
            result=ControlResult.NOT_TESTABLE,
            evidence="Résolution DNS impossible.",
            detection_method="Requête DNS des enregistrements DS/RRSIG.",
            phrasing_context={},
        )

    if dnssec_present:
        return CheckOutcome(
            control_id=CONTROL_ID,
            result=ControlResult.OBSERVED,
            evidence="Enregistrements DNSSEC (DS/RRSIG) présents.",
            detection_method="Requête DNS des enregistrements DS/RRSIG.",
            score_contribution=100.0,
            phrasing_context={},
        )

    return CheckOutcome(
        control_id=CONTROL_ID,
        result=ControlResult.ABSENT,
        evidence="Aucun enregistrement DNSSEC (DS/RRSIG) trouvé.",
        detection_method="Requête DNS des enregistrements DS/RRSIG.",
        score_contribution=0.0,
        phrasing_context={},
    )

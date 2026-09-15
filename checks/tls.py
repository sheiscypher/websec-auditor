"""
checks/tls.py — sec.tls

Décision verrouillée (mission section 7) : AUCUN hard cap TLS dans cette
version. TLS est un contrôle scoré normal, comme les 6 autres.

Critères déterministes : SPEC.md §8.6.

`TLSEvidence` représente ce qu'une couche de collecte (hors scope de cette
implémentation, cf. compte rendu) aurait obtenu par une négociation TLS
réelle. Ce check est purement interprétatif : il ne fait aucune connexion
réseau, ce qui le rend testable de façon déterministe.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from enums import ControlResult
from results import CheckOutcome

CONTROL_ID = "sec.tls"

CRITICAL_PROTOCOLS = {"SSLv3", "TLSv1.0", "TLSv1.1"}
EXPIRY_WARNING_THRESHOLD_DAYS = 30


@dataclass(frozen=True)
class TLSEvidence:
    """Evidence attendue en entrée du check, déjà collectée."""

    connection_succeeded: bool
    negotiation_explicitly_failed: bool = False  # refus explicite (pas un timeout)
    certificate_expired: Optional[bool] = None
    days_until_expiry: Optional[int] = None
    negotiated_protocol: Optional[str] = None  # ex: "TLSv1.2", "TLSv1.3"
    tls13_available: Optional[bool] = None
    hostname_matches: Optional[bool] = None
    is_self_signed: Optional[bool] = None


def evaluate_tls(evidence: TLSEvidence) -> CheckOutcome:
    if not evidence.connection_succeeded:
        if evidence.negotiation_explicitly_failed:
            # Refus explicite de négociation (ex: serveur ne propose que des
            # protocoles obsolètes et le rejette formellement) : c'est une
            # anomalie critique constatée, pas une absence de preuve.
            return CheckOutcome(
                control_id=CONTROL_ID,
                result=ControlResult.ABSENT,
                evidence="Négociation TLS explicitement refusée par le serveur.",
                detection_method="Tentative de connexion TLS.",
                score_contribution=0.0,
                phrasing_context={"detail": "négociation TLS refusée par le serveur"},
            )
        return CheckOutcome(
            control_id=CONTROL_ID,
            result=ControlResult.NOT_TESTABLE,
            evidence="Échec de connexion (timeout ou reset réseau).",
            detection_method="Tentative de connexion TLS.",
            phrasing_context={},
        )

    critical_reasons = []
    if evidence.certificate_expired:
        critical_reasons.append("certificat expiré")
    if evidence.negotiated_protocol in CRITICAL_PROTOCOLS:
        critical_reasons.append(f"protocole obsolète négocié ({evidence.negotiated_protocol})")
    if evidence.hostname_matches is False:
        critical_reasons.append("incohérence hostname/certificat")
    if evidence.is_self_signed:
        critical_reasons.append("certificat auto-signé sur un domaine public")

    if critical_reasons:
        return CheckOutcome(
            control_id=CONTROL_ID,
            result=ControlResult.ABSENT,
            evidence="; ".join(critical_reasons),
            detection_method="Analyse du certificat et du protocole négocié.",
            score_contribution=0.0,  # Pas de hard cap : contribution normale à 0
            phrasing_context={"detail": "; ".join(critical_reasons)},
        )

    non_critical_reasons = []
    if (
        evidence.days_until_expiry is not None
        and evidence.days_until_expiry < EXPIRY_WARNING_THRESHOLD_DAYS
    ):
        non_critical_reasons.append(f"expiration dans {evidence.days_until_expiry} jours")
    if evidence.negotiated_protocol == "TLSv1.2" and evidence.tls13_available is False:
        non_critical_reasons.append("TLS1.3 non proposé par le serveur")

    if non_critical_reasons:
        return CheckOutcome(
            control_id=CONTROL_ID,
            result=ControlResult.PARTIAL,
            evidence="; ".join(non_critical_reasons),
            detection_method="Analyse du certificat et du protocole négocié.",
            score_contribution=50.0,
            phrasing_context={"detail": "; ".join(non_critical_reasons)},
        )

    return CheckOutcome(
        control_id=CONTROL_ID,
        result=ControlResult.OBSERVED,
        evidence="Certificat valide, protocole TLS1.3 disponible, aucune anomalie détectée.",
        detection_method="Analyse du certificat et du protocole négocié.",
        score_contribution=100.0,
        phrasing_context={},
    )

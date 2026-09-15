"""
checks/headers.py — sec.headers

Contrôle purement interprétatif : reçoit un dict de headers HTTP déjà
collectés (evidence), ne fait aucun appel réseau lui-même. C'est ce qui le
rend testable indépendamment (mission section 10 / 16).

Critères déterministes : SPEC.md §8.5.
"""

from __future__ import annotations

from typing import Optional

from config.sensitive_permissions import SENSITIVE_PERMISSIONS_FEATURES
from enums import ControlResult
from results import CheckOutcome

CONTROL_ID = "sec.headers"

HSTS_MIN_MAX_AGE = 31536000  # 1 an
CSP_UNSAFE_TOKENS = ("unsafe-inline", "unsafe-eval")
XFO_ALLOWED_VALUES = {"DENY", "SAMEORIGIN"}
XCTO_EXPECTED_VALUE = "nosniff"
REFERRER_POLICY_ALLOWED = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
}


def _check_hsts(value: Optional[str]) -> bool:
    if not value:
        return False
    for part in value.split(";"):
        part = part.strip()
        if part.lower().startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1])
            except ValueError:
                return False
            return max_age >= HSTS_MIN_MAX_AGE
    return False


def _check_csp(value: Optional[str]) -> bool:
    if not value:
        return False
    lowered = value.lower()
    # Isoler script-src / default-src pour ne juger que les directives
    # concernées par le critère (pas l'intégralité de la CSP).
    directives = {}
    for chunk in lowered.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = chunk.split()
        directives[parts[0]] = parts[1:]

    relevant_sources: list[str] = []
    relevant_sources += directives.get("script-src", [])
    relevant_sources += directives.get("default-src", [])

    if not relevant_sources:
        # CSP présente mais sans script-src/default-src explicite : on ne
        # peut pas juger le critère précis -> considéré non correct
        # (déterministe : absence de directive pertinente = non conforme
        # au critère défini, pas une supposition favorable).
        return False

    for token in CSP_UNSAFE_TOKENS:
        if f"'{token}'" in relevant_sources:
            return False
    if "*" in relevant_sources:
        return False
    return True


def _check_xfo(value: Optional[str]) -> bool:
    if not value:
        return False
    return value.strip().upper() in XFO_ALLOWED_VALUES


def _check_xcto(value: Optional[str]) -> bool:
    if not value:
        return False
    return value.strip().lower() == XCTO_EXPECTED_VALUE


def _check_referrer_policy(value: Optional[str]) -> bool:
    if not value:
        return False
    # Une valeur peut contenir plusieurs politiques séparées par des virgules
    # (fallback list) ; on retient la dernière, comme le fait un navigateur.
    last = value.split(",")[-1].strip().lower()
    return last in REFERRER_POLICY_ALLOWED


def is_permissions_policy_restrictive(value: Optional[str]) -> bool:
    """Retourne True si la politique restreint explicitement au moins une
    fonctionnalité sensible (mission section 9). Ne juge pas la
    "perfection" de la politique — seulement ce critère précis."""
    if not value:
        return False
    stripped = value.strip()
    if stripped == "*":
        # Syntaxe globale permissive : aucune restriction.
        return False

    for directive in stripped.split(","):
        directive = directive.strip()
        if "=" not in directive:
            continue
        feature, allowlist = directive.split("=", 1)
        feature = feature.strip().lower()
        allowlist = allowlist.strip()
        if feature not in SENSITIVE_PERMISSIONS_FEATURES:
            continue
        # allowlist wildcard = pas de restriction pour CETTE fonctionnalité
        if allowlist in ("*", "(*)"):
            continue
        # allowlist vide () ou restreinte à self/origines nommées = restriction
        return True
    return False


def _check_permissions_policy(value: Optional[str]) -> bool:
    return is_permissions_policy_restrictive(value)


CHECKS_BY_HEADER = {
    "strict-transport-security": _check_hsts,
    "content-security-policy": _check_csp,
    "x-frame-options": _check_xfo,
    "x-content-type-options": _check_xcto,
    "referrer-policy": _check_referrer_policy,
    "permissions-policy": _check_permissions_policy,
}


def evaluate_headers(headers: Optional[dict[str, str]]) -> CheckOutcome:
    """`headers` : dict déjà collecté (evidence), clés insensibles à la casse
    attendues en minuscules par l'appelant (normalisation faite en amont,
    hors de ce check — cohérent avec la séparation Evidence/Check)."""

    if headers is None:
        return CheckOutcome(
            control_id=CONTROL_ID,
            result=ControlResult.NOT_TESTABLE,
            evidence="Aucune réponse HTTP obtenue.",
            detection_method="Lecture des en-têtes de la réponse HTTP (GET).",
            phrasing_context={},
        )

    normalized = {k.lower(): v for k, v in headers.items()}

    per_header_result = {
        header_name: check_fn(normalized.get(header_name))
        for header_name, check_fn in CHECKS_BY_HEADER.items()
    }
    correct_count = sum(1 for ok in per_header_result.values() if ok)
    total = len(CHECKS_BY_HEADER)  # 6, déterministe

    if correct_count == total:
        result = ControlResult.OBSERVED
    elif correct_count == 0:
        result = ControlResult.ABSENT
    else:
        result = ControlResult.PARTIAL

    score_contribution = (correct_count / total) * 100

    missing_or_incorrect = [name for name, ok in per_header_result.items() if not ok]

    return CheckOutcome(
        control_id=CONTROL_ID,
        result=result,
        evidence=f"{correct_count}/{total} en-têtes corrects. Non conformes : {', '.join(missing_or_incorrect) or 'aucun'}.",
        detection_method="Analyse déterministe des en-têtes HTTP de la réponse (critères SPEC.md §8.5).",
        score_contribution=score_contribution,
        phrasing_context={"n": correct_count},
    )

"""checks/ai_signals.py — panneau AI & Governance Signals.

Rappel non négociable (SPEC.md §8.4 / mission section 14) : ces contrôles
sont tous EXCLUDED du scoring, aujourd'hui et dans cette version. Aucune
logique ici ne doit produire un score ou un grade IA.
"""

from __future__ import annotations

from typing import Optional

from enums import ControlResult
from results import CheckOutcome

CONTROL_ID_LLMS_TXT = "ai.llms_txt.presence"
CONTROL_ID_ROBOTS_BOTS = "ai.robots_bot_directives"
CONTROL_ID_CHATBOT = "ai.chatbot_detected"
CONTROL_ID_PUBLIC_MENTION = "ai.public_ai_usage_mention"
CONTROL_ID_GOVERNANCE_DOC = "ai.governance_documentation_public"


def evaluate_llms_txt(present: bool) -> CheckOutcome:
    return CheckOutcome(
        control_id=CONTROL_ID_LLMS_TXT,
        result=ControlResult.OBSERVED if present else ControlResult.ABSENT,
        evidence="Fichier llms.txt détecté." if present else "Aucun fichier llms.txt détecté.",
        detection_method="Requête GET sur /llms.txt.",
        score_contribution=None,
        phrasing_context={},
    )


def evaluate_robots_bot_directives(present: bool) -> CheckOutcome:
    return CheckOutcome(
        control_id=CONTROL_ID_ROBOTS_BOTS,
        result=ControlResult.OBSERVED if present else ControlResult.ABSENT,
        evidence=(
            "Directives spécifiques aux bots IA présentes dans robots.txt."
            if present
            else "Aucune directive spécifique aux bots IA détectée."
        ),
        detection_method="Analyse de robots.txt (user-agents GPTBot, ClaudeBot, PerplexityBot...).",
        score_contribution=None,
        phrasing_context={},
    )


def evaluate_chatbot_detected(
    detected: Optional[bool], dynamic_content_only: bool = False
) -> CheckOutcome:
    if detected is None or (detected is False and dynamic_content_only):
        return CheckOutcome(
            control_id=CONTROL_ID_CHATBOT,
            result=ControlResult.NOT_TESTABLE,
            evidence="Interface potentiellement chargée dynamiquement — détection incertaine.",
            detection_method="Analyse structurelle du DOM statique (pas d'exécution JavaScript).",
            score_contribution=None,
            phrasing_context={},
        )
    return CheckOutcome(
        control_id=CONTROL_ID_CHATBOT,
        result=ControlResult.OBSERVED if detected else ControlResult.ABSENT,
        evidence=(
            "Interface de type chatbot/assistant détectée."
            if detected
            else "Aucune interface conversationnelle détectée."
        ),
        detection_method="Analyse structurelle du DOM statique (pas d'exécution JavaScript).",
        score_contribution=None,
        phrasing_context={},
    )


def evaluate_public_ai_usage_mention(mention_found: bool) -> CheckOutcome:
    return CheckOutcome(
        control_id=CONTROL_ID_PUBLIC_MENTION,
        result=ControlResult.OBSERVED if mention_found else ControlResult.ABSENT,
        evidence=(
            "Mention publique relative à l'usage de systèmes d'IA détectée."
            if mention_found
            else "Aucune mention publique détectée."
        ),
        detection_method="Recherche de mentions dans les pages publiques (à propos, mentions légales, blog).",
        score_contribution=None,
        phrasing_context={},
    )


def evaluate_governance_documentation(documents_found: list[str] | None) -> CheckOutcome:
    if documents_found:
        return CheckOutcome(
            control_id=CONTROL_ID_GOVERNANCE_DOC,
            result=ControlResult.OBSERVED,
            evidence=f"Document(s) identifié(s) : {', '.join(documents_found)}.",
            detection_method="Recherche de documents publics de gouvernance IA (politique, DPIA IA).",
            limitation="La qualité et l'exhaustivité du contenu ne sont pas évaluées par l'outil.",
            score_contribution=None,
            phrasing_context={"documents": ", ".join(documents_found)},
        )
    return CheckOutcome(
        control_id=CONTROL_ID_GOVERNANCE_DOC,
        result=ControlResult.ABSENT,
        evidence="Aucun document de gouvernance IA publique identifié.",
        detection_method="Recherche de documents publics de gouvernance IA (politique, DPIA IA).",
        score_contribution=None,
        phrasing_context={},
    )

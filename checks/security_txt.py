"""checks/security_txt.py — sec.security_txt.presence (informatif, EXCLUDED).

Décision verrouillée : jamais scoré. L'adoption de ce fichier reste encore
faible, y compris chez des organisations matures et bien sécurisées —
le scorer pénaliserait injustement des sites sûrs pour une pratique encore
émergente (même biais de couverture que celui identifié sur DNSSEC).
"""

from __future__ import annotations

from enums import ControlResult
from results import CheckOutcome

CONTROL_ID = "sec.security_txt.presence"

# RFC 9116 : emplacement canonique /.well-known/security.txt, avec un
# repli historique à la racine /security.txt toléré par la RFC elle-même.
CANONICAL_PATH = "/.well-known/security.txt"
FALLBACK_PATH = "/security.txt"


def evaluate_security_txt(found_path: str | None) -> CheckOutcome:
    """`found_path` : chemin où le fichier a été trouvé (None si absent
    des deux emplacements testés)."""
    if found_path:
        return CheckOutcome(
            control_id=CONTROL_ID,
            result=ControlResult.OBSERVED,
            evidence=f"Fichier security.txt détecté à {found_path}.",
            detection_method="Requête GET sur /.well-known/security.txt puis /security.txt (RFC 9116).",
            score_contribution=None,
            phrasing_context={"path": found_path},
        )

    return CheckOutcome(
        control_id=CONTROL_ID,
        result=ControlResult.ABSENT,
        evidence="Aucun fichier security.txt détecté.",
        detection_method="Requête GET sur /.well-known/security.txt puis /security.txt (RFC 9116).",
        score_contribution=None,
        phrasing_context={},
    )

"""
scripts/verify_catalog_static.py — Vérifie les invariants du catalogue
(section 7 de la mission) par ANALYSE STATIQUE du code source de
control_catalog.py, sans importer Pydantic.

Raison d'être : dans un environnement sans Pydantic installé, on ne peut
pas instancier ControlDefinition. Ce script contourne le problème en
parsant l'AST du fichier et en lisant directement les arguments littéraux
passés à ControlDefinition(...) — control_id, domain, scoring_status,
weight — sans exécuter aucune classe Pydantic.

Ce n'est PAS un substitut à tests/test_catalog.py (qui doit être exécuté
avec Pydantic installé pour valider aussi les VALIDATEURS). C'est une
vérification complémentaire, utilisable même sans dépendances.
"""

import ast
import sys
from pathlib import Path

CATALOG_FILE = Path(__file__).resolve().parent.parent / "control_catalog.py"

# Référentiel exact issu de SPEC.md §8 — même liste que
# tests/test_catalog.py::EXPECTED_CATALOG, dupliquée ici volontairement
# pour que cette vérification reste utilisable SANS Pydantic installé.
EXPECTED_CATALOG = {
    "sec.headers": ("SECURITY", "INCLUDED", "A"),
    "sec.tls": ("SECURITY", "INCLUDED", "A"),
    "sec.exposed_files": ("SECURITY", "INCLUDED", "A"),
    "sec.secrets.pattern_detected": ("SECURITY", "INCLUDED", "A"),
    "sec.dns.dnssec": ("SECURITY", "INCLUDED", "A"),
    "sec.email_security": ("SECURITY", "INCLUDED", "A"),
    "sec.supply_chain.sri": ("SECURITY", "INCLUDED", "A"),
    "sec.cookies.secure_httponly": ("SECURITY", "INCLUDED", "A"),
    "sec.cookies.samesite_distribution": ("SECURITY", "EXCLUDED", "B"),
    "sec.security_txt.presence": ("SECURITY", "EXCLUDED", "A"),
    "sec.cms_detection": ("SECURITY", "EXCLUDED", "A"),
    "sec.cms_cve_mapping": ("SECURITY", "EXCLUDED", "B"),
    "sec.secrets.corroborated_signal": ("SECURITY", "EXCLUDED", "B"),
    "sec.supply_chain.outdated_library": ("SECURITY", "EXCLUDED", "B"),
    "priv.legal_pages.privacy_policy": ("PRIVACY", "INCLUDED", "A"),
    "priv.legal_pages.legal_notice": ("PRIVACY", "INCLUDED", "A"),
    "priv.cmp.presence": ("PRIVACY", "INCLUDED", "A"),
    "priv.trackers.third_party_detected": ("PRIVACY", "EXCLUDED", "B"),
    "ai.llms_txt.presence": ("AI_GOVERNANCE", "EXCLUDED", "A"),
    "ai.robots_bot_directives": ("AI_GOVERNANCE", "EXCLUDED", "A"),
    "ai.chatbot_detected": ("AI_GOVERNANCE", "EXCLUDED", "B"),
    "ai.public_ai_usage_mention": ("AI_GOVERNANCE", "EXCLUDED", "B"),
    "ai.governance_documentation_public": ("AI_GOVERNANCE", "EXCLUDED", "C"),
}


def _eval_simple(node: ast.AST):
    """Évalue uniquement des littéraux, None, ou une division de deux
    constantes numériques (ex: 1 / 7). Refuse tout le reste par sécurité
    (pas d'exécution de code arbitraire)."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        left = _eval_simple(node.left)
        right = _eval_simple(node.right)
        if isinstance(left, (int, float)) and isinstance(right, (int, float)):
            return left / right
    raise ValueError(f"Expression non supportée par la vérification statique : {ast.dump(node)}")


def _extract_control_definitions(tree: ast.Module) -> list[dict]:
    controls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "ControlDefinition":
            entry = {}
            for kw in node.keywords:
                if kw.arg == "control_id":
                    entry["control_id"] = _eval_simple(kw.value)
                elif kw.arg == "domain":
                    entry["domain"] = kw.value.attr  # Domain.SECURITY -> "SECURITY"
                elif kw.arg == "scoring_status":
                    entry["scoring_status"] = kw.value.attr  # ScoringStatus.INCLUDED -> "INCLUDED"
                elif kw.arg == "evidence_level":
                    entry["evidence_level"] = kw.value.attr  # EvidenceLevel.A -> "A"
                elif kw.arg == "weight":
                    entry["weight"] = _eval_simple(kw.value)
            controls.append(entry)
    return controls


def main() -> int:
    tree = ast.parse(CATALOG_FILE.read_text())
    controls = _extract_control_definitions(tree)

    errors = []

    if len(controls) != 23:
        errors.append(f"Catalogue : attendu 23 contrôles (8+6 Security, 3+1 Privacy, 5 AI), trouvé {len(controls)}.")

    included = [c for c in controls if c["scoring_status"] == "INCLUDED"]
    excluded = [c for c in controls if c["scoring_status"] == "EXCLUDED"]

    if len(included) != 11:
        errors.append(f"INCLUDED : attendu 11, trouvé {len(included)}.")

    for c in included:
        if c.get("weight") is None:
            errors.append(f"{c['control_id']} : INCLUDED sans poids.")
    for c in excluded:
        if c.get("weight") is not None:
            errors.append(f"{c['control_id']} : EXCLUDED mais porte un poids ({c['weight']}).")

    for domain_name, expected_count in (("SECURITY", 8), ("PRIVACY", 3)):
        domain_included = [c for c in included if c["domain"] == domain_name]
        if len(domain_included) != expected_count:
            errors.append(
                f"{domain_name} : attendu {expected_count} contrôles INCLUDED, trouvé {len(domain_included)}."
            )
        total_weight = sum(c["weight"] for c in domain_included)
        if abs(total_weight - 1.0) > 1e-9:
            errors.append(f"{domain_name} : somme des poids = {total_weight}, attendu 1.0.")

    ai_included = [c for c in included if c["domain"] == "AI_GOVERNANCE"]
    if ai_included:
        errors.append(f"AI_GOVERNANCE : {len(ai_included)} contrôle(s) INCLUDED trouvé(s), attendu 0.")

    control_ids = [c["control_id"] for c in controls]
    if len(control_ids) != len(set(control_ids)):
        duplicates = {cid for cid in control_ids if control_ids.count(cid) > 1}
        errors.append(f"control_id dupliqué(s) : {duplicates}")

    # Vérification par ID exact (mission complément, étape 1/2) : détecte
    # un contrôle manquant, en trop, ou avec un domain/scoring_status/
    # evidence_level incorrect — même si les compteurs globaux restent
    # accidentellement corrects.
    by_id = {c["control_id"]: c for c in controls}
    actual_ids = set(by_id.keys())
    expected_ids = set(EXPECTED_CATALOG.keys())

    missing = expected_ids - actual_ids
    if missing:
        errors.append(f"Contrôle(s) attendu(s) par SPEC.md mais absent(s) du catalogue : {sorted(missing)}")

    extra = actual_ids - expected_ids
    if extra:
        errors.append(f"Contrôle(s) présent(s) dans le catalogue mais absent(s) de SPEC.md : {sorted(extra)}")

    for control_id, (expected_domain, expected_status, expected_level) in EXPECTED_CATALOG.items():
        actual = by_id.get(control_id)
        if actual is None:
            continue  # déjà signalé ci-dessus
        if actual["domain"] != expected_domain:
            errors.append(f"{control_id} : domain={actual['domain']} attendu {expected_domain}")
        if actual["scoring_status"] != expected_status:
            errors.append(f"{control_id} : scoring_status={actual['scoring_status']} attendu {expected_status}")
        if actual.get("evidence_level") != expected_level:
            errors.append(f"{control_id} : evidence_level={actual.get('evidence_level')} attendu {expected_level}")

    print(f"Contrôles totaux : {len(controls)}")
    print(f"INCLUDED : {len(included)} — {[c['control_id'] for c in included]}")
    print(f"EXCLUDED : {len(excluded)} — {[c['control_id'] for c in excluded]}")

    if errors:
        print("\nÉCHEC — invariants violés :")
        for e in errors:
            print(f"  - {e}")
        return 1

    print("\nOK — tous les invariants statiques sont respectés.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

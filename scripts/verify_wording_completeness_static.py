"""
scripts/verify_wording_completeness_static.py

Empêche la classe de bug rencontrée en production : un check peut produire
un ControlResult pour lequel control_catalog.py ne définit aucun wording
(ControlPhrasing), ce qui fait planter build_finding() au moment de la
restitution — jamais avant, puisque rien ne le détecte à l'écriture du
check ni à l'écriture du catalogue séparément.

Méthode, sans Pydantic :
1. Parser checks/*.py pour trouver, par control_id, l'ensemble des
   ControlResult littéralement construits dans un CheckOutcome(...).
2. Parser services/audit_service.py pour repérer les appels à
   _budget_exceeded_outcome(X.CONTROL_ID) — qui produisent toujours
   ControlResult.NOT_TESTABLE pour le control_id visé, en dehors du check
   lui-même.
3. Parser control_catalog.py pour la liste des templates de wording
   réellement définis par contrôle.
4. Comparer : tout ControlResult atteignable sans wording correspondant
   est un bug à corriger AVANT tout déploiement.

Limite assumée : analyse par motifs de code, pas une exécution symbolique
complète. Un check qui construirait un ControlResult de façon indirecte
(variable, fonction intermédiaire) pourrait échapper à cette détection —
en pratique, tous les checks du projet construisent leurs CheckOutcome de
façon littérale et directe, donc cette limite n'a pas d'impact aujourd'hui.
"""

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKS_DIR = ROOT / "checks"
AUDIT_SERVICE_FILE = ROOT / "services" / "audit_service.py"
CATALOG_FILE = ROOT / "control_catalog.py"

RESULT_TO_PHRASING_KEY = {
    "OBSERVED": "observed",
    "ABSENT": "absent",
    "PARTIAL": "partial",
    "NOT_APPLICABLE": "not_applicable",
    "NOT_TESTABLE": "not_testable",
}


def _resolve_result_expr(node, variable_to_results: dict[str, set[str]], context: str) -> set[str]:
    """Résout récursivement l'expression passée à result= dans un
    CheckOutcome : littéral (ControlResult.X), variable locale, ou
    ternaire (A if cond else B, y compris imbriqué). Échoue bruyamment si
    une forme non reconnue apparaît plutôt que de renvoyer un ensemble
    vide silencieusement (cf. docstring du module)."""
    if isinstance(node, ast.Attribute):
        return {node.attr}
    if isinstance(node, ast.Name):
        if node.id in variable_to_results:
            return set(variable_to_results[node.id])
        raise RuntimeError(
            f"{context}: impossible de résoudre la variable '{node.id}' passée à "
            f"result= — aucune assignation ControlResult.X trouvée pour ce nom."
        )
    if isinstance(node, ast.IfExp):
        return _resolve_result_expr(node.body, variable_to_results, context) | _resolve_result_expr(
            node.orelse, variable_to_results, context
        )
    raise RuntimeError(
        f"{context}: forme d'expression non reconnue pour result= "
        f"({ast.dump(node)}) — vérification arrêtée plutôt que de sous-estimer."
    )


def _reachable_results_from_checks() -> dict[str, set[str]]:
    """control_id -> set des ControlResult atteignables par un
    CheckOutcome(...) à travers tous les fichiers de checks/.

    Résout quatre niveaux d'indirection, sinon des branches entières
    échappent silencieusement à la détection (TROIS bugs réels rencontrés
    en construisant ce script — pas des cas théoriques) :

    1. control_id passé via une constante de module
       (CONTROL_ID = "sec.headers" ; ... control_id=CONTROL_ID) ;
    2. result passé via une variable locale assignée à ControlResult.X
       dans une ou plusieurs branches, pas en littéral direct ;
    3. control_id passé en PARAMÈTRE d'une fonction interne (helper),
       elle-même appelée depuis un ou plusieurs wrappers publics avec un
       control_id littéral ou constant différent à chaque appel (ex:
       checks/privacy.py::_evaluate_legal_page) ;
    4. result passé via un opérateur ternaire
       (ControlResult.X if cond else ControlResult.Y), y compris imbriqué.

    Principe de sécurité, appliqué strictement : si une valeur ne peut être
    résolue par AUCUN des mécanismes ci-dessus, le script s'arrête en
    erreur plutôt que d'ignorer silencieusement l'appel — une omission
    silencieuse ici est exactement le bug qui a atteint la production,
    trois fois de suite pendant l'écriture de ce script."""
    reachable: dict[str, set[str]] = {}

    for py_file in sorted(CHECKS_DIR.glob("*.py")):
        tree = ast.parse(py_file.read_text())

        module_constants: dict[str, str] = {}
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        module_constants[target.id] = node.value.value

        variable_to_results: dict[str, set[str]] = {}
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Attribute)
                and isinstance(node.value.value, ast.Name)
                and node.value.value.id == "ControlResult"
            ):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        variable_to_results.setdefault(target.id, set()).add(node.value.attr)

        def resolve_control_id(value_node, enclosing_func) -> tuple[str | None, str | None]:
            """Retourne (control_id_litteral_ou_None, nom_du_parametre_si_indirection)."""
            if isinstance(value_node, ast.Constant):
                return value_node.value, None
            if isinstance(value_node, ast.Name):
                if value_node.id in module_constants:
                    return module_constants[value_node.id], None
                if enclosing_func is not None:
                    param_names = [a.arg for a in enclosing_func.args.args]
                    if value_node.id in param_names:
                        return None, value_node.id  # indirection via paramètre
            return None, None

        parameterized_helpers: dict[str, tuple[str, set[str]]] = {}

        for func_node in ast.walk(tree):
            if not isinstance(func_node, ast.FunctionDef):
                continue
            for node in ast.walk(func_node):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "CheckOutcome"):
                    continue
                control_id = None
                param_indirection = None
                results: set[str] = set()
                for kw in node.keywords:
                    if kw.arg == "control_id":
                        control_id, param_indirection = resolve_control_id(kw.value, func_node)
                    elif kw.arg == "result":
                        results = _resolve_result_expr(
                            kw.value, variable_to_results, f"{py_file.name}::{func_node.name}"
                        )
                if not results:
                    continue
                if control_id:
                    reachable.setdefault(control_id, set()).update(results)
                elif param_indirection:
                    key = func_node.name
                    existing_param, existing_results = parameterized_helpers.get(key, (param_indirection, set()))
                    parameterized_helpers[key] = (existing_param, existing_results | results)
                else:
                    raise RuntimeError(
                        f"{py_file.name}::{func_node.name}: impossible de résoudre control_id "
                        f"pour un CheckOutcome — ni littéral, ni constante de module, ni "
                        f"paramètre de fonction reconnu. Vérification arrêtée plutôt que de "
                        f"sous-estimer les résultats atteignables."
                    )

        for helper_name, (param_name, helper_results) in parameterized_helpers.items():
            call_sites_resolved = False
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == helper_name):
                    continue
                arg_node = None
                if node.args:
                    arg_node = node.args[0]
                for kw in node.keywords:
                    if kw.arg == param_name:
                        arg_node = kw.value
                if arg_node is None:
                    continue
                resolved_id, _ = resolve_control_id(arg_node, None)
                if resolved_id is None:
                    raise RuntimeError(
                        f"{py_file.name}: appel à {helper_name}(...) avec un control_id "
                        f"non résoluble statiquement — vérification arrêtée."
                    )
                reachable.setdefault(resolved_id, set()).update(helper_results)
                call_sites_resolved = True
            if not call_sites_resolved:
                raise RuntimeError(
                    f"{py_file.name}: la fonction '{helper_name}' construit un CheckOutcome "
                    f"avec un control_id paramétré, mais aucun site d'appel n'a été trouvé "
                    f"dans ce fichier — impossible de résoudre les control_id réels."
                )

    return reachable


def _budget_exceeded_control_ids() -> set[str]:
    """control_id visés par _budget_exceeded_outcome(X.CONTROL_ID) dans
    audit_service.py — toujours NOT_TESTABLE, construits hors des checks."""
    if not AUDIT_SERVICE_FILE.exists():
        return set()

    tree = ast.parse(AUDIT_SERVICE_FILE.read_text())

    # 1) Résoudre les alias d'import : "from checks import headers, tls, ..."
    #    -> {"headers": "headers", "tls": "tls", ...} (module local -> nom réel)
    imported_modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "checks":
            for alias in node.names:
                imported_modules.add(alias.asname or alias.name)

    # 2) Pour chaque module importé, lire son fichier pour mapper
    #    NOM_DE_LA_CONSTANTE -> valeur littérale du control_id.
    control_id_constants: dict[str, str] = {}
    for module_name in imported_modules:
        module_file = CHECKS_DIR / f"{module_name}.py"
        if not module_file.exists():
            continue
        module_tree = ast.parse(module_file.read_text())
        for node in ast.walk(module_tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id.startswith("CONTROL_ID"):
                        control_id_constants[f"{module_name}.{target.id}"] = node.value.value

    # 3) Trouver les appels _budget_exceeded_outcome(module.CONTROL_ID_X)
    budget_ids: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_budget_exceeded_outcome"
            and node.args
            and isinstance(node.args[0], ast.Attribute)
            and isinstance(node.args[0].value, ast.Name)
        ):
            key = f"{node.args[0].value.id}.{node.args[0].attr}"
            if key in control_id_constants:
                budget_ids.add(control_id_constants[key])

    return budget_ids


def _phrasing_keys_from_catalog() -> dict[str, set[str]]:
    tree = ast.parse(CATALOG_FILE.read_text())
    phrasing_by_id: dict[str, set[str]] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "ControlDefinition":
            control_id = None
            phrasing_keys = set()
            for kw in node.keywords:
                if kw.arg == "control_id" and isinstance(kw.value, ast.Constant):
                    control_id = kw.value.value
                if kw.arg == "phrasing" and isinstance(kw.value, ast.Call):
                    phrasing_keys = {k.arg for k in kw.value.keywords if k.arg}
            if control_id:
                phrasing_by_id[control_id] = phrasing_keys

    return phrasing_by_id


def main() -> int:
    reachable = _reachable_results_from_checks()
    budget_ids = _budget_exceeded_control_ids()
    for control_id in budget_ids:
        reachable.setdefault(control_id, set()).add("NOT_TESTABLE")

    phrasing_by_id = _phrasing_keys_from_catalog()

    errors = []
    for control_id, results in sorted(reachable.items()):
        phrasing_keys = phrasing_by_id.get(control_id)
        if phrasing_keys is None:
            errors.append(f"{control_id} : aucune entrée trouvée dans control_catalog.py.")
            continue
        for result in sorted(results):
            expected_key = RESULT_TO_PHRASING_KEY[result]
            if expected_key not in phrasing_keys:
                errors.append(
                    f"{control_id} : peut produire {result} mais aucun wording "
                    f"'{expected_key}' défini dans le catalogue."
                )

    print(f"Contrôles analysés : {len(reachable)}")
    if errors:
        print("\nÉCHEC — wording manquant pour un résultat atteignable :")
        for e in errors:
            print(f"  - {e}")
        return 1

    print("OK — tous les ControlResult atteignables ont un wording défini.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

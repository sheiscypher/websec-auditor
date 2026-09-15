"""
tests/test_wording_completeness.py — Intègre à la suite pytest normale la
vérification statique de scripts/verify_wording_completeness_static.py.

Sans dépendance à Pydantic (analyse AST uniquement) — s'exécute donc même
dans un environnement minimal. Empêche la régression du bug réel survenu
en production : un ControlResult atteignable sans wording correspondant
dans control_catalog.py, découvert uniquement à l'exécution réelle (au
moment de build_finding), jamais avant.
"""

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "verify_wording_completeness_static.py"


class TestWordingCompleteness(unittest.TestCase):
    def test_all_reachable_control_results_have_wording(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
        )
        self.assertEqual(
            result.returncode,
            0,
            f"scripts/verify_wording_completeness_static.py a échoué :\n"
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}",
        )


if __name__ == "__main__":
    unittest.main()

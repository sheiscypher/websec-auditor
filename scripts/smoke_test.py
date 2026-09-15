"""
scripts/smoke_test.py — Vérifie qu'une URL de test peut être auditée sans
crash, en conditions réelles (réseau requis). À lancer manuellement après
déploiement, PAS en CI unitaire (mission §10 : "Smoke test" est distinct
des tests unitaires/intégration).

Usage :
    python scripts/smoke_test.py https://example.com
    python scripts/smoke_test.py https://example.com --verbose   # détail par contrôle
    python scripts/smoke_test.py http://localhost:8000  # via l'API déployée

Sans argument, audite directement https://example.com via audit_service
(sans passer par l'API HTTP).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main() -> int:
    args = sys.argv[1:]
    verbose = "--verbose" in args or "-v" in args
    args = [a for a in args if a not in ("--verbose", "-v")]
    target_url = args[0] if args else "https://example.com"

    print(f"Smoke test — audit de {target_url}")
    try:
        from services.audit_service import run_audit

        payload, key_findings = run_audit(target_url)
    except Exception as exc:  # volontairement large : un smoke test doit
        # capturer TOUT crash, pas seulement les erreurs attendues.
        print(f"ÉCHEC — exception non gérée : {type(exc).__name__}: {exc}")
        return 1

    sec = payload.score_breakdown.security_posture
    print(f"OK — audit_id={payload.audit_id}")
    print(f"  Web Security Signals : {sec.status}"
          + (f" ({sec.score:.1f}/100, {len(sec.contributing_controls)}/8 contrôles applicables)"
             if sec.score is not None else ""))
    print(f"  Privacy Technical Signals : {payload.score_breakdown.privacy_signals.status}"
          + (f" ({payload.score_breakdown.privacy_signals.score:.1f}/100)"
             if payload.score_breakdown.privacy_signals.score is not None else ""))
    print(f"  AI & Governance Signals : {payload.score_breakdown.ai_governance.signals_observed_count}"
          f"/{payload.score_breakdown.ai_governance.signals_total_count} signaux")
    print(f"  Findings         : {len(payload.findings)}")
    print(f"  Key Findings     : {len(key_findings)}")
    print(f"  Modules NOT_TESTABLE : {payload.failed_modules or 'aucun'}")

    if verbose:
        print("\n--- Key Findings ---")
        if not key_findings:
            print("  Aucun résultat défavorable parmi les contrôles scorés.")
        for kf in key_findings:
            category = f" [{kf['risk_category']}]" if kf.get("risk_category") else ""
            print(f"  - {kf['constat']}{category}")

        print("\n--- Détail des findings (--verbose) ---")
        for f in payload.findings:
            print(f"  [{f.result:15s}] {f.control_id:40s} {f.resolved_label}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

"""
api/main.py — Point d'entrée de l'application web.

Rôle de CE fichier : exposer HTTP, valider les entrées de surface (schéma
Pydantic de requête), déléguer TOUT le travail à services.audit_service, et
traduire les erreurs (mission complément §5 : "la route ne doit pas
contenir toute la logique").

NON EXÉCUTÉ dans ce sandbox (fastapi/uvicorn non installables sans réseau).
Relu manuellement. Commandes de vérification dans README.md.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from services.audit_service import AuditInputError, run_audit
from control_catalog import CATALOG_BY_ID

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
logger = logging.getLogger("websec_auditor")

app = FastAPI(
    title="WebSec Auditor",
    description=(
        "Outil d'aide au diagnostic et de pré-audit passif — cybersécurité, "
        "confidentialité technique et signaux IA. Ne certifie ni la sécurité, "
        "ni la conformité RGPD, ni la conformité à l'AI Act."
    ),
    version="1.0.0",
)

# CORS ouvert par défaut pour un outil de portfolio public en lecture seule
# (pas de session, pas de donnée utilisateur persistée). À restreindre via
# la variable d'environnement ALLOWED_ORIGINS si le frontend est un jour
# servi depuis un domaine distinct du backend.
allowed_origins = os.environ.get("ALLOWED_ORIGINS", "*")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in allowed_origins.split(",")],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

STATIC_DIR = Path(__file__).parent / "static"


class AuditRequest(BaseModel):
    url: str = Field(..., description="URL cible, http:// ou https:// uniquement.")


def _enrich_finding(finding) -> dict:
    """Fusionne un Finding (résultat d'audit) avec les métadonnées STABLES
    du catalogue (domaine, niveau de preuve, statut de scoring, poids,
    libellé). Décision d'architecture : cette fusion reste une simple
    JOINTURE DE DONNÉES, jamais une réinterprétation — le frontend n'a donc
    aucune raison de connaître control_id pour en déduire un sens.
    Ajouté ici plutôt que dans models.py (Finding) pour ne pas toucher au
    contrat interne verrouillé ; c'est une enrichissement propre à la
    couche API, pas au modèle de données métier."""
    control_def = CATALOG_BY_ID.get(finding.control_id)
    data = finding.model_dump(mode="json")
    if control_def is not None:
        data["domain"] = control_def.domain.value
        data["evidence_level"] = control_def.evidence_level.value
        data["scoring_status"] = control_def.scoring_status.value
        data["weight"] = control_def.weight
        data["report_label"] = control_def.report_label
    return data


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/audit")
def audit(request: AuditRequest):
    try:
        payload, key_findings = run_audit(request.url)
    except AuditInputError as exc:
        # Entrée invalide / bloquée par la protection SSRF : 400, pas 500.
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception:
        # Erreur technique imprévue : ne jamais renvoyer la trace brute côté
        # client (fuite d'information), mais logger côté serveur pour
        # diagnostic (Render logs).
        logger.exception("Erreur inattendue pendant l'audit de %s", request.url)
        raise HTTPException(
            status_code=500,
            detail="Erreur technique pendant l'audit. Réessayez ou consultez les logs serveur.",
        )

    response = payload.model_dump(mode="json")
    response["key_findings"] = key_findings
    # Remplace la liste brute de findings par leur version enrichie —
    # c'est la SEULE transformation faite ici, purement additive (jointure
    # de métadonnées statiques), jamais une interprétation nouvelle.
    response["findings"] = [_enrich_finding(f) for f in payload.findings]
    return response


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

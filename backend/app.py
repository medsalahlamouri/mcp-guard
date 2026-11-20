"""Backend web local de MCP-Guard (FastAPI) : assemblage de l'application.

Lancement : python run.py   puis ouvrir http://127.0.0.1:8000

Organisation :
- backend/config.py         chemins, .env, limites des dépôts
- backend/securite.py       mot de passe de l'interface, sessions        (/api/connexion, /api/session…)
- backend/planification.py  ré-audit planifié des serveurs approuvés      (/api/planification…)
- backend/routes/elements.py  échantillons, dépôt de fichiers, import GitHub
- backend/routes/audits.py    audit, dialogue, historique, rapports, alertes
- backend/routes/serveurs.py  approbation, démonstration du rug pull
- backend/routes/systeme.py   préférences, connecteurs, Fonctionnalités, knowledge base
- backend/demo/               code de démonstration de l'onglet « Fonctionnalités »
"""
from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

from backend import config, planification, securite
from backend.demo import fonctionnalites
from backend.routes import audits, elements, serveurs, systeme
from mcp_server import registry

# Fichiers de l'interface servis publiquement (liste blanche : aucun autre fichier de frontend/).
FICHIERS_INTERFACE = {"style.css": "text/css", "app.js": "text/javascript"}


@asynccontextmanager
async def cycle_de_vie(_app: FastAPI) -> AsyncGenerator[None, None]:  # noqa: ARG001
    planification.demarrer()
    fonctionnalites.configurer(planification.planificateur, planification.reaudit_planifie)
    registry.completer_sessions_depuis_audits()
    yield
    planification.arreter()


app = FastAPI(title="MCP-Guard", lifespan=cycle_de_vie)

for module in (securite, elements, audits, serveurs, planification, systeme):
    app.include_router(module.router)


@app.get("/")
def page_accueil() -> FileResponse:
    return FileResponse(config.FRONTEND / "index.html")


@app.get("/{fichier}")
def fichier_interface(fichier: str) -> FileResponse:
    if fichier not in FICHIERS_INTERFACE:
        raise HTTPException(404, "Introuvable.")
    return FileResponse(config.FRONTEND / fichier, media_type=FICHIERS_INTERFACE[fichier])

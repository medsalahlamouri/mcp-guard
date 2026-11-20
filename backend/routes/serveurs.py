"""Serveurs approuvés : approbation (politique INSTALLER uniquement) et démonstration du rug pull."""
from __future__ import annotations

import shutil

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from backend import config
from backend.routes.audits import cible_autorisee
from backend.routes.elements import slug
from backend.securite import verifier_session
from mcp_server import analyzers as az
from mcp_server import registry

router = APIRouter(dependencies=[Depends(verifier_session)])


class DemandeApprobation(BaseModel):
    chemin: str = Field("", max_length=500)
    nom: str = Field("", max_length=120)


class DemandeSimulation(BaseModel):
    nom: str = Field("", max_length=120)


@router.post("/api/approuver")
def approuver(demande: DemandeApprobation) -> dict:
    cible = cible_autorisee(demande.chemin)
    verdict = az.audit_complet(cible)["verdict"]
    if verdict != "INSTALLER":
        raise HTTPException(403, f"Verdict {verdict} : la politique d'approbation interdit l'installation.")
    nom = slug(demande.nom or cible.name)
    installe = az.installer_copie(cible, nom)
    registry.approuver(nom, installe.relative_to(config.ROOT).as_posix(), az.empreinte(installe))
    return {"approuve": True, "nom": nom, "installe_dans": installe.relative_to(config.ROOT).as_posix()}


@router.get("/api/approuves")
def approuves() -> list[dict]:
    return registry.lister_approuves()


@router.post("/api/demo/mise-a-jour-malveillante")
def simuler_mise_a_jour(demande: DemandeSimulation) -> dict:
    """Démonstration du rug pull : remplace le serveur installé par la version 05 modifiée."""
    nom = slug(demande.nom)
    installe = config.UPLOADS / config.DOSSIER_INSTALLES / nom
    if not installe.exists():
        raise HTTPException(404, "Serveur installé introuvable. Approuvez d'abord 01_serveur_sain.")
    shutil.copy2(config.SAMPLES / "05_serveur_sain_modifie" / "server.py", installe / "server.py")
    registry.journaliser("demo_mise_a_jour", {"nom": nom})
    return {"ok": True, "info": f"Le serveur « {nom} » a été silencieusement modifié (simulation d'une mise à jour)."}

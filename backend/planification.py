"""Tâche planifiée : ré-audit des serveurs approuvés (analyse statique, sans LLM, donc sans quota).

Mode normal : chaque jour à MCPGUARD_REAUDIT_HEURE. Mode démonstration : toutes les
MCPGUARD_REAUDIT_MINUTES minutes (si la valeur est supérieure à 0).
"""
from __future__ import annotations

import os
import smtplib

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import APIRouter, Depends

from backend import config  # noqa: F401  (charge le .env avant de lire le fuseau)
from backend.agent import envoyer_email
from backend.securite import verifier_session
from mcp_server import analyzers as az
from mcp_server import registry

ID_TACHE = "reaudit"
planificateur = BackgroundScheduler(timezone=os.getenv("MCPGUARD_FUSEAU", "Africa/Tunis"))


def reaudit_planifie() -> dict:
    """Vérifie l'empreinte de chaque serveur approuvé ; suspend et alerte en cas de rug pull."""
    bilan: dict = {"verifies": 0, "rug_pulls": []}
    for s in registry.lister_approuves():
        if s["statut"] != "approuvé":
            continue
        approuve = registry.obtenir_approuve(s["nom"])
        bilan["verifies"] += 1
        try:
            diff = az.evaluer_modification(approuve["empreinte"], az.chemin_sur(approuve["chemin"]))
        except Exception as e:  # noqa: BLE001  volontaire : un serveur illisible ne bloque pas les suivants
            registry.ajouter_alerte(s["nom"], "erreur_reaudit", f"{type(e).__name__} : {e}")
            continue
        if diff["rug_pull"]:  # tools OU code modifiés depuis l'approbation
            registry.changer_statut(s["nom"], "suspendu (rug pull)")
            message = (f"Le serveur « {s['nom']} » a changé depuis son approbation du "
                       f"{approuve['date_approbation']}.\n{az.resume_modification(diff)}\n\n"
                       "Approbation suspendue automatiquement. Un nouvel audit est requis.")
            registry.ajouter_alerte(s["nom"], "rug_pull", message)
            try:
                envoyer_email(f"[MCP-Guard] Rug pull détecté : {s['nom']}", message)
            except (smtplib.SMTPException, OSError) as e:
                registry.journaliser("echec_email", f"{type(e).__name__} : {e}")
            bilan["rug_pulls"].append({"nom": s["nom"], **diff})
        else:
            registry.changer_statut(s["nom"], "approuvé")
    registry.journaliser("reaudit_planifie", bilan)
    return bilan


def demarrer() -> None:
    minutes = int(os.getenv("MCPGUARD_REAUDIT_MINUTES", "0"))
    if minutes > 0:  # mode démonstration : toutes les N minutes
        planificateur.add_job(reaudit_planifie, "interval", minutes=minutes, id=ID_TACHE, replace_existing=True)
    else:  # mode normal : chaque jour à l'heure choisie
        planificateur.add_job(reaudit_planifie, "cron", hour=int(os.getenv("MCPGUARD_REAUDIT_HEURE", "8")),
                              minute=0, id=ID_TACHE, replace_existing=True)
    planificateur.start()


def arreter() -> None:
    planificateur.shutdown(wait=False)


router = APIRouter(dependencies=[Depends(verifier_session)])


@router.get("/api/planification")
def planification() -> dict:
    tache = planificateur.get_job(ID_TACHE)
    return {"prochaine_execution": str(tache.next_run_time) if tache else None,
            "declencheur": str(tache.trigger) if tache else None}


@router.post("/api/planification/executer")
def executer_maintenant() -> dict:
    return reaudit_planifie()

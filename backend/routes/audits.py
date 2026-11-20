"""Audit, dialogue avec l'agent, historique des audits, rapports et alertes."""
from __future__ import annotations

import asyncio
import smtplib
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from backend import connecteurs
from backend.agent import envoyer_email, interroger_agent
from backend.securite import verifier_session
from mcp_server import analyzers as az
from mcp_server import registry

router = APIRouter(dependencies=[Depends(verifier_session)])

LONGUEUR_MAX_MESSAGE = 4000


class DemandeAudit(BaseModel):
    chemin: str = Field("", max_length=500)


class MessageDialogue(BaseModel):
    message: str = ""
    session_id: str | None = Field(None, max_length=200)


def cible_autorisee(chemin: str) -> Path:
    """Chemin limité à samples/ et uploads/ ; sinon erreur 400 avec un message clair."""
    try:
        return az.chemin_sur(chemin)
    except (OSError, ValueError) as e:  # PermissionError, FileNotFoundError, caractère nul…
        raise HTTPException(400, str(e)) from e


@router.post("/api/audit")
async def audit(demande: DemandeAudit) -> dict:
    cible = cible_autorisee(demande.chemin)
    # Calcul déterministe pour les indicateurs de l'interface (hors de la boucle asyncio).
    donnees = await asyncio.to_thread(az.audit_complet, cible)
    prompt = (f"Audite l'élément « {demande.chemin} » ({donnees['type'].replace('_', ' ')}) avant son installation. "
              "Suis la méthode de la skill rapport-audit-mcp et rédige le rapport complet.")
    reponse = await interroger_agent(prompt)
    audit_id = registry.enregistrer_audit(demande.chemin, donnees["type"], donnees["score"], donnees["verdict"],
                                          reponse.get("reponse", ""), donnees, reponse.get("session_id"),
                                          reponse.get("cout_equivalent_usd"))
    registry.enregistrer_session(reponse.get("session_id"), f"Audit n° {audit_id} – {demande.chemin}", audit_id)
    # Après l'enregistrement local : archivage Drive puis e-mail (backend, déterministe, sans LLM).
    envois = await asyncio.to_thread(connecteurs.apres_audit, audit_id, demande.chemin, donnees,
                                     reponse.get("reponse", ""), bool(reponse.get("erreur")))
    return {"audit_id": audit_id, "donnees": donnees, **reponse, "envois": envois}


@router.post("/api/dialogue")
async def dialogue(demande: MessageDialogue) -> dict:
    message = demande.message.strip()
    if not message:
        raise HTTPException(400, "Message vide.")
    reponse = await interroger_agent(message[:LONGUEUR_MAX_MESSAGE], demande.session_id or None)
    registry.enregistrer_session(reponse.get("session_id"), message[:80])  # mémoire à court terme
    return reponse


@router.get("/api/sessions")
def sessions() -> list[dict]:
    return registry.lister_sessions()


@router.get("/api/audits")
def audits() -> list[dict]:
    return registry.lister_audits()


def _audit_existant(audit_id: int) -> dict:
    a = registry.obtenir_audit(audit_id)
    if not a:
        raise HTTPException(404, "Audit introuvable.")
    return a


@router.get("/api/audits/{audit_id}")
def detail_audit(audit_id: int) -> dict:
    return _audit_existant(audit_id)


@router.get("/api/audits/{audit_id}/rapport.md")
def rapport_markdown(audit_id: int) -> PlainTextResponse:
    a = _audit_existant(audit_id)
    return PlainTextResponse(a["rapport"] or "", media_type="text/markdown",
                             headers={"Content-Disposition": f'attachment; filename="rapport_audit_{audit_id}.md"'})


@router.post("/api/alerte/{audit_id}")
def alerte(audit_id: int) -> dict:
    a = _audit_existant(audit_id)
    critiques = [c for c in a["donnees"].get("constats", []) if c["gravite"] == "critique"]
    corps = (f"Cible : {a['cible']}\nScore : {a['score']}/100\nVerdict : {a['verdict']}\n\n"
             "Constats critiques :\n" + "\n".join(f"- [{c['owasp']}] {c['titre']} ({c['tool']})" for c in critiques)
             + "\n\nRapport complet disponible dans l'interface MCP-Guard.")
    try:
        resultat = envoyer_email(f"[MCP-Guard] {a['verdict']} — {a['cible']}", connecteurs.masquer_secrets(corps))
    except (smtplib.SMTPException, OSError) as e:
        raise HTTPException(502, f"Échec de l'envoi : {e}") from e
    registry.ajouter_alerte(a["cible"], "verdict", f"Alerte envoyée ({a['verdict']}, score {a['score']}).")
    return resultat


@router.get("/api/alertes")
def alertes() -> list[dict]:
    return registry.lister_alertes()

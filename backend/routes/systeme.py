"""Préférences utilisateur, état et tests des connecteurs, onglet Fonctionnalités, knowledge base."""
from __future__ import annotations

import asyncio
import os
import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from backend import connecteurs
from backend.demo import fonctionnalites
from backend.securite import verifier_session
from mcp_server import registry

router = APIRouter(dependencies=[Depends(verifier_session)])

EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}")


class Preferences(BaseModel):
    """Champs facultatifs : seuls ceux envoyés sont modifiés."""
    niveau_detail: str | None = Field(None, max_length=40)
    email_notification: str | None = Field(None, max_length=254)


# ---------------------------------------------------------------------------
# Préférences (mémoire à long terme, respectées par l'agent et par les notifications)
# ---------------------------------------------------------------------------
@router.get("/api/preferences")
def lire_preferences() -> dict:
    return {**registry.lire_preferences(), "niveaux": list(registry.NIVEAUX_DETAIL),
            "email_par_defaut": bool(os.getenv("ALERTE_DESTINATAIRE"))}


@router.put("/api/preferences")
def ecrire_preferences(preferences: Preferences) -> dict:
    if preferences.niveau_detail is not None:
        if preferences.niveau_detail not in registry.NIVEAUX_DETAIL:
            raise HTTPException(400, f"Niveau de détail invalide (choix : {', '.join(registry.NIVEAUX_DETAIL)}).")
        registry.ecrire_preference("niveau_detail", preferences.niveau_detail)
    if preferences.email_notification is not None:
        email = preferences.email_notification.strip()
        if email and not EMAIL.fullmatch(email):
            raise HTTPException(400, "Adresse e-mail invalide.")
        registry.ecrire_preference("email_notification", email)
    return registry.lire_preferences()


# ---------------------------------------------------------------------------
# Connecteurs (Gmail, Drive, GitHub) — aucun e-mail envoyé par les tests
# ---------------------------------------------------------------------------
@router.get("/api/connecteurs")
def etat_connecteurs() -> dict:
    return connecteurs.etat_connecteurs()


@router.post("/api/connecteurs/{nom}/tester")
async def tester_connecteur(nom: str) -> dict:
    if nom not in connecteurs.TESTS:
        raise HTTPException(404, "Connecteur inconnu.")
    return await asyncio.to_thread(connecteurs.tester, nom)


# ---------------------------------------------------------------------------
# Onglet Fonctionnalités (démonstration, sans appel au LLM) et knowledge base
# ---------------------------------------------------------------------------
@router.get("/api/fonctionnalites")
async def etat_fonctionnalites() -> list[dict]:
    return await asyncio.to_thread(fonctionnalites.etat)


@router.post("/api/fonctionnalites/{id_}/tester")
async def tester_fonctionnalite(id_: str) -> dict:
    """Test réel d'une fonctionnalité, SANS appel au LLM (aucun quota consommé)."""
    if id_ not in fonctionnalites.TESTS:
        raise HTTPException(404, "Fonctionnalité inconnue.")
    return await asyncio.to_thread(fonctionnalites.tester, id_)


@router.get("/api/knowledge")
def recherche_knowledge(q: str = "") -> list[dict]:
    if not q.strip():
        raise HTTPException(400, "Saisissez une recherche.")
    return fonctionnalites.rechercher_knowledge(q[:200], 3)

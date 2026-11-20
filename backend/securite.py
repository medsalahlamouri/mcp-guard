"""Authentification de l'interface web : mot de passe local et sessions.

Gestion des sessions (choix assumé pour un outil personnel lié à 127.0.0.1) :
- jeton aléatoire de 256 bits (secrets.token_urlsafe), transmis dans un cookie HttpOnly, SameSite=Strict ;
- jetons gardés EN MÉMOIRE côté serveur, jamais écrits sur le disque : un redémarrage du backend
  invalide toutes les sessions et il faut se reconnecter ;
- durée de vie limitée à DUREE_SESSION (12 h) ; le cookie expire en même temps ;
- au plus MAX_SESSIONS sessions simultanées : au-delà, la plus ancienne est supprimée ;
- un mot de passe faux est suivi d'une pause de DELAI_ECHEC secondes (freine les essais en rafale).
"""
from __future__ import annotations

import asyncio
import hmac
import os
import secrets
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from backend import config  # noqa: F401  (charge le .env)
from mcp_server import registry

COOKIE = "mcpguard_session"
DUREE_SESSION = 12 * 3600  # secondes
MAX_SESSIONS = 50
DELAI_ECHEC = 1.0  # secondes

_sessions: dict[str, float] = {}  # jeton -> instant d'expiration (horloge monotone)


def mot_de_passe_attendu() -> str:
    return os.getenv("MCPGUARD_MOT_DE_PASSE", "")


def _purger() -> None:
    maintenant = time.monotonic()
    for jeton in [j for j, expiration in _sessions.items() if expiration <= maintenant]:
        del _sessions[jeton]


def creer_session() -> str:
    _purger()
    while len(_sessions) >= MAX_SESSIONS:
        del _sessions[min(_sessions, key=_sessions.__getitem__)]
    jeton = secrets.token_urlsafe(32)
    _sessions[jeton] = time.monotonic() + DUREE_SESSION
    return jeton


def session_valide(jeton: str | None) -> bool:
    expiration = _sessions.get(jeton) if jeton else None
    if expiration is None:
        return False
    if expiration <= time.monotonic():
        _sessions.pop(jeton, None)
        return False
    return True


def fermer_session(jeton: str | None) -> None:
    if jeton:
        _sessions.pop(jeton, None)


def verifier_session(request: Request) -> None:
    """Dépendance FastAPI : toute route protégée renvoie 401 sans session valide."""
    if not session_valide(request.cookies.get(COOKIE)):
        raise HTTPException(status_code=401, detail="Session expirée. Reconnectez-vous.")


class Identifiants(BaseModel):
    mot_de_passe: str = Field("", max_length=256)


router = APIRouter()


@router.post("/api/connexion")
async def connexion(identifiants: Identifiants, request: Request) -> JSONResponse:
    attendu = mot_de_passe_attendu()
    if not attendu:
        raise HTTPException(500, "Définissez MCPGUARD_MOT_DE_PASSE dans le fichier .env.")
    # Comparaison à temps constant, sur des octets (accepte les mots de passe accentués).
    if not hmac.compare_digest(identifiants.mot_de_passe.encode("utf-8"), attendu.encode("utf-8")):
        registry.journaliser("connexion_refusee", {"ip": request.client.host if request.client else "?"})
        await asyncio.sleep(DELAI_ECHEC)
        raise HTTPException(401, "Mot de passe incorrect.")
    reponse = JSONResponse({"ok": True})
    reponse.set_cookie(COOKIE, creer_session(), httponly=True, samesite="strict", max_age=DUREE_SESSION)
    registry.journaliser("connexion", {})
    return reponse


@router.post("/api/deconnexion")
def deconnexion(request: Request) -> JSONResponse:
    fermer_session(request.cookies.get(COOKIE))
    reponse = JSONResponse({"ok": True})
    reponse.delete_cookie(COOKIE)
    return reponse


@router.get("/api/session", dependencies=[Depends(verifier_session)])
def etat_session() -> dict:
    return {"ok": True, "modele": os.getenv("MCPGUARD_MODELE", "sonnet")}

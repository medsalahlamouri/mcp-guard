"""Éléments à auditer : échantillons, dépôt de fichiers et import GitHub (connecteur GitHub).

Tout est validé AVANT d'écrire sur le disque : un dépôt refusé ne laisse aucun fichier.
"""
from __future__ import annotations

import asyncio
import json
import re
import shutil
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from backend import config, connecteurs
from backend.securite import verifier_session
from mcp_server import registry

router = APIRouter(dependencies=[Depends(verifier_session)])

# github.com/<propriétaire>/<dépôt>[.git][/tree/<branche>[/<dossier>]][/]
URL_GITHUB = re.compile(
    r"(?:https?://)?(?:www\.)?github\.com/"
    r"(?P<proprio>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/"
    r"(?P<depot>[A-Za-z0-9_.-]{1,100}?)(?:\.git)?"
    r"(?:/tree/(?P<branche>[A-Za-z0-9_.-]{1,100})(?:/(?P<dossier>[^?#]*))?)?/?"
    r"(?:[?#].*)?")  # paramètres d'affichage collés depuis le navigateur (?tab=readme…) : ignorés
FORMAT_URL = "https://github.com/<propriétaire>/<dépôt> ou https://github.com/<propriétaire>/<dépôt>/tree/<branche>/<dossier>"


def slug(texte: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "-", texte).strip("-")[:60] or "element"


@router.get("/api/elements")
def elements() -> list[dict]:
    resultat = []
    for zone, dossier in (("samples", config.SAMPLES), ("uploads", config.UPLOADS)):
        for p in sorted(dossier.iterdir()) if dossier.exists() else []:
            if p.name.startswith(".") or p.name == config.DOSSIER_INSTALLES:
                continue
            resultat.append({"chemin": f"{zone}/{p.name}", "zone": zone, "nom": p.name})
    installes = config.UPLOADS / config.DOSSIER_INSTALLES
    for p in sorted(installes.iterdir()) if installes.exists() else []:
        resultat.append({"chemin": f"uploads/{config.DOSSIER_INSTALLES}/{p.name}", "zone": "installé", "nom": p.name})
    return resultat


# ---------------------------------------------------------------------------
# Dépôt de fichiers
# ---------------------------------------------------------------------------
def nom_de_fichier_sur(nom_brut: str | None) -> str:
    """Garde uniquement le nom final (supprime tout chemin, « / » comme « \\ ») : anti path traversal."""
    nom = re.split(r"[\\/]", nom_brut or "")[-1].strip()
    if nom in ("", ".", ".."):
        raise HTTPException(400, f"Nom de fichier invalide : « {nom_brut} ».")
    return nom


@router.post("/api/depot")
async def depot(nom: str = Form(..., max_length=120), fichiers: list[UploadFile] = File(...)) -> dict:
    nom_dossier = slug(nom)
    if nom_dossier.lower() == config.DOSSIER_INSTALLES:  # réservé aux serveurs approuvés (surveillés)
        raise HTTPException(400, f"Nom réservé : « {config.DOSSIER_INSTALLES} ». Choisissez un autre nom.")
    if len(fichiers) > config.MAX_FICHIERS_DEPOT:
        raise HTTPException(400, f"{len(fichiers)} fichiers envoyés : {config.MAX_FICHIERS_DEPOT} au maximum.")

    # 1. Validation complète (noms, extensions, tailles) : rien n'est écrit si un fichier est refusé.
    valides: dict[str, bytes] = {}
    refuses: list[str] = []
    for f in fichiers:
        nom_fichier = nom_de_fichier_sur(f.filename)
        if Path(nom_fichier).suffix.lower() not in config.EXTENSIONS_AUTORISEES:
            refuses.append(nom_fichier)
            continue
        contenu = await f.read(config.TAILLE_MAX + 1)  # lecture bornée : jamais plus de 1 Mo en mémoire
        if len(contenu) > config.TAILLE_MAX:
            raise HTTPException(400, f"« {nom_fichier} » dépasse 1 Mo.")
        valides[nom_fichier] = contenu
    if refuses:
        raise HTTPException(400, f"Extension non autorisée : {', '.join(refuses)}. "
                                 f"Extensions acceptées : {config.extensions_lisibles()}.")
    if not valides:
        raise HTTPException(400, f"Aucun fichier reçu. Extensions acceptées : {config.extensions_lisibles()}.")

    # 2. Écriture
    cible = config.UPLOADS / nom_dossier
    cible.mkdir(parents=True, exist_ok=True)
    for nom_fichier, contenu in valides.items():
        (cible / nom_fichier).write_bytes(contenu)
    registry.journaliser("depot", {"cible": cible.name, "fichiers": list(valides)})
    registry.enregistrer_source(f"uploads/{cible.name}", "dépôt")
    return {"chemin": f"uploads/{cible.name}", "fichiers": list(valides)}


# ---------------------------------------------------------------------------
# Import GitHub (API REST, GITHUB_TOKEN facultatif)
# ---------------------------------------------------------------------------
class DemandeImport(BaseModel):
    url: str = Field("", max_length=400)


def analyser_url_github(url: str) -> tuple[str, str, str | None, str]:
    """Valide l'URL et renvoie (propriétaire, dépôt, branche, dossier). Lève HTTPException(400) sinon."""
    m = URL_GITHUB.fullmatch(url.strip())
    if not m:
        raise HTTPException(400, f"URL GitHub invalide. Format attendu : {FORMAT_URL}.")
    proprio, depot_nom, branche = m["proprio"], m["depot"], m["branche"]
    dossier = (m["dossier"] or "").strip("/")
    if depot_nom in (".", "..") or branche in (".", "..") or ".." in dossier.split("/"):
        raise HTTPException(400, "URL GitHub invalide : « . » et « .. » sont interdits dans le chemin.")
    return proprio, depot_nom, branche, dossier


def message_erreur_github(e: Exception) -> str:
    """Message d'erreur compréhensible pour l'interface (au lieu d'une trace brute)."""
    if isinstance(e, urllib.error.HTTPError):
        if e.code == 403 and e.headers.get("X-RateLimit-Remaining") == "0":
            return ("Quota de l'API GitHub épuisé (60 requêtes/h sans jeton). Réessayez plus tard "
                    "ou définissez GITHUB_TOKEN dans .env.")
        if e.code == 401:
            return "GITHUB_TOKEN invalide ou expiré."
        if e.code == 404:
            return "Dépôt, branche ou dossier introuvable (ou dépôt privé sans GITHUB_TOKEN)."
        return f"GitHub a répondu {e.code} : {e.reason}"
    if isinstance(e, urllib.error.URLError):
        return f"GitHub injoignable (réseau) : {e.reason}"
    if isinstance(e, TimeoutError):
        return "GitHub ne répond pas (délai dépassé). Réessayez plus tard."
    return f"Réponse inattendue de l'API GitHub : {type(e).__name__} : {e}"


def telecharger_depot(proprio: str, depot_nom: str, branche: str | None, dossier: str, cible: Path) -> list[str]:
    """Parcourt le dépôt (profondeur et nombre de fichiers bornés) et copie les fichiers analysables."""
    entetes = connecteurs.entetes_github()
    recuperes: list[str] = []
    ref = f"?ref={urllib.parse.quote(branche, safe='')}" if branche else ""

    def parcourir(chemin: str, profondeur: int = 0) -> None:
        if profondeur > config.PROFONDEUR_MAX_GITHUB or len(recuperes) >= config.MAX_FICHIERS_GITHUB:
            return
        api = f"https://api.github.com/repos/{proprio}/{depot_nom}/contents/{urllib.parse.quote(chemin)}{ref}"
        with urllib.request.urlopen(urllib.request.Request(api, headers=entetes), timeout=20) as r:
            contenu = json.loads(r.read())
        for e in contenu if isinstance(contenu, list) else [contenu]:
            if len(recuperes) >= config.MAX_FICHIERS_GITHUB:  # limite vérifiée à chaque fichier
                return
            if e["type"] == "dir" and e["name"] not in config.DOSSIERS_IGNORES_GITHUB:
                parcourir(e["path"], profondeur + 1)
            elif (e["type"] == "file" and e.get("download_url")
                  and Path(e["name"]).suffix in config.EXTENSIONS_AUTORISEES and e.get("size", 0) < config.TAILLE_MAX):
                telechargement = urllib.request.Request(e["download_url"], headers=entetes)
                with urllib.request.urlopen(telechargement, timeout=20) as r:
                    (cible / e["path"].replace("/", "__")).write_bytes(r.read(config.TAILLE_MAX))
                    recuperes.append(e["path"])

    parcourir(dossier)
    return recuperes


def lire_commit(proprio: str, depot_nom: str, branche: str | None) -> str | None:
    """Commit exact importé, cité dans la notification e-mail (None si indisponible)."""
    ref = urllib.parse.quote(branche or "HEAD", safe="")
    requete = urllib.request.Request(f"https://api.github.com/repos/{proprio}/{depot_nom}/commits/{ref}",
                                     headers={**connecteurs.entetes_github(), "Accept": "application/vnd.github.sha"})
    try:
        with urllib.request.urlopen(requete, timeout=20) as r:
            return r.read().decode("ascii", "replace").strip()[:40]
    except (OSError, ValueError):
        return None


@router.post("/api/import-github")
async def import_github(demande: DemandeImport) -> dict:
    proprio, depot_nom, branche, dossier = analyser_url_github(demande.url)
    cible = config.UPLOADS / slug(f"github-{proprio}-{depot_nom}")
    deja_present = cible.exists()
    cible.mkdir(parents=True, exist_ok=True)
    try:
        # Requêtes réseau bloquantes exécutées hors de la boucle asyncio : l'interface reste réactive.
        recuperes = await asyncio.to_thread(telecharger_depot, proprio, depot_nom, branche, dossier, cible)
    except (OSError, ValueError, KeyError, TypeError) as e:  # réseau, HTTP, JSON ou réponse inattendue
        message = message_erreur_github(e)
        registry.journaliser("import_github_echec", {"url": demande.url, "ok": False, "message": message})
        if not deja_present:
            shutil.rmtree(cible, ignore_errors=True)
        raise HTTPException(502, message) from e
    if not recuperes:
        if not deja_present:
            shutil.rmtree(cible, ignore_errors=True)
        raise HTTPException(404, "Aucun fichier analysable dans ce dépôt ou ce dossier "
                                 f"(extensions acceptées : {config.extensions_lisibles()}).")

    commit = await asyncio.to_thread(lire_commit, proprio, depot_nom, branche)
    url_propre = f"https://github.com/{proprio}/{depot_nom}"
    if branche:
        url_propre += f"/tree/{branche}/{dossier}".rstrip("/")
    registry.enregistrer_source(f"uploads/{cible.name}", "github", url_propre, commit)
    registry.journaliser("import_github",
                         {"url": demande.url, "fichiers": len(recuperes), "commit": commit, "ok": True})
    return {"chemin": f"uploads/{cible.name}", "fichiers": recuperes, "commit": commit}

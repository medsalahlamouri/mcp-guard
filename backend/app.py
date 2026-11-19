"""Backend web local de MCP-Guard (FastAPI).

Lancement : python run.py   puis ouvrir http://127.0.0.1:8000
"""
from __future__ import annotations

import asyncio
import hmac
import json
import os
import re
import secrets
import shutil
import sys
import urllib.error
import urllib.parse
import urllib.request
from contextlib import asynccontextmanager
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from backend import connecteurs, fonctionnalites  # noqa: E402
from backend.agent import envoyer_email, interroger_agent  # noqa: E402
from mcp_server import analyzers as az  # noqa: E402
from mcp_server import registry  # noqa: E402

FRONTEND = ROOT / "frontend"
UPLOADS = ROOT / "uploads"
EXTENSIONS_AUTORISEES = {".py", ".json", ".md", ".js", ".ts", ".txt", ".toml"}
TAILLE_MAX = 1_000_000  # 1 Mo par fichier

# ---------------------------------------------------------------------------
# Authentification de l'interface (mot de passe local + jeton de session)
# ---------------------------------------------------------------------------
MOT_DE_PASSE = os.getenv("MCPGUARD_MOT_DE_PASSE", "")
SESSIONS: set[str] = set()
COOKIE = "mcpguard_session"


def verifier_session(request: Request) -> None:
    jeton = request.cookies.get(COOKIE, "")
    if not jeton or jeton not in SESSIONS:
        raise HTTPException(status_code=401, detail="Session expirée. Reconnectez-vous.")


# ---------------------------------------------------------------------------
# Tâche planifiée : réaudit des serveurs approuvés (sans LLM, donc sans quota)
# ---------------------------------------------------------------------------
planificateur = BackgroundScheduler(timezone=os.getenv("MCPGUARD_FUSEAU", "Africa/Tunis"))


def reaudit_planifie() -> dict:
    """Vérifie l'empreinte de chaque serveur approuvé ; suspend et alerte en cas de rug pull."""
    bilan = {"verifies": 0, "rug_pulls": []}
    for s in registry.lister_approuves():
        if s["statut"] != "approuvé":
            continue
        approuve = registry.obtenir_approuve(s["nom"])
        bilan["verifies"] += 1
        try:
            diff = az.evaluer_modification(approuve["empreinte"], az.chemin_sur(approuve["chemin"]))
        except Exception as e:
            registry.ajouter_alerte(s["nom"], "erreur_reaudit", str(e))
            continue
        if diff["rug_pull"]:  # tools OU code modifiés depuis l'approbation
            registry.changer_statut(s["nom"], "suspendu (rug pull)")
            message = (f"Le serveur « {s['nom']} » a changé depuis son approbation du "
                       f"{approuve['date_approbation']}.\n{az.resume_modification(diff)}\n\n"
                       "Approbation suspendue automatiquement. Un nouvel audit est requis.")
            registry.ajouter_alerte(s["nom"], "rug_pull", message)
            try:
                envoyer_email(f"[MCP-Guard] Rug pull détecté : {s['nom']}", message)
            except Exception as e:
                registry.journaliser("echec_email", str(e))
            bilan["rug_pulls"].append({"nom": s["nom"], **diff})
        else:
            registry.changer_statut(s["nom"], "approuvé")
    registry.journaliser("reaudit_planifie", bilan)
    return bilan


@asynccontextmanager
async def cycle_de_vie(app: FastAPI):
    minutes = int(os.getenv("MCPGUARD_REAUDIT_MINUTES", "0"))
    if minutes > 0:  # mode démonstration : toutes les N minutes
        planificateur.add_job(reaudit_planifie, "interval", minutes=minutes, id="reaudit")
    else:  # mode normal : chaque jour à l'heure choisie
        planificateur.add_job(reaudit_planifie, "cron", hour=int(os.getenv("MCPGUARD_REAUDIT_HEURE", "8")),
                              minute=0, id="reaudit")
    planificateur.start()
    fonctionnalites.configurer(planificateur, reaudit_planifie)
    registry.completer_sessions_depuis_audits()
    yield
    planificateur.shutdown(wait=False)


app = FastAPI(title="MCP-Guard", lifespan=cycle_de_vie)


# ---------------------------------------------------------------------------
# Pages et authentification
# ---------------------------------------------------------------------------
@app.get("/")
def page_accueil():
    return FileResponse(FRONTEND / "index.html")


@app.post("/api/connexion")
async def connexion(request: Request):
    corps = await request.json()
    if not MOT_DE_PASSE:
        raise HTTPException(500, "Définissez MCPGUARD_MOT_DE_PASSE dans le fichier .env.")
    if not hmac.compare_digest(str(corps.get("mot_de_passe", "")), MOT_DE_PASSE):
        registry.journaliser("connexion_refusee", {"ip": request.client.host if request.client else "?"})
        raise HTTPException(401, "Mot de passe incorrect.")
    jeton = secrets.token_urlsafe(32)
    SESSIONS.add(jeton)
    reponse = JSONResponse({"ok": True})
    reponse.set_cookie(COOKIE, jeton, httponly=True, samesite="strict")
    registry.journaliser("connexion", {})
    return reponse


@app.post("/api/deconnexion")
def deconnexion(request: Request):
    SESSIONS.discard(request.cookies.get(COOKIE, ""))
    reponse = JSONResponse({"ok": True})
    reponse.delete_cookie(COOKIE)
    return reponse


@app.get("/api/session")
def etat_session(request: Request):
    verifier_session(request)
    return {"ok": True, "modele": os.getenv("MCPGUARD_MODELE", "sonnet")}


# ---------------------------------------------------------------------------
# Éléments à auditer : échantillons, dépôts de fichiers, import GitHub
# ---------------------------------------------------------------------------
@app.get("/api/elements")
def elements(request: Request):
    verifier_session(request)
    resultat = []
    for zone in ("samples", "uploads"):
        dossier = ROOT / zone
        for p in sorted(dossier.iterdir()) if dossier.exists() else []:
            if p.name.startswith(".") or p.name == "installes":
                continue
            resultat.append({"chemin": f"{zone}/{p.name}", "zone": zone, "nom": p.name})
    installes = UPLOADS / "installes"
    for p in sorted(installes.iterdir()) if installes.exists() else []:
        resultat.append({"chemin": f"uploads/installes/{p.name}", "zone": "installé", "nom": p.name})
    return resultat


def _slug(texte: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "-", texte).strip("-")[:60] or "element"


@app.post("/api/depot")
async def depot(request: Request, nom: str = Form(...), fichiers: list[UploadFile] = File(...)):
    verifier_session(request)
    if len(fichiers) > 20:
        raise HTTPException(400, "20 fichiers maximum.")
    if _slug(nom).lower() == "installes":  # dossier réservé aux serveurs approuvés (surveillés)
        raise HTTPException(400, "Nom réservé : choisissez un autre nom.")
    cible = UPLOADS / _slug(nom)
    cible.mkdir(parents=True, exist_ok=True)
    enregistres = []
    for f in fichiers:
        nom_fichier = Path(f.filename or "").name  # supprime tout chemin (anti path traversal)
        if Path(nom_fichier).suffix.lower() not in EXTENSIONS_AUTORISEES:
            continue
        contenu = await f.read()
        if len(contenu) > TAILLE_MAX:
            raise HTTPException(400, f"{nom_fichier} dépasse 1 Mo.")
        (cible / nom_fichier).write_bytes(contenu)
        enregistres.append(nom_fichier)
    if not enregistres:
        raise HTTPException(400, "Aucun fichier valide (.py, .json, .md, .js, .ts).")
    registry.journaliser("depot", {"cible": cible.name, "fichiers": enregistres})
    registry.enregistrer_source(f"uploads/{cible.name}", "dépôt")
    return {"chemin": f"uploads/{cible.name}", "fichiers": enregistres}


@app.post("/api/import-github")
async def import_github(request: Request):
    """Connecteur GitHub : récupère les fichiers d'un dépôt public (ou privé avec GITHUB_TOKEN)."""
    verifier_session(request)
    url = (await request.json()).get("url", "")
    m = re.match(r"(?:https?://)?github\.com/([\w.-]+)/([\w.-]+)(?:/tree/([\w.-]+)/?(.*))?", url.strip())
    if not m:
        raise HTTPException(400, "URL GitHub invalide (ex. https://github.com/org/depot).")
    proprio, depot_nom, branche, sous_dossier = m.group(1), m.group(2).removesuffix(".git"), m.group(3), m.group(4) or ""
    entetes = connecteurs.entetes_github()  # API REST GitHub + GITHUB_TOKEN du .env s'il est défini
    cible = UPLOADS / _slug(f"github-{proprio}-{depot_nom}")
    cible.mkdir(parents=True, exist_ok=True)
    recuperes: list[str] = []

    def parcourir(chemin: str, profondeur: int = 0):
        if profondeur > 3 or len(recuperes) >= 30:
            return
        api = f"https://api.github.com/repos/{proprio}/{depot_nom}/contents/{urllib.parse.quote(chemin)}"
        if branche:
            api += f"?ref={branche}"
        with urllib.request.urlopen(urllib.request.Request(api, headers=entetes), timeout=20) as r:
            elements = json.loads(r.read())
        for e in elements if isinstance(elements, list) else [elements]:
            if len(recuperes) >= 30:  # limite vérifiée à chaque fichier (et pas seulement par dossier)
                return
            if e["type"] == "dir" and e["name"] not in ("node_modules", ".git", "tests", "docs"):
                parcourir(e["path"], profondeur + 1)
            elif e["type"] == "file" and Path(e["name"]).suffix in EXTENSIONS_AUTORISEES and e.get("size", 0) < TAILLE_MAX:
                with urllib.request.urlopen(urllib.request.Request(e["download_url"], headers=entetes), timeout=20) as r:
                    nom_local = e["path"].replace("/", "__")
                    (cible / nom_local).write_bytes(r.read())
                    recuperes.append(e["path"])

    try:
        # Requêtes réseau bloquantes exécutées hors de la boucle asyncio : l'interface reste réactive.
        await asyncio.to_thread(parcourir, sous_dossier)
    except Exception as e:
        message = _message_erreur_github(e)
        registry.journaliser("import_github_echec", {"url": url, "ok": False, "message": message})
        raise HTTPException(502, message)

    def lire_commit() -> str | None:
        """Commit exact importé, cité dans la notification e-mail."""
        ref = urllib.parse.quote(branche or "HEAD", safe="")
        requete = urllib.request.Request(f"https://api.github.com/repos/{proprio}/{depot_nom}/commits/{ref}",
                                         headers={**entetes, "Accept": "application/vnd.github.sha"})
        with urllib.request.urlopen(requete, timeout=20) as r:
            return r.read().decode("ascii", "replace").strip()[:40]

    try:
        commit = await asyncio.to_thread(lire_commit)
    except Exception:
        commit = None
    url_propre = f"https://github.com/{proprio}/{depot_nom}" + (f"/tree/{branche}/{sous_dossier}".rstrip("/") if branche else "")
    registry.enregistrer_source(f"uploads/{cible.name}", "github", url_propre, commit)
    registry.journaliser("import_github", {"url": url, "fichiers": len(recuperes), "commit": commit, "ok": True})
    return {"chemin": f"uploads/{cible.name}", "fichiers": recuperes, "commit": commit}


def _message_erreur_github(e: Exception) -> str:
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
    return f"Import GitHub impossible : {type(e).__name__} : {e}"


# ---------------------------------------------------------------------------
# Audit et dialogue avec l'agent
# ---------------------------------------------------------------------------
@app.post("/api/audit")
async def audit(request: Request):
    verifier_session(request)
    chemin = (await request.json()).get("chemin", "")
    try:
        cible = az.chemin_sur(chemin)
    except Exception as e:
        raise HTTPException(400, str(e))
    donnees = az.audit_complet(cible)  # calcul déterministe pour les indicateurs de l'interface
    prompt = (f"Audite l'élément « {chemin} » ({donnees['type'].replace('_', ' ')}) avant son installation. "
              "Suis la méthode de la skill rapport-audit-mcp et rédige le rapport complet.")
    reponse = await interroger_agent(prompt)
    audit_id = registry.enregistrer_audit(chemin, donnees["type"], donnees["score"], donnees["verdict"],
                                          reponse.get("reponse", ""), donnees, reponse.get("session_id"),
                                          reponse.get("cout_equivalent_usd"))
    # Après l'enregistrement local : archivage Drive puis e-mail (backend, déterministe, sans LLM).
    registry.enregistrer_session(reponse.get("session_id"), f"Audit n° {audit_id} – {chemin}", audit_id)
    envois = await asyncio.to_thread(connecteurs.apres_audit, audit_id, chemin, donnees,
                                     reponse.get("reponse", ""), bool(reponse.get("erreur")))
    return {"audit_id": audit_id, "donnees": donnees, **reponse, "envois": envois}


@app.post("/api/dialogue")
async def dialogue(request: Request):
    verifier_session(request)
    corps = await request.json()
    message = str(corps.get("message", "")).strip()
    if not message:
        raise HTTPException(400, "Message vide.")
    reponse = await interroger_agent(message[:4000], corps.get("session_id") or None)
    registry.enregistrer_session(reponse.get("session_id"), message[:80])  # mémoire à court terme
    return reponse


@app.get("/api/sessions")
def sessions(request: Request):
    verifier_session(request)
    return registry.lister_sessions()


# ---------------------------------------------------------------------------
# Préférences utilisateur (mémoire à long terme, respectées par l'agent et par les notifications)
# ---------------------------------------------------------------------------
@app.get("/api/preferences")
def lire_preferences(request: Request):
    verifier_session(request)
    return {**registry.lire_preferences(), "niveaux": list(registry.NIVEAUX_DETAIL),
            "email_par_defaut": bool(os.getenv("ALERTE_DESTINATAIRE"))}


@app.put("/api/preferences")
async def ecrire_preferences(request: Request):
    verifier_session(request)
    corps = await request.json()
    if "niveau_detail" in corps:
        if corps["niveau_detail"] not in registry.NIVEAUX_DETAIL:
            raise HTTPException(400, f"Niveau de détail invalide (choix : {', '.join(registry.NIVEAUX_DETAIL)}).")
        registry.ecrire_preference("niveau_detail", corps["niveau_detail"])
    if "email_notification" in corps:
        email = str(corps["email_notification"]).strip()
        if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}", email):
            raise HTTPException(400, "Adresse e-mail invalide.")
        registry.ecrire_preference("email_notification", email)
    return registry.lire_preferences()


# ---------------------------------------------------------------------------
# Actions : approbation, rug pull, alertes, rapports
# ---------------------------------------------------------------------------
@app.post("/api/approuver")
async def approuver(request: Request):
    verifier_session(request)
    corps = await request.json()
    try:
        cible = az.chemin_sur(corps.get("chemin", ""))
    except Exception as e:
        raise HTTPException(400, str(e))
    verdict = az.audit_complet(cible)["verdict"]
    if verdict != "INSTALLER":
        raise HTTPException(403, f"Verdict {verdict} : la politique d'approbation interdit l'installation.")
    nom = _slug(corps.get("nom") or cible.name)
    installe = az.installer_copie(cible, nom)
    registry.approuver(nom, installe.relative_to(ROOT).as_posix(), az.empreinte(installe))
    return {"approuve": True, "nom": nom, "installe_dans": installe.relative_to(ROOT).as_posix()}


@app.get("/api/approuves")
def approuves(request: Request):
    verifier_session(request)
    return registry.lister_approuves()


@app.post("/api/demo/mise-a-jour-malveillante")
async def simuler_mise_a_jour(request: Request):
    """Démonstration du rug pull : remplace le serveur installé par la version 05 modifiée."""
    verifier_session(request)
    nom = _slug((await request.json()).get("nom", ""))
    installe = UPLOADS / "installes" / nom
    if not installe.exists():
        raise HTTPException(404, "Serveur installé introuvable. Approuvez d'abord 01_serveur_sain.")
    shutil.copy2(ROOT / "samples" / "05_serveur_sain_modifie" / "server.py", installe / "server.py")
    registry.journaliser("demo_mise_a_jour", {"nom": nom})
    return {"ok": True, "info": f"Le serveur « {nom} » a été silencieusement modifié (simulation d'une mise à jour)."}


@app.get("/api/planification")
def planification(request: Request):
    verifier_session(request)
    job = planificateur.get_job("reaudit")
    return {"prochaine_execution": str(job.next_run_time) if job else None,
            "declencheur": str(job.trigger) if job else None}


@app.post("/api/planification/executer")
def executer_maintenant(request: Request):
    verifier_session(request)
    return reaudit_planifie()


@app.post("/api/alerte/{audit_id}")
def alerte(audit_id: int, request: Request):
    verifier_session(request)
    a = registry.obtenir_audit(audit_id)
    if not a:
        raise HTTPException(404, "Audit introuvable.")
    critiques = [c for c in a["donnees"].get("constats", []) if c["gravite"] == "critique"]
    corps = (f"Cible : {a['cible']}\nScore : {a['score']}/100\nVerdict : {a['verdict']}\n\n"
             "Constats critiques :\n" + "\n".join(f"- [{c['owasp']}] {c['titre']} ({c['tool']})" for c in critiques)
             + "\n\nRapport complet disponible dans l'interface MCP-Guard.")
    try:
        resultat = envoyer_email(f"[MCP-Guard] {a['verdict']} — {a['cible']}", corps)
    except Exception as e:
        raise HTTPException(502, f"Échec de l'envoi : {e}")
    registry.ajouter_alerte(a["cible"], "verdict", f"Alerte envoyée ({a['verdict']}, score {a['score']}).")
    return resultat


@app.get("/api/audits")
def audits(request: Request):
    verifier_session(request)
    return registry.lister_audits()


@app.get("/api/audits/{audit_id}")
def detail_audit(audit_id: int, request: Request):
    verifier_session(request)
    a = registry.obtenir_audit(audit_id)
    if not a:
        raise HTTPException(404, "Audit introuvable.")
    return a


@app.get("/api/audits/{audit_id}/rapport.md")
def rapport_markdown(audit_id: int, request: Request):
    verifier_session(request)
    a = registry.obtenir_audit(audit_id)
    if not a:
        raise HTTPException(404, "Audit introuvable.")
    return PlainTextResponse(a["rapport"] or "", media_type="text/markdown",
                             headers={"Content-Disposition": f'attachment; filename="rapport_audit_{audit_id}.md"'})


@app.get("/api/alertes")
def alertes(request: Request):
    verifier_session(request)
    return registry.lister_alertes()


# ---------------------------------------------------------------------------
# État et test des connecteurs (Gmail, Drive, GitHub) — aucun e-mail envoyé par les tests
# ---------------------------------------------------------------------------
@app.get("/api/connecteurs")
def etat_connecteurs(request: Request):
    verifier_session(request)
    return connecteurs.etat_connecteurs()


@app.get("/api/fonctionnalites")
async def etat_fonctionnalites(request: Request):
    verifier_session(request)
    return await asyncio.to_thread(fonctionnalites.etat)


@app.post("/api/fonctionnalites/{id_}/tester")
async def tester_fonctionnalite(id_: str, request: Request):
    """Test réel d'une fonctionnalité, SANS appel au LLM (aucun quota consommé)."""
    verifier_session(request)
    if id_ not in fonctionnalites.TESTS:
        raise HTTPException(404, "Fonctionnalité inconnue.")
    return await asyncio.to_thread(fonctionnalites.tester, id_)


@app.get("/api/knowledge")
def recherche_knowledge(request: Request, q: str = ""):
    verifier_session(request)
    if not q.strip():
        raise HTTPException(400, "Saisissez une recherche.")
    return fonctionnalites.rechercher_knowledge(q[:200], 3)


@app.post("/api/connecteurs/{nom}/tester")
async def tester_connecteur(nom: str, request: Request):
    verifier_session(request)
    if nom not in connecteurs.TESTS:
        raise HTTPException(404, "Connecteur inconnu.")
    return await asyncio.to_thread(connecteurs.tester, nom)

"""Connecteurs déclenchés par le BACKEND après chaque audit (déterministes, sans LLM).

Ordre : audit -> enregistrement local (SQLite) -> archivage Google Drive -> e-mail (avec le lien Drive).
- Un échec Drive n'empêche pas l'e-mail (envoyé sans lien, avec un avertissement).
- Un échec Gmail ne remet pas en cause l'audit (déjà enregistré).
- Chaque envoi est journalisé (succès ou échec, avec le message d'erreur).

Google Drive : OAuth2 « Application de bureau », scope drive.file UNIQUEMENT (l'application ne voit
que les fichiers qu'elle a créés). token.json est créé une fois par « python -m backend.autoriser_drive ».
"""
from __future__ import annotations

import json
import os
import re
import smtplib
import ssl
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

from backend.agent import envoyer_email  # connecteur Gmail SMTP existant
from mcp_server import analyzers as az
from mcp_server import registry

ROOT = Path(__file__).resolve().parent.parent
SCOPES = ["https://www.googleapis.com/auth/drive.file"]
MIME_DOSSIER = "application/vnd.google-apps.folder"
MIME_GDOC = "application/vnd.google-apps.document"
ICONES = {"INSTALLER": "✅", "CORRIGER": "⚠️", "REJETER": "🚨"}
ORDRE_GRAVITE = {"critique": 0, "eleve": 1, "moyen": 2, "faible": 3, "info": 4}
LIBELLES_GRAVITE = {"critique": "Critique", "eleve": "Élevée", "moyen": "Moyenne", "faible": "Faible", "info": "Info"}


# ---------------------------------------------------------------------------
# Outils communs
# ---------------------------------------------------------------------------
def _chemin_env(variable: str, defaut: str) -> Path:
    p = Path(os.getenv(variable) or defaut)
    return p if p.is_absolute() else ROOT / p


def chemin_credentials() -> Path:
    return _chemin_env("DRIVE_CREDENTIALS", "credentials.json")


def chemin_token() -> Path:
    return _chemin_env("DRIVE_TOKEN", "token.json")


def _court(e: Exception) -> str:
    return f"{type(e).__name__} : {str(e)[:300]}"


def masquer_secrets(texte: str) -> str:
    """Second filet de sécurité : masque tout secret encore présent dans un texte sortant (Drive, e-mail)."""
    for _nom, motif in az.MOTIFS_SECRETS:
        texte = re.sub(motif, lambda m: az._masquer(m.group(0)), texte)
    return texte


def _nom_fichier(sur: str) -> str:
    return re.sub(r"[^\w.-]", "-", sur).strip("-")[:80] or "element"


# ---------------------------------------------------------------------------
# Google Drive
# ---------------------------------------------------------------------------
_cache_dossiers: dict[str, str] = {}


def drive_configure() -> bool:
    return chemin_credentials().exists() and chemin_token().exists()


def service_drive():
    """Client Drive authentifié (le jeton est rafraîchi automatiquement s'il a expiré)."""
    import google_auth_httplib2
    import httplib2
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from googleapiclient.discovery import build

    jeton = chemin_token()
    if not jeton.exists():
        raise RuntimeError("token.json absent : lancez « python -m backend.autoriser_drive ».")
    creds = Credentials.from_authorized_user_file(str(jeton), SCOPES)
    if not creds.valid:
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
            jeton.write_text(creds.to_json(), encoding="utf-8")
        else:
            raise RuntimeError("Jeton Drive invalide : relancez « python -m backend.autoriser_drive ».")
    http = google_auth_httplib2.AuthorizedHttp(creds, http=httplib2.Http(timeout=30))
    return build("drive", "v3", http=http, cache_discovery=False)


def _dossier(service, nom: str, parent: str) -> str:
    """Retrouve (ou crée) un dossier par son nom sous un parent. Avec drive.file, seuls les
    dossiers créés par MCP-Guard sont visibles : aucun accès au reste du Drive."""
    cle = f"{parent}/{nom}"
    if cle in _cache_dossiers:
        return _cache_dossiers[cle]
    nom_q = nom.replace("\\", "\\\\").replace("'", "\\'")
    requete = f"name = '{nom_q}' and mimeType = '{MIME_DOSSIER}' and '{parent}' in parents and trashed = false"
    trouves = service.files().list(q=requete, spaces="drive", fields="files(id)", pageSize=1).execute()["files"]
    if trouves:
        id_ = trouves[0]["id"]
    else:
        id_ = service.files().create(body={"name": nom, "mimeType": MIME_DOSSIER, "parents": [parent]},
                                     fields="id").execute()["id"]
    _cache_dossiers[cle] = id_
    return id_


def dossier_racine(service) -> str:
    return _dossier(service, os.getenv("DRIVE_DOSSIER_RACINE") or "MCP-Guard", "root")


def televerser_markdown(service, parent: str, nom: str, texte: str, convertir: bool = True) -> dict:
    """Envoie un texte Markdown ; avec convertir=True, Drive le convertit en Google Docs (mise en forme)."""
    from googleapiclient.http import MediaInMemoryUpload

    media = MediaInMemoryUpload(texte.encode("utf-8"), mimetype="text/markdown", resumable=False)
    corps = {"name": nom if convertir else nom + ".md", "parents": [parent]}
    if convertir:
        corps["mimeType"] = MIME_GDOC
    return service.files().create(body=corps, media_body=media, fields="id, name, webViewLink").execute()


def archiver_rapport(nom: str, markdown: str, quand: datetime) -> dict:
    """Range le rapport dans MCP-Guard/Rapports/AAAA-MM/ (dossiers créés au besoin)."""
    from googleapiclient.errors import HttpError

    service = service_drive()

    def _envoyer() -> dict:
        parent = _dossier(service, quand.strftime("%Y-%m"), _dossier(service, "Rapports", dossier_racine(service)))
        try:
            return {**televerser_markdown(service, parent, nom, markdown, convertir=True), "format": "Google Docs"}
        except HttpError as e:
            if e.resp.status != 400:
                raise
            # Conversion refusée par Drive : on archive le Markdown brut plutôt que de ne rien archiver.
            return {**televerser_markdown(service, parent, nom, markdown, convertir=False), "format": "Markdown"}

    try:
        return _envoyer()
    except HttpError as e:
        if e.resp.status != 404:
            raise
        _cache_dossiers.clear()  # un dossier mémorisé a été supprimé dans Drive : on le recrée
        return _envoyer()


# ---------------------------------------------------------------------------
# Contenu du rapport archivé et de l'e-mail
# ---------------------------------------------------------------------------
def decrire_source(chemin: str) -> str:
    if chemin.startswith("samples/"):
        return "Échantillon de démonstration (samples/)"
    if chemin.startswith("uploads/installes/"):
        return "Copie installée d'un serveur approuvé (uploads/installes/)"
    source = registry.obtenir_source("/".join(chemin.split("/")[:2]))
    if source and source["type"] == "github":
        commit = f" — commit {source['commit_sha'][:12]}" if source.get("commit_sha") else " — commit inconnu"
        return f"Import GitHub : {source['url']}{commit}"
    if source and source["type"] == "dépôt":
        return "Dépôt manuel de fichiers (interface web)"
    return "Dossier uploads/ (origine non enregistrée)"


def constats_principaux(donnees: dict, nombre: int = 3) -> list[dict]:
    return sorted(donnees.get("constats", []),
                  key=lambda c: (ORDRE_GRAVITE.get(c["gravite"], 9), -c.get("points", 0)))[:nombre]


def rapport_de_secours(chemin: str, donnees: dict) -> str:
    """Rapport déterministe utilisé si l'agent n'a pas pu rédiger le sien (quota, erreur…)."""
    lignes = [f"# Rapport d'audit MCP-Guard — {Path(chemin).name}", "",
              "_Rapport généré automatiquement par le backend (l'agent n'a pas pu rédiger le rapport)._", "",
              f"- **Score** : {donnees['score']}/100", f"- **Niveau** : {donnees.get('niveau', '-')}",
              f"- **Verdict** : {donnees['verdict']}", "",
              "| Gravité | OWASP | Tool | Constat | Preuve |", "|---|---|---|---|---|"]
    for c in donnees.get("constats", []):
        lignes.append(f"| {LIBELLES_GRAVITE.get(c['gravite'], c['gravite'])} | {c['owasp']} | {c.get('tool') or '-'} "
                      f"| {c['titre']} | `{(c.get('preuve') or '').replace('|', '/')}` |")
    if not donnees.get("constats"):
        lignes.append("| – | – | – | Aucun constat | – |")
    return "\n".join(lignes)


def construire_sujet(nom: str, verdict: str, score: int) -> str:
    return f"[MCP-Guard] {ICONES.get(verdict, '')} {verdict} – {nom} – score {score}/100"


def construire_corps(audit_id: int, chemin: str, donnees: dict, quand: datetime, drive: dict) -> str:
    lignes = [
        f"Rapport d'audit MCP-Guard n° {audit_id}",
        "",
        f"Élément audité : {chemin}",
        f"Type           : {(donnees.get('type') or '').replace('_', ' ')}",
        f"Source         : {decrire_source(chemin)}",
        f"Date           : {quand:%d/%m/%Y %H:%M}",
        f"Score          : {donnees['score']}/100",
        f"Niveau         : {donnees.get('niveau', '-')}",
        f"Verdict        : {ICONES.get(donnees['verdict'], '')} {donnees['verdict']}",
        "",
    ]
    principaux = constats_principaux(donnees)
    if principaux:
        lignes.append(f"Les {len(principaux)} constats les plus graves (sur {len(donnees['constats'])}) :")
        for i, c in enumerate(principaux, 1):
            ou = f" — tool {c['tool']}" if c.get("tool") else ""
            ou += f", ligne {c['ligne']}" if c.get("ligne") else ""
            lignes.append(f"  {i}. [{LIBELLES_GRAVITE.get(c['gravite'], c['gravite'])}] {c['owasp']} – {c['titre']}{ou}")
            if c.get("preuve"):
                lignes.append(f"     Preuve : {c['preuve']}")
    else:
        lignes.append("Aucun constat : aucune faille détectée par l'analyse statique.")
    lignes.append("")
    if drive.get("lien"):
        lignes.append(f"Rapport complet (Google Drive) : {drive['lien']}")
    else:
        raison = drive.get("message") or drive.get("statut", "inconnu")
        lignes.append(f"⚠️ Archivage Google Drive indisponible ({raison}).")
        lignes.append(f"   Le rapport reste consultable dans l'interface MCP-Guard (audit n° {audit_id}).")
    lignes += ["", "--", "Message automatique envoyé par le backend MCP-Guard après l'audit (sans LLM).",
               "Analyse statique : le code audité n'a jamais été exécuté."]
    return masquer_secrets("\n".join(lignes))


# ---------------------------------------------------------------------------
# Traitement après chaque audit
# ---------------------------------------------------------------------------
def apres_audit(audit_id: int, chemin: str, donnees: dict, rapport: str, erreur_agent: bool = False) -> dict:
    quand = datetime.now()
    nom = Path(chemin).name
    verdict = donnees["verdict"]

    # 1. Archivage Google Drive
    drive: dict = {"statut": "désactivé", "lien": None}
    if os.getenv("DRIVE_ACTIVE", "1") != "0":
        if not drive_configure():
            drive = {"statut": "non configuré", "lien": None,
                     "message": "credentials.json ou token.json absent"}
        else:
            corps_rapport = rapport if (rapport and not erreur_agent) else rapport_de_secours(chemin, donnees)
            entete = (f"> Audit n° {audit_id} · {quand:%d/%m/%Y %H:%M} · {chemin} · "
                      f"source : {decrire_source(chemin)}\n\n")
            try:
                f = archiver_rapport(f"{quand:%Y-%m-%d_%Hh%M}_{_nom_fichier(nom)}_{verdict}",
                                     masquer_secrets(entete + corps_rapport), quand)
                drive = {"statut": "ok", "lien": f["webViewLink"], "nom": f["name"], "format": f["format"]}
            except Exception as e:
                drive = {"statut": "erreur", "lien": None, "message": _court(e)}
        registry.journaliser("drive_envoi", {"audit_id": audit_id, "ok": drive["statut"] == "ok",
                                             **{k: v for k, v in drive.items() if k != "statut"},
                                             "statut": drive["statut"]})

    # 2. Notification e-mail (part même si Drive a échoué)
    email: dict = {"statut": "désactivé"}
    if os.getenv("NOTIFICATION_CHAQUE_AUDIT", "1") != "0":
        try:
            r = envoyer_email(construire_sujet(nom, verdict, donnees["score"]),
                              construire_corps(audit_id, chemin, donnees, quand, drive))
            email = {"statut": "ok" if r.get("envoye") else "démonstration", **r}
        except Exception as e:  # SMTP, réseau, authentification : l'audit reste valide
            email = {"statut": "erreur", "message": _court(e)}
        registry.journaliser("email_envoi", {"audit_id": audit_id, "ok": email["statut"] in ("ok", "démonstration"),
                                             **email})

    def _resume(d: dict) -> str:
        return d["statut"] + (f" : {d['message']}" if d.get("message") else "")

    registry.maj_envois_audit(audit_id, drive.get("lien"), _resume(drive), _resume(email))
    return {"drive": drive, "email": email}


# ---------------------------------------------------------------------------
# État et tests des connecteurs (aucun envoi d'e-mail, aucun fichier laissé dans Drive)
# ---------------------------------------------------------------------------
def gmail_configure() -> bool:
    return all(os.getenv(k) for k in ("SMTP_UTILISATEUR", "SMTP_MOT_DE_PASSE", "ALERTE_DESTINATAIRE"))


def tester_gmail() -> str:
    """Connexion + authentification SMTP, puis déconnexion : aucun e-mail n'est envoyé."""
    if not gmail_configure():
        raise RuntimeError("SMTP_UTILISATEUR, SMTP_MOT_DE_PASSE ou ALERTE_DESTINATAIRE vide dans .env")
    hote, port = os.getenv("SMTP_HOTE", "smtp.gmail.com"), int(os.getenv("SMTP_PORT", "465"))
    with smtplib.SMTP_SSL(hote, port, timeout=20, context=ssl.create_default_context()) as smtp:
        smtp.login(os.environ["SMTP_UTILISATEUR"], os.environ["SMTP_MOT_DE_PASSE"])
    return f"Authentification SMTP réussie sur {hote}:{port} (aucun e-mail envoyé)"


def tester_drive() -> str:
    """Test réel aller-retour : crée un document de test dans MCP-Guard/, le relit, puis le supprime."""
    if not drive_configure():
        raise RuntimeError("credentials.json ou token.json absent")
    service = service_drive()
    racine = dossier_racine(service)
    f = televerser_markdown(service, racine, f"test_mcp-guard_{datetime.now():%Y%m%d_%H%M%S}",
                            "# Test MCP-Guard\n\nFichier de test créé puis supprimé automatiquement.")
    try:
        relu = service.files().get(fileId=f["id"], fields="id, mimeType").execute()
    finally:
        service.files().delete(fileId=f["id"]).execute()
    return (f"Écriture Drive OK : document de test créé ({relu['mimeType'].split('.')[-1]}), relu puis supprimé "
            f"dans le dossier « {os.getenv('DRIVE_DOSSIER_RACINE') or 'MCP-Guard'} »")


def entetes_github() -> dict:
    entetes = {"Accept": "application/vnd.github+json", "User-Agent": "mcp-guard"}
    if os.getenv("GITHUB_TOKEN"):
        entetes["Authorization"] = f"Bearer {os.getenv('GITHUB_TOKEN')}"
    return entetes


def tester_github() -> str:
    mode = "avec GITHUB_TOKEN" if os.getenv("GITHUB_TOKEN") else "anonyme (sans jeton)"
    try:
        with urllib.request.urlopen(urllib.request.Request("https://api.github.com/rate_limit",
                                                           headers=entetes_github()), timeout=20) as r:
            core = json.loads(r.read())["resources"]["core"]
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise RuntimeError("GITHUB_TOKEN invalide ou expiré") from None
        raise
    if core["remaining"] == 0:
        fin = datetime.fromtimestamp(core["reset"]).strftime("%H:%M")
        raise RuntimeError(f"quota API épuisé (0/{core['limit']}, {mode}) jusqu'à {fin}")
    return f"API GitHub joignable, {mode} : quota restant {core['remaining']}/{core['limit']} requêtes/h"


TESTS = {"gmail": tester_gmail, "drive": tester_drive, "github": tester_github}
USAGES = {"gmail": ["email_envoi"], "drive": ["drive_envoi"], "github": ["import_github", "import_github_echec"]}


def tester(nom: str) -> dict:
    try:
        resultat = {"connecteur": nom, "ok": True, "message": TESTS[nom]()}
    except Exception as e:
        resultat = {"connecteur": nom, "ok": False, "message": _court(e)}
    registry.journaliser("test_connecteur", resultat)
    return resultat


def etat_connecteurs() -> dict:
    configures = {"gmail": gmail_configure(), "drive": drive_configure(), "github": True}
    details = {"gmail": "SMTP " + os.getenv("SMTP_HOTE", "smtp.gmail.com"),
               "drive": "scope drive.file",
               "github": "avec jeton" if os.getenv("GITHUB_TOKEN") else "anonyme (60 requêtes/h)"}
    etat = {}
    for nom in TESTS:
        evenements = [registry.dernier_evenement("test_connecteur", f'"connecteur": "{nom}"')]
        for ev in USAGES[nom]:
            e = registry.dernier_evenement(ev)
            if e is not None and "ok" not in e:
                e["ok"] = ev != "import_github_echec"
            evenements.append(e)
        dernier = max((e for e in evenements if e), key=lambda e: e["date"], default=None)
        if not configures[nom]:
            statut = "non configuré"
        elif dernier is None:
            statut = "configuré"
        else:
            statut = "ok" if dernier.get("ok") else "erreur"
        etat[nom] = {"configure": configures[nom], "statut": statut, "detail": details[nom],
                     "dernier": {"date": dernier["date"], "ok": dernier.get("ok"),
                                 "message": dernier.get("message") or dernier.get("lien") or ""} if dernier else None}
    return etat

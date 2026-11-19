"""Onglet « Fonctionnalités » : état en direct et tests RÉELS des 9 fonctionnalités de l'énoncé.

Aucun test n'appelle le LLM (aucun quota consommé) :
- skills, plugins et MCP : Claude Code est démarré via l'Agent SDK puis interrogé en phase
  « initialize » uniquement (aucun message n'est envoyé au modèle) ;
- tools : vrai client MCP (tools/list + appel en lecture seule sur samples/01_serveur_sain) ;
- connecteurs : API GitHub en lecture, connexion SMTP sans envoi, fichier Drive créé puis supprimé ;
- plugin OSV : vraie requête à l'API OSV.dev.
Chaque résultat est journalisé (événement « test_fonctionnalite ») et affiché dans l'interface.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import re
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from backend import agent, connecteurs
from mcp_server import analyzers as az
from mcp_server import registry

ROOT = Path(__file__).resolve().parents[2]
SERVEUR_MCP = ROOT / "mcp_server" / "server.py"
ECHANTILLON = "samples/01_serveur_sain"

DEFINITIONS = [
    {"id": "instructions", "numero": 1, "nom": "Instructions (System Prompt)",
     "definition": "Règles de comportement claires et contraintes de l'agent.",
     "justification": "Fixe le rôle d'auditeur, les règles numérotées et les contraintes de sécurité : jamais "
                      "d'exécution du code audité, une preuve pour chaque constat, "
                      "périmètre limité à samples/ et uploads/."},
    {"id": "skills", "numero": 2, "nom": "Skills (Compétences)",
     "definition": "Capacités spécifiques définies (ex : savoir analyser un fichier JSON).",
     "justification": "Trois savoir-faire packagés : la méthode et le format du rapport d'audit, l'analyse d'un "
                      "fichier SKILL.md et l'analyse d'un fichier JSON MCP (l'exemple de l'énoncé). Claude les charge "
                      "à la demande pendant les audits."},
    {"id": "tools", "numero": 3, "nom": "Outils (Tools)",
     "definition": "Fonctions exécutables (ex : appel API, requête SQL, script Python).",
     "justification": "Fonctions Python d'analyse statique (AST et regex), de calcul d'empreinte, de requêtes SQL "
                      "et d'appels API, exposées à l'agent par le serveur MCP."},
    {"id": "connecteurs", "numero": 4, "nom": "Connecteurs",
     "definition": "Liaison avec des services externes (Slack, Teams, GitHub, ServiceNow).",
     "justification": "GitHub (import d'un dépôt à auditer), Google Drive (archivage de chaque rapport) et Gmail "
                      "(notification après chaque audit), déclenchés par le backend de façon déterministe."},
    {"id": "plugins", "numero": 5, "nom": "Plugins",
     "definition": "Extensions préconçues ajoutant des capacités "
                   "(ex : plugin de recherche web, plugin d'analyse de données).",
     "justification": "Deux plugins Claude Code : « mcp-guard » (skills d'audit) et « osv-scanner », qui ajoute son "
                      "propre serveur MCP pour vérifier les dépendances auprès de la base de vulnérabilités OSV.dev."},
    {"id": "mcp", "numero": 6, "nom": "MCP (Model Context Protocol)",
     "definition": "Bonus majeur. Utilisation de MCP pour connecter l'agent de manière standardisée et sécurisée "
                   "à des sources de données locales ou distantes.",
     "justification": "Trois serveurs MCP : stdio local (analyse et mémoire), in-process (e-mail) et celui du plugin "
                      "(OSV.dev, distant). L'agent n'a accès qu'à ces tools et à Skill : ni Bash, ni Read, ni Write."},
    {"id": "knowledge", "numero": 7, "nom": "Connaissances (Knowledge Base)",
     "definition": "Base de données vectorielle (RAG) ou documents uploadés (ex : politique de sécurité de "
                   "l'entreprise, documentation technique).",
     "justification": "Documents de référence (OWASP MCP Top 10, grille de scoring, politique d'approbation) "
                      "consultés par le tool rechercher_knowledge pour justifier chaque remédiation."},
    {"id": "memoire", "numero": 8, "nom": "Mémoire",
     "definition": "Gestion de la mémoire à court terme (contexte de conversation) et à long terme (persistance "
                   "des préférences utilisateur ou historique des actions).",
     "justification": "Court terme : reprise de la conversation liée à un audit. Long terme : SQLite (audits, "
                      "serveurs approuvés et empreintes, alertes, journal, préférences), consultable par l'agent."},
    {"id": "authentification", "numero": 9, "nom": "Authentification",
     "definition": "Mécanisme sécurisé pour que l'agent accède aux ressources "
                   "(OAuth2, Clés API, ou Microsoft Entra ID).",
     "justification": "OAuth du compte Claude, OAuth2 Google Drive, mot de passe d'application Gmail, jeton GitHub et "
                      "mot de passe de l'interface. Tous les secrets sont hors du code et jamais affichés."},
    {"id": "bonus", "numero": 0, "nom": "Bonus : tâche planifiée",
     "definition": "Hors liste : automatisation sans intervention humaine.",
     "justification": "Ré-audit périodique des serveurs approuvés (comparaison d'empreintes, sans LLM) : détecte un "
                      "« rug pull », suspend l'approbation et alerte."},
]
IDS = [d["id"] for d in DEFINITIONS]

_planificateur = None
_reaudit = None
_verrou_sdk = threading.Lock()
_cache_sdk: dict = {"t": 0.0, "donnees": None}


def configurer(planificateur, reaudit) -> None:
    """Le backend fournit son planificateur et sa fonction de ré-audit (carte Bonus)."""
    global _planificateur, _reaudit
    _planificateur, _reaudit = planificateur, reaudit


def _boucle(coroutine):
    boucle = asyncio.ProactorEventLoop() if sys.platform == "win32" else asyncio.new_event_loop()
    try:
        return boucle.run_until_complete(coroutine)
    finally:
        boucle.close()


# ---------------------------------------------------------------------------
# Sondes réelles (sans LLM)
# ---------------------------------------------------------------------------
def inspection_sdk(force: bool = False) -> dict:
    """Démarre Claude Code avec la configuration de l'agent, phase « initialize » seulement (aucun message au
    modèle, donc aucun quota), et relève skills, serveurs MCP et tools. Résultat gardé 2 minutes."""
    from claude_agent_sdk import ClaudeSDKClient

    with _verrou_sdk:
        if not force and _cache_sdk["donnees"] and time.time() - _cache_sdk["t"] < 120:
            return _cache_sdk["donnees"]

        async def _sonder() -> dict:
            async with ClaudeSDKClient(options=agent.options_agent()) as client:
                info = await client.get_server_info() or {}
                serveurs: list = []
                for _ in range(40):
                    etat = await client.get_mcp_status()
                    serveurs = [s if isinstance(s, dict) else vars(s) for s in etat.get("mcpServers", [])]
                    if serveurs and all(s.get("status") != "pending" for s in serveurs):
                        break
                    await asyncio.sleep(0.5)
                return {
                    "version_cli": info.get("claude_code_version"),
                    "mode_permission": info.get("current_permission_mode"),
                    "skills": sorted(c["name"] for c in info.get("commands", []) if ":" in c.get("name", "")),
                    "serveurs": [{"nom": s.get("name"), "statut": s.get("status"), "erreur": s.get("error"),
                                  "tools": [t.get("name") if isinstance(t, dict) else getattr(t, "name", str(t))
                                            for t in (s.get("tools") or [])]} for s in serveurs],
                }

        donnees = _boucle(_sonder())
        _cache_sdk.update(t=time.time(), donnees=donnees)
        return donnees


def commande_cli() -> list[str]:
    """Commande exacte que l'Agent SDK passe à Claude Code (construite sans être lancée)."""
    from claude_agent_sdk._internal.transport.subprocess_cli import SubprocessCLITransport

    transport = SubprocessCLITransport(prompt="", options=agent.options_agent())
    transport._cli_path = transport._find_cli()
    return transport._build_command()


def _valeur(cmd: list[str], drapeau: str) -> str | None:
    if drapeau in cmd:
        return cmd[cmd.index(drapeau) + 1]
    return next((c.split("=", 1)[1] for c in cmd if c.startswith(drapeau + "=")), None)


def client_mcp(appels: list[tuple[str, dict]]) -> dict:
    """Vrai client MCP stdio : tools/list puis appels en lecture seule."""
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    async def _client() -> dict:
        params = StdioServerParameters(command=sys.executable, args=[str(SERVEUR_MCP)], cwd=str(ROOT))
        async with stdio_client(params) as (lecture, ecriture), ClientSession(lecture, ecriture) as session:
            await session.initialize()
            tools = (await session.list_tools()).tools
            resultats = {}
            for nom, args in appels:
                r = await session.call_tool(nom, args)
                texte = "".join(c.text for c in r.content if hasattr(c, "text"))
                resultats[nom] = {"erreur": r.is_error, "donnees": r.structured_content or _json(texte)}
            return {"tools": [{"nom": t.name, "description": (t.description or "").strip().splitlines()[0]}
                              for t in tools], "appels": resultats}

    return _boucle(_client())


def _json(texte: str):
    try:
        return json.loads(texte)
    except ValueError:
        return texte


def _module_osv():
    spec = importlib.util.spec_from_file_location("serveur_osv", ROOT / "plugin" / "osv-scanner" / "serveur_osv.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# Données affichées (rapides, sans démarrer Claude Code)
# ---------------------------------------------------------------------------
def _regles() -> list[str]:
    texte = (ROOT / "backend" / "instructions.md").read_text(encoding="utf-8")
    return [re.sub(r"\*\*", "", m.group(2)).strip(" :") for m in re.finditer(r"^(\d+)\.\s+\*\*(.+?)\*\*", texte, re.M)]


def _skills_declarees() -> list[dict]:
    resultat = []
    for f in sorted((ROOT / "plugin").glob("*/skills/*/SKILL.md")):
        entete = re.search(r"^---\s*\n(.*?)\n---", f.read_text(encoding="utf-8"), re.S)
        champs = dict(re.findall(r"^(\w+):\s*(.+)$", entete.group(1), re.M)) if entete else {}
        resultat.append({"nom": f"{f.parents[2].name}:{champs.get('name', f.parent.name)}",
                         "description": champs.get("description", "")[:220], "fichier": f.relative_to(ROOT).as_posix()})
    return resultat


def _plugins() -> list[dict]:
    resultat = []
    for manifeste in sorted((ROOT / "plugin").glob("*/.claude-plugin/plugin.json")):
        racine = manifeste.parents[1]
        info = json.loads(manifeste.read_text(encoding="utf-8"))
        mcp = racine / ".mcp.json"
        resultat.append({"nom": info["name"], "version": info.get("version"), "description": info.get("description"),
                         "skills": sorted(p.parent.name for p in racine.glob("skills/*/SKILL.md")),
                         "serveurs_mcp": sorted(json.loads(mcp.read_text(encoding="utf-8"))["mcpServers"])
                                         if mcp.exists() else []})
    return resultat


def _tools_statiques() -> list[str]:
    return re.findall(r"@serveur\.tool\(\)\s*\ndef (\w+)", SERVEUR_MCP.read_text(encoding="utf-8"))


def _documents() -> list[dict]:
    docs = []
    for f in sorted((ROOT / "knowledge").glob("*.md")):
        texte = f.read_text(encoding="utf-8")
        docs.append({"fichier": f.name, "titre": texte.strip().splitlines()[0].lstrip("# ").strip(),
                     "lignes": texte.count("\n") + 1, "sections": len(re.findall(r"^##\s", texte, re.M))})
    return docs


def rechercher_knowledge(question: str, nombre: int = 3) -> list[dict]:
    from mcp_server.server import rechercher_knowledge as rechercher
    return [{**r, "texte": r["texte"][:500]} for r in rechercher(question, nombre)]


def _mecanismes_auth() -> list[dict]:
    defini = lambda k: "défini" if os.getenv(k) else "vide"  # noqa: E731
    jeton = connecteurs.chemin_token()
    return [
        {"nom": "Compte Claude (OAuth via Claude Code)", "type": "OAuth",
         "stockage": "identifiants Claude Code (hors projet)",
         "etat": "vérifié au test"},
        {"nom": "Google Drive (OAuth2, ID client « Application de bureau »)", "type": "OAuth2",
         "stockage": "credentials.json + token.json",
         "etat": "défini" if connecteurs.drive_configure()
          else ("credentials.json seul" if connecteurs.chemin_credentials().exists() else "vide"),
         "portee": "drive.file uniquement" if jeton.exists() else None},
        {"nom": "Gmail (mot de passe d'application)", "type": "Secret applicatif",
         "stockage": ".env (SMTP_MOT_DE_PASSE)",
         "etat": defini("SMTP_MOT_DE_PASSE")},
        {"nom": "GitHub (jeton d'accès personnel)", "type": "Clé API", "stockage": ".env (GITHUB_TOKEN)",
         "etat": defini("GITHUB_TOKEN") if os.getenv("GITHUB_TOKEN") else "vide (mode anonyme, 60 requêtes/h)"},
        {"nom": "Interface web (mot de passe + cookie de session)", "type": "Mot de passe",
         "stockage": ".env (MCPGUARD_MOT_DE_PASSE)",
         "etat": defini("MCPGUARD_MOT_DE_PASSE")},
    ]


def donnees(id_: str) -> dict:
    if id_ == "instructions":
        regles = _regles()
        return {"fichier": "backend/instructions.md", "nombre_regles": len(regles), "regles": regles,
                "caracteres": len(agent.instructions_agent()), "preferences_injectees": True}
    if id_ == "skills":
        return {"declarees": _skills_declarees(), "activees": agent.SKILLS}
    if id_ == "tools":
        return {"serveur": "mcp_server/server.py", "tools": _tools_statiques()}
    if id_ == "connecteurs":
        return connecteurs.etat_connecteurs()
    if id_ == "plugins":
        return {"plugins": _plugins()}
    if id_ == "mcp":
        return {"serveurs": [
            {"nom": "mcp-guard", "transport": "stdio (local)", "fichier": "mcp_server/server.py"},
            {"nom": "connecteurs", "transport": "in-process (SDK)", "fichier": "backend/agent.py"},
            {"nom": "plugin:osv-scanner:osv", "transport": "stdio, fourni par le plugin (API distante OSV.dev)",
             "fichier": "plugin/osv-scanner/serveur_osv.py"}],
            "outils_autorises": len(agent.OUTILS_AUTORISES)}
    if id_ == "knowledge":
        return {"documents": _documents()}
    if id_ == "memoire":
        return {"tables": registry.compter_tables(), "preferences": {**registry.lire_preferences(),
                "email_notification": "personnalisée" if registry.lire_preferences()["email_notification"]
                 else "celle du .env"},
                "sessions": registry.lister_sessions(5)}
    if id_ == "authentification":
        return {"mecanismes": _mecanismes_auth()}
    if id_ == "bonus":
        job = _planificateur.get_job("reaudit") if _planificateur else None
        return {"declencheur": str(job.trigger) if job else None,
                "prochaine_execution": str(job.next_run_time).split(".")[0] if job else None,
                "executions": registry.compter_evenements("reaudit_planifie"),
                "serveurs_surveilles": len(registry.lister_approuves())}
    raise KeyError(id_)


# ---------------------------------------------------------------------------
# Tests réels (sans LLM)
# ---------------------------------------------------------------------------
def _ok(message: str, **details) -> dict:
    return {"ok": True, "statut": "ok", "message": message, "details": details}


def _ko(message: str, statut: str = "erreur", **details) -> dict:
    return {"ok": False, "statut": statut, "message": message, "details": details}


def tester_instructions() -> dict:
    cmd = commande_cli()
    prompt = _valeur(cmd, "--system-prompt")
    attendu = agent.instructions_agent()
    regles = _regles()
    contraintes = {"aucune exécution": "Aucune exécution" in attendu, "preuve obligatoire": "preuve" in attendu,
                   "périmètre samples/ uploads/": "samples/" in attendu and "uploads/" in attendu}
    if prompt != attendu:
        return _ko("Le system prompt transmis à Claude Code diffère de instructions.md")
    if not all(contraintes.values()):
        return _ko(f"Contrainte absente : {[k for k, v in contraintes.items() if not v]}")
    return _ok(f"System prompt transmis à Claude Code ({len(prompt)} caractères, {len(regles)} règles numérotées, "
               "préférences incluses)", contraintes=contraintes)


def tester_skills() -> dict:
    sdk = inspection_sdk(force=True)
    manquantes = [s for s in agent.SKILLS if s not in sdk["skills"]]
    if manquantes:
        return _ko(f"Skills non chargées par Claude Code : {manquantes}", chargees=sdk["skills"])
    return _ok(f"{len(agent.SKILLS)} skills chargées par Claude Code {sdk['version_cli']} "
               "(initialize, sans appel au modèle)",
               chargees=sdk["skills"])


def tester_tools() -> dict:
    r = client_mcp([("lister_elements_disponibles", {}), ("audit_complet", {"chemin": ECHANTILLON}),
                    ("rechercher_knowledge", {"question": "tool poisoning", "nombre": 1})])
    audit = r["appels"]["audit_complet"]
    verdict = audit["donnees"].get("verdict") if isinstance(audit["donnees"], dict) else None
    if any(a["erreur"] for a in r["appels"].values()) or verdict != "INSTALLER":
        return _ko("Un appel de tool a échoué", tools=r["tools"])
    return _ok(f"tools/list : {len(r['tools'])} tools ; audit_complet({ECHANTILLON}) → score "
               f"{audit['donnees']['score']}, {verdict}", tools=r["tools"])


def tester_connecteurs() -> dict:
    resultats = {nom: connecteurs.tester(nom) for nom in connecteurs.TESTS}
    non_config = [n for n, c in connecteurs.etat_connecteurs().items() if not c["configure"]]
    resume = " · ".join(f"{n} {'✓' if r['ok'] else '✗'}" for n, r in resultats.items())
    if all(r["ok"] for r in resultats.values()):
        return _ok(f"3/3 connecteurs testés : {resume}", resultats=resultats)
    return _ko(f"{resume}", "non configuré" if non_config else "erreur", resultats=resultats)


def tester_plugins() -> dict:
    sdk = inspection_sdk()
    osv = next((s for s in sdk["serveurs"] if s["nom"] == "plugin:osv-scanner:osv"), None)
    if not osv or osv["statut"] != "connected":
        return _ko("Le serveur MCP du plugin osv-scanner n'est pas connecté")
    if not any(s.startswith("mcp-guard:") for s in sdk["skills"]):
        return _ko("Les skills du plugin mcp-guard ne sont pas chargées")
    module = _module_osv()
    deps = module.extraire_dependances(az.chemin_sur(ECHANTILLON))
    analyse = module.interroger_osv(deps)
    vulnerables = sum(1 for d in analyse if d["vulnerabilites"])
    return _ok(f"2 plugins chargés ; requête OSV.dev réelle sur {ECHANTILLON} : {len(analyse)} dépendances, "
               f"{vulnerables} avec des vulnérabilités connues",
               dependances=[{k: d[k] for k in ("paquet", "version", "vulnerabilites")} for d in analyse])


def tester_mcp() -> dict:
    sdk = inspection_sdk()
    cmd = commande_cli()
    serveurs = {s["nom"]: s for s in sdk["serveurs"]}
    attendus = ["mcp-guard", "connecteurs", "plugin:osv-scanner:osv"]
    absents = [n for n in attendus if serveurs.get(n, {}).get("statut") != "connected"]
    intrus = [n for n in serveurs if n not in attendus]
    outils_natifs = (_valeur(cmd, "--tools") or "").split(",")
    if absents:
        return _ko(f"Serveurs MCP non connectés : {absents}")
    if intrus or outils_natifs != ["Skill"] or sdk["mode_permission"] != "dontAsk":
        return _ko(f"Périmètre de l'agent trop large : serveurs en trop {intrus}, outils natifs {outils_natifs}")
    nb_tools = sum(len(serveurs[n]["tools"]) for n in attendus)
    return _ok(f"3 serveurs MCP connectés ({nb_tools} tools) ; outils natifs : Skill seulement ; mode dontAsk ; "
               "aucun connecteur claude.ai", serveurs=[{k: s[k] for k in ("nom", "statut")} | {"tools": len(s["tools"])}
                                                       for s in sdk["serveurs"]])


def tester_knowledge() -> dict:
    resultats = rechercher_knowledge("tool poisoning", 3)
    if not resultats or "MCP03" not in resultats[0]["titre"]:
        return _ko("La recherche « tool poisoning » ne renvoie pas MCP03 en premier")
    return _ok(f"{len(_documents())} documents ; « tool poisoning » → {resultats[0]['titre']} "
               f"(pertinence {resultats[0]['pertinence']})")


def tester_memoire() -> dict:
    con = sqlite3.connect(f"file:{registry.DB_PATH.as_posix()}?mode=ro", uri=True)
    integrite = con.execute("PRAGMA quick_check").fetchone()[0]
    con.close()
    tables = registry.compter_tables()
    sessions = registry.lister_sessions(50)
    projets = Path.home() / ".claude" / "projects"
    reprenables = sum(1 for s in sessions if any(projets.glob(f"*/{s['session_id']}.jsonl")))
    if integrite != "ok":
        return _ko(f"Base SQLite corrompue : {integrite}")
    return _ok(f"SQLite intègre ({len(tables)} tables, {tables.get('audits', 0)} audits) ; préférences lues ; "
               f"{reprenables}/{len(sessions)} sessions de conversation reprenables", tables=tables)


def tester_authentification() -> dict:
    from claude_agent_sdk._internal.transport.subprocess_cli import SubprocessCLITransport

    cli = SubprocessCLITransport(prompt="", options=agent.options_agent())._find_cli()
    env = {k: v for k, v in os.environ.items() if not k.startswith("CLAUDE")}
    sortie = subprocess.run([cli, "auth", "status"], capture_output=True, text=True, timeout=60, env=env,
                            encoding="utf-8")
    try:
        statut = json.loads(sortie.stdout)
    except ValueError:
        statut = {}
    claude = {"connecte": bool(statut.get("loggedIn")), "methode": statut.get("authMethod"),
              "abonnement": statut.get("subscriptionType")}
    try:
        urllib.request.urlopen("http://127.0.0.1:8000/api/session", timeout=10)
        interface_401 = False
    except urllib.error.HTTPError as e:
        interface_401 = e.code == 401
    except OSError:  # interface non démarrée sur 127.0.0.1:8000 : vérification impossible
        interface_401 = None
    jeton = connecteurs.chemin_token()
    portee = json.loads(jeton.read_text(encoding="utf-8")).get("scopes") if jeton.exists() else None
    gmail = connecteurs.tester("gmail")
    verifs = {"Claude Code connecté (OAuth)": claude["connecte"],
              "Interface : accès refusé sans mot de passe (401)": interface_401,
              "Google OAuth2 : scope drive.file uniquement": portee == connecteurs.SCOPES,
              "Gmail : authentification SMTP": gmail["ok"]}
    details = {"claude": claude, "verifications": verifs,
               "github": "jeton défini" if os.getenv("GITHUB_TOKEN") else "mode anonyme (jeton facultatif)"}
    if all(verifs.values()):
        return _ok(f"{len(verifs)}/{len(verifs)} mécanismes vérifiés (Claude {claude['methode']}, abonnement "
                   f"{claude['abonnement']})", **details)
    manquants = [k for k, v in verifs.items() if not v]
    non_config = not connecteurs.gmail_configure() or not connecteurs.drive_configure()
    return _ko("Échec : " + " ; ".join(manquants), "non configuré" if non_config else "erreur", **details)


def tester_bonus() -> dict:
    if not _reaudit:
        return _ko("Planificateur indisponible")
    bilan = _reaudit()
    return _ok(f"Ré-audit exécuté : {bilan['verifies']} serveur(s) vérifié(s), {len(bilan['rug_pulls'])} rug pull(s) "
               "détecté(s) (sans LLM)", bilan=bilan)


TESTS = {"instructions": tester_instructions, "skills": tester_skills, "tools": tester_tools,
         "connecteurs": tester_connecteurs, "plugins": tester_plugins, "mcp": tester_mcp,
         "knowledge": tester_knowledge, "memoire": tester_memoire, "authentification": tester_authentification,
         "bonus": tester_bonus}


def tester(id_: str) -> dict:
    debut = time.time()
    try:
        resultat = TESTS[id_]()
    except Exception as e:  # noqa: BLE001  volontaire : une carte de démonstration affiche tout échec
        resultat = _ko(f"{type(e).__name__} : {str(e)[:300]}")
    resultat["duree_s"] = round(time.time() - debut, 1)
    registry.journaliser("test_fonctionnalite", {"id": id_, **resultat})
    resultat["date"] = registry.maintenant()
    return resultat


def etat() -> list[dict]:
    cartes = []
    for d in DEFINITIONS:
        dernier = registry.dernier_evenement("test_fonctionnalite", f'"id": "{d["id"]}"')
        try:
            donnees_carte = donnees(d["id"])
        except Exception as e:  # noqa: BLE001  volontaire : une carte en erreur ne masque pas les autres
            donnees_carte = {"erreur": f"{type(e).__name__} : {e}"}
        cartes.append({**d, "donnees": donnees_carte, "dernier_test": dernier})
    return cartes

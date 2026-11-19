"""Moteur d'analyse statique de MCP-Guard.

Toutes les fonctions de ce module analysent du code ou du texte SANS JAMAIS
l'exécuter (analyse par AST et expressions régulières). Elles sont utilisées
à la fois par le serveur MCP (tools exposés au LLM) et par le backend
(réaudit planifié, sans consommer de quota LLM).
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
import unicodedata
from pathlib import Path

# ---------------------------------------------------------------------------
# Constantes : gravités et points (voir knowledge/02_grille_scoring.md)
# ---------------------------------------------------------------------------
POINTS = {"critique": 40, "eleve": 20, "moyen": 10, "faible": 3, "info": 0}

ROOT = Path(__file__).resolve().parent.parent
ZONES_AUTORISEES = [ROOT / "samples", ROOT / "uploads"]


# ---------------------------------------------------------------------------
# Sécurité de MCP-Guard lui-même : pas de path traversal dans nos propres tools
# ---------------------------------------------------------------------------
def chemin_sur(chemin: str) -> Path:
    """Résout un chemin et vérifie qu'il reste dans samples/ ou uploads/.

    MCP-Guard applique à lui-même les règles qu'il audite (MCP05 : path traversal).
    """
    candidat = Path(chemin)
    if not candidat.is_absolute():
        candidat = ROOT / candidat
    reel = candidat.resolve()
    for zone in ZONES_AUTORISEES:
        if reel == zone.resolve() or zone.resolve() in reel.parents:
            if not reel.exists():
                raise FileNotFoundError(f"Introuvable : {chemin}")
            return reel
    raise PermissionError(
        "Accès refusé : seuls les fichiers de samples/ et uploads/ peuvent être audités."
    )


def lire_texte(chemin: Path) -> str:
    return chemin.read_text(encoding="utf-8", errors="replace")


def fichiers_a_auditer(chemin: Path) -> list[Path]:
    """Accepte un fichier ou un dossier (serveur complet)."""
    if chemin.is_file():
        return [chemin]
    exts = {".py", ".json", ".md", ".js", ".ts"}
    return sorted(p for p in chemin.rglob("*") if p.is_file() and p.suffix in exts)


def constat(regle, gravite, owasp, titre, explication, preuve="", tool=None, ligne=None):
    return {
        "regle": regle,
        "gravite": gravite,
        "points": POINTS[gravite],
        "owasp": owasp,
        "titre": titre,
        "explication": explication,
        "preuve": (preuve or "")[:240],
        "tool": tool,
        "ligne": ligne,
    }


# ---------------------------------------------------------------------------
# 1. Extraction des définitions de tools (nom, description, paramètres)
# ---------------------------------------------------------------------------
def _est_decorateur_tool(dec: ast.expr) -> bool:
    cible = dec.func if isinstance(dec, ast.Call) else dec
    return isinstance(cible, ast.Attribute) and cible.attr == "tool"


def _description_decorateur(dec: ast.expr) -> str | None:
    if isinstance(dec, ast.Call):
        for kw in dec.keywords:
            if kw.arg == "description" and isinstance(kw.value, ast.Constant):
                return str(kw.value.value)
    return None


def extraire_tools_python(source: str) -> list[dict]:
    arbre = ast.parse(source)
    tools = []
    for noeud in ast.walk(arbre):
        if not isinstance(noeud, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decs = [d for d in noeud.decorator_list if _est_decorateur_tool(d)]
        if not decs:
            continue
        description = _description_decorateur(decs[0]) or ast.get_docstring(noeud, clean=False) or ""
        params = []
        for arg in noeud.args.args + noeud.args.kwonlyargs:
            if arg.arg in ("self", "ctx"):
                continue
            params.append({
                "nom": arg.arg,
                "type": ast.unparse(arg.annotation) if arg.annotation else None,
            })
        tools.append({
            "nom": noeud.name,
            "description": description,
            "parametres": params,
            "ligne": noeud.lineno,
        })
    return tools


def extraire_tools_json(source: str) -> list[dict]:
    """Format tools/list (serveur distant) : [{name, description, inputSchema}]."""
    donnees = json.loads(source)
    if isinstance(donnees, dict):
        donnees = donnees.get("tools", [])
    tools = []
    for t in donnees:
        props = (t.get("inputSchema") or {}).get("properties", {})
        tools.append({
            "nom": t.get("name", "?"),
            "description": t.get("description", ""),
            "parametres": [{"nom": k, "type": v.get("type")} for k, v in props.items()],
            "ligne": None,
        })
    return tools


def extraire_tools(chemin: Path) -> list[dict]:
    tools = []
    for f in fichiers_a_auditer(chemin):
        texte = lire_texte(f)
        try:
            if f.suffix == ".py":
                tools += [dict(t, fichier=f.name) for t in extraire_tools_python(texte)]
            elif f.suffix == ".json":
                tools += [dict(t, fichier=f.name) for t in extraire_tools_json(texte)]
        except (SyntaxError, ValueError, json.JSONDecodeError):
            continue
    return tools


# ---------------------------------------------------------------------------
# 2. Tool poisoning : analyse des descriptions (MCP03, MCP10)
# ---------------------------------------------------------------------------
INVISIBLES = re.compile(r"[​‌‍⁠﻿‪-‮⁦-⁩]")
PARAMS_FOURRE_TOUT = {"notes", "note", "contexte", "context", "metadata", "extra",
                      "debug", "debug_info", "data", "payload", "sidenote"}

REGLES_DESCRIPTION = [
    ("balise_cachee", "critique", "MCP03", "Balise d'instruction cachée",
     r"<\s*/?\s*(important|system|instructions?|secret|admin)\s*>|\[INST\]",
     "Des balises de type <IMPORTANT> servent à glisser des ordres au modèle dans une description."),
    ("contournement", "critique", "MCP03", "Tentative de contournement des instructions",
     r"ignor\w*\s+(toute|toutes|les|any|all|previous|prior)?\s*(instructions?|r[eè]gles?)"
     r"|ignore\s+toute\s+instruction|disregard\s+(previous|prior|all)",
     "La description demande au modèle d'ignorer ses instructions : signe classique d'injection."),
    ("dissimulation", "critique", "MCP03", "Action dissimulée à l'utilisateur",
     r"ne\s+(le\s+|la\s+|les\s+)?(dis|mentionne|signale|r[eé]v[eè]le|pr[eé]viens)\w*\s+(pas|jamais)"
     r"|sans\s+(le\s+)?(dire|pr[eé]venir|informer)|do\s*n[o']t\s+(tell|mention|inform)|without\s+telling",
     "La description demande au modèle de cacher une action à l'utilisateur."),
    ("fichier_sensible", "critique", "MCP03", "Accès demandé à des fichiers sensibles",
     r"~/\.ssh|id_rsa|id_ed25519|\.env\b|\.aws|credentials|\.git-credentials|/etc/passwd|\.kube/config",
     "Une description de tool n'a aucune raison légitime de mentionner des clés ou des secrets."),
    ("exfiltration", "critique", "MCP03", "Redirection ou envoi de données vers un tiers",
     r"(redirig|envoi|envoie|transmet|transf[eè]r|forward|send|bcc|cc)\w*[^.\n]{0,80}"
     r"([\w.+-]+@[\w-]+\.[\w.]+|https?://)",
     "La description ordonne d'envoyer des données vers une adresse e-mail ou une URL externe."),
    ("shadowing", "eleve", "MCP03", "Instruction visant un autre tool (shadowing)",
     r"(quand|lorsque|si|when|if)\s+(l['’]outil|le\s+tool|the\s+tool|un\s+autre\s+outil)\s+[\w`]+",
     "La description tente de modifier le comportement d'un autre tool de l'agent."),
    ("sur_partage", "critique", "MCP10", "Demande de contexte excessive",
     r"historique\s+(complet\s+)?de\s+la\s+conversation|conversation\s+history|toute\s+la\s+conversation"
     r"|variables?\s+d['’]environnement|environment\s+variables",
     "Le tool réclame tout le contexte de l'agent, bien au-delà de sa fonction."),
    ("pseudo_systeme", "eleve", "MCP06", "Faux message système",
     r"note\s+syst[eè]me|system\s+note|message\s+syst[eè]me|instruction\s+syst[eè]me",
     "La description se fait passer pour une consigne système afin de gagner la confiance du modèle."),
]


def analyser_descriptions(tools: list[dict]) -> list[dict]:
    constats = []
    for t in tools:
        desc = t["description"] or ""
        desc_norm = unicodedata.normalize("NFKC", desc)
        for regle, gravite, owasp, titre, motif, expl in REGLES_DESCRIPTION:
            m = re.search(motif, desc_norm, re.IGNORECASE)
            if m:
                debut = max(0, m.start() - 60)
                constats.append(constat(regle, gravite, owasp, titre, expl,
                                        desc_norm[debut:m.end() + 80].strip(), t["nom"], t["ligne"]))
        if INVISIBLES.search(desc):
            n = len(INVISIBLES.findall(desc))
            constats.append(constat("caracteres_invisibles", "eleve", "MCP03",
                                    "Caractères invisibles dans la description",
                                    f"{n} caractère(s) invisible(s) (zero-width/bidi) peuvent cacher du texte à l'humain.",
                                    repr(desc[:120]), t["nom"], t["ligne"]))
        suspects = [p["nom"] for p in t["parametres"] if p["nom"].lower() in PARAMS_FOURRE_TOUT]
        for p in suspects:
            gravite = "critique" if p in desc else "moyen"
            constats.append(constat("parametre_fourre_tout", gravite, "MCP03",
                                    f"Paramètre fourre-tout « {p} »",
                                    "Un paramètre libre sans lien avec la fonction peut servir de canal d'exfiltration."
                                    + (" La description demande explicitement de le remplir." if gravite == "critique" else ""),
                                    f"paramètres : {[x['nom'] for x in t['parametres']]}", t["nom"], t["ligne"]))
        if len(desc) > 1200:
            constats.append(constat("description_longue", "faible", "MCP03", "Description anormalement longue",
                                    f"{len(desc)} caractères : une description longue peut dissimuler des instructions.",
                                    "", t["nom"], t["ligne"]))
    return constats


# ---------------------------------------------------------------------------
# 3. Secrets en dur (MCP01)
# ---------------------------------------------------------------------------
MOTIFS_SECRETS = [
    ("Clé d'accès AWS", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("Jeton GitHub", r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}"),
    ("Clé API Anthropic", r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    ("Clé API (format sk-)", r"\bsk-[A-Za-z0-9]{20,}\b"),
    ("Jeton Slack", r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    ("Clé privée", r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ("Secret assigné en dur",
     r"(?i)\b\w*(api_?key|secret|token|passw(or)?d|pwd)\w*\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']"),
]


def _masquer(valeur: str) -> str:
    return valeur[:6] + "…" + "*" * 6 if len(valeur) > 8 else "****"


def analyser_secrets(chemin: Path) -> list[dict]:
    constats, vus = [], set()
    for f in fichiers_a_auditer(chemin):
        for num, ligne in enumerate(lire_texte(f).splitlines(), 1):
            for nom, motif in MOTIFS_SECRETS:
                m = re.search(motif, ligne)
                if m and (f.name, num) not in vus:
                    vus.add((f.name, num))
                    constats.append(constat("secret_en_dur", "eleve", "MCP01", f"{nom} écrit en dur",
                                            "Un secret dans le code source est exposé à toute personne qui lit le dépôt.",
                                            f"{f.name}:{num} → {_masquer(m.group(0))}", None, num))
    return constats


# ---------------------------------------------------------------------------
# 4. Code dangereux (MCP05, MCP02, MCP01, MCP10) — analyse AST
# ---------------------------------------------------------------------------
VERBES_LECTURE = re.compile(r"\b(lit|lire|liste|lister|lecture|affiche|obtenir|consulte|read|list|get|show|view)\b", re.I)
APPELS_DESTRUCTIFS = {"remove", "unlink", "rmtree", "rmdir", "truncate"}


def _nom_appel(appel: ast.Call) -> str:
    try:
        return ast.unparse(appel.func)
    except Exception:  # pragma: no cover
        return ""


def _est_dynamique(noeud: ast.expr | None) -> bool:
    """Vrai si la valeur n'est pas une constante littérale (donc potentiellement contrôlée)."""
    return noeud is not None and not isinstance(noeud, ast.Constant)


def analyser_code_python(source: str, fichier: str = "") -> list[dict]:
    constats = []
    arbre = ast.parse(source)
    descriptions = {t["nom"]: t["description"] for t in extraire_tools_python(source)}

    fonctions = [n for n in ast.walk(arbre) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for fn in fonctions:
        nom_tool = fn.name if fn.name in descriptions else None
        params = {a.arg for a in fn.args.args + fn.args.kwonlyargs}
        corps = ast.unparse(fn)
        normalise = "realpath" in corps or "abspath" in corps or ".resolve(" in corps
        destructif = False

        for n in ast.walk(fn):
            if not isinstance(n, ast.Call):
                continue
            nom = _nom_appel(n)
            premier = n.args[0] if n.args else None
            preuve = f"{fichier}:{n.lineno} → {ast.unparse(n)[:160]}"

            if nom.startswith("subprocess.") and any(
                    k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in n.keywords):
                g = "critique" if _est_dynamique(premier) else "eleve"
                constats.append(constat("injection_commande", g, "MCP05", "Commande shell avec shell=True",
                                        "La commande est interprétée par un shell : une entrée comme "
                                        "« 8.8.8.8; rm -rf / » exécute une seconde commande.",
                                        preuve, nom_tool, n.lineno))
            elif nom in ("os.system", "os.popen") and _est_dynamique(premier):
                constats.append(constat("injection_commande", "critique", "MCP05", f"Appel {nom} avec entrée dynamique",
                                        "La chaîne est passée telle quelle au shell : injection de commande possible.",
                                        preuve, nom_tool, n.lineno))
            elif nom in ("eval", "exec") and _est_dynamique(premier):
                constats.append(constat("execution_code", "critique", "MCP05", f"Utilisation de {nom}()",
                                        "Exécute du code Python arbitraire fourni en entrée.",
                                        preuve, nom_tool, n.lineno))
            elif nom in ("pickle.loads", "pickle.load", "marshal.loads", "dill.loads"):
                constats.append(constat("deserialisation", "eleve", "MCP05", f"Désérialisation dangereuse ({nom})",
                                        "Désérialiser des données non fiables avec pickle permet l'exécution de code.",
                                        preuve, nom_tool, n.lineno))
            elif nom == "yaml.load" and not any(k.arg == "Loader" and "Safe" in ast.unparse(k.value) for k in n.keywords):
                constats.append(constat("deserialisation", "eleve", "MCP05", "yaml.load sans SafeLoader",
                                        "yaml.load sans SafeLoader peut instancier des objets arbitraires.",
                                        preuve, nom_tool, n.lineno))
            elif nom in ("open", "os.path.join", "Path") and any(
                    isinstance(a, ast.Name) and a.id in params for a in ast.walk(n)) and not normalise:
                constats.append(constat("path_traversal", "eleve", "MCP05", "Chemin de fichier non contrôlé",
                                        "Un paramètre est utilisé dans un chemin sans normalisation : "
                                        "« ../../etc/passwd » permet de sortir du dossier prévu.",
                                        preuve, nom_tool, n.lineno))

            if nom.split(".")[-1] in APPELS_DESTRUCTIFS:
                destructif = True

            if re.match(r"^(requests|httpx|urllib\.request|aiohttp)\.?\w*\.(post|put|get|request|urlopen)$", nom) \
                    or nom in ("requests.post", "httpx.post", "requests.put", "httpx.put"):
                url = ast.unparse(premier) if premier is not None else ""
                payload = " ".join(ast.unparse(k.value) for k in n.keywords if k.arg in ("json", "data", "params"))
                fuite = re.search(r"os\.environ|token|secret|key|passw|contexte|context", payload, re.I)
                ip_brute = re.search(r"\d{1,3}(\.\d{1,3}){3}", url)
                if fuite:
                    constats.append(constat("exfiltration", "critique", "MCP10" if "environ" in payload else "MCP01",
                                            "Envoi de données sensibles vers l'extérieur",
                                            "Le code transmet des secrets, l'environnement ou le contexte de l'agent à un serveur distant.",
                                            preuve, nom_tool, n.lineno))
                elif ip_brute and not url.startswith(("'https://127.", '"http://127.')):
                    constats.append(constat("hote_inconnu", "eleve", "MCP04", "Connexion vers une adresse IP brute",
                                            "Une adresse IP codée en dur, sans nom de domaine documenté, est un indicateur de C2.",
                                            preuve, nom_tool, n.lineno))

        if nom_tool and destructif and VERBES_LECTURE.search(descriptions.get(nom_tool) or ""):
            constats.append(constat("incoherence_description", "eleve", "MCP02",
                                    "La description ne correspond pas au code",
                                    "Le tool se présente comme une lecture mais son code supprime des fichiers : "
                                    "le modèle et l'utilisateur sont trompés sur ses effets.",
                                    f"description : « {(descriptions[nom_tool] or '')[:80]} »", nom_tool, fn.lineno))
    return constats


def analyser_code(chemin: Path) -> list[dict]:
    constats = []
    for f in fichiers_a_auditer(chemin):
        if f.suffix == ".py":
            try:
                constats += analyser_code_python(lire_texte(f), f.name)
            except SyntaxError as e:
                constats.append(constat("syntaxe", "info", "-", "Fichier non analysable", str(e), f.name))
    return constats


def lister_imports(chemin: Path) -> list[str]:
    modules = set()
    for f in fichiers_a_auditer(chemin):
        if f.suffix != ".py":
            continue
        try:
            for n in ast.walk(ast.parse(lire_texte(f))):
                if isinstance(n, ast.Import):
                    modules |= {a.name.split(".")[0] for a in n.names}
                elif isinstance(n, ast.ImportFrom) and n.module and n.level == 0:
                    modules.add(n.module.split(".")[0])
        except SyntaxError:
            continue
    return sorted(modules)


# ---------------------------------------------------------------------------
# 5. Skills (SKILL.md) — instructions malveillantes
# ---------------------------------------------------------------------------
REGLES_SKILL = [
    ("execution_distante", "critique", "MCP04", "Téléchargement et exécution de script distant",
     r"(curl|wget)[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b",
     "« curl … | bash » exécute un script distant non vérifié : compromission directe de la machine."),
    ("desactivation_confirmations", "critique", "MCP02", "Désactivation des confirmations de sécurité",
     r"dangerously-skip-permissions|bypassPermissions|n['’]attends?\s+(jamais|pas)\s+de\s+confirmation"
     r"|sans\s+(demander|attendre)\s+(de\s+)?confirmation|without\s+(asking|confirmation)",
     "La skill supprime le contrôle humain sur les actions de l'agent."),
    ("vol_identifiants", "critique", "MCP01", "Collecte d'identifiants",
     r"\.git-credentials|\.aws/credentials|~/\.ssh|id_rsa|\.netrc|\.env\b|toutes\s+les\s+variables\s+d['’]environnement",
     "La skill demande de lire des fichiers d'identifiants ou l'environnement complet."),
    ("exfiltration", "critique", "MCP10", "Envoi de données vers un serveur externe",
     r"(env|printenv|cat)[^\n]*\|\s*(base64\s*\|\s*)?curl|curl\s+[^\n]*-X\s*POST[^\n]*-d\s*@",
     "Des données locales sont encodées puis transmises à un serveur distant."),
    ("dissimulation", "critique", "MCP03", "Étapes cachées à l'utilisateur",
     r"ne\s+signale\s+pas|ne\s+(le\s+)?dis\s+pas|n['’]informe\s+pas|do\s*n[o']t\s+(tell|mention)|sans\s+int[eé]r[eê]t\s+pour\s+lui",
     "La skill demande à l'agent de cacher certaines actions."),
    ("priorite_abusive", "critique", "MCP06", "Tentative de prise de priorité sur les autres instructions",
     r"ignore[-\s]la|cette\s+skill\s+est\s+prioritaire|ignore\s+(any|all)\s+other|override\s+(the\s+)?system",
     "La skill tente de neutraliser les instructions système et les autres skills."),
    ("declencheur_large", "moyen", "MCP02", "Déclencheur trop large",
     r"d[eè]s\s+que\s+l['’]utilisateur|[aà]\s+chaque\s+(fois|message)|always\s+use|use\s+for\s+every",
     "Une description qui s'active sur presque toute demande élargit la surface d'attaque."),
]


def analyser_skill_texte(texte: str) -> list[dict]:
    constats = []
    for regle, gravite, owasp, titre, motif, expl in REGLES_SKILL:
        for m in re.finditer(motif, texte, re.IGNORECASE):
            ligne = texte.count("\n", 0, m.start()) + 1
            constats.append(constat(regle, gravite, owasp, titre, expl,
                                    texte.splitlines()[ligne - 1].strip(), "SKILL.md", ligne))
            break
    return constats


# ---------------------------------------------------------------------------
# 5 bis. Fichiers de configuration MCP en JSON (claude_desktop_config.json, .mcp.json, mcp.json)
#        Lecture du JSON uniquement : aucune commande déclarée n'est exécutée.
# ---------------------------------------------------------------------------
LANCEURS_PAQUETS = {"npx", "npx.cmd", "uvx", "uvx.exe", "bunx", "pnpx", "pipx"}
SHELLS = {"bash", "sh", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"}
SCRIPT_DISTANT = re.compile(r"(curl|wget|iwr|invoke-webrequest)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b|\|\s*iex\b|-encodedcommand", re.I)
OPTIONS_DANGEREUSES = re.compile(r"--dangerously-skip-permissions|--no-sandbox|--allow-all|bypassPermissions", re.I)
CLE_SECRETE = re.compile(r"token|secret|key|passw(or)?d|pwd|credential|auth", re.I)
VALEUR_FACTICE = re.compile(r"\$\{?\w+\}?|<[^>]+>|(your|votre)[-_ ].*|x{3,}|changeme|\*+", re.I)
RACINES_LARGES = {"", "c:", "~", "$home", "%userprofile%", "/home", "/users", "c:/users", "c:\\users"}


def lire_config_mcp(chemin: Path) -> list[dict]:
    """Serveurs déclarés dans les fichiers JSON de configuration MCP (clé mcpServers, ou servers pour VS Code).
    Les valeurs des variables d'environnement sont masquées : seules leurs clés sont exposées."""
    serveurs = []
    for f in fichiers_a_auditer(chemin):
        if f.suffix != ".json":
            continue
        texte = lire_texte(f)
        try:
            donnees = json.loads(texte)
        except ValueError:
            continue
        bloc = (donnees.get("mcpServers") or donnees.get("servers")) if isinstance(donnees, dict) else None
        if not isinstance(bloc, dict):
            continue
        for nom, conf in bloc.items():
            if not isinstance(conf, dict):
                continue
            position = texte.find(f'"{nom}"')
            env = conf.get("env") if isinstance(conf.get("env"), dict) else {}
            serveurs.append({
                "fichier": f.name, "nom": nom, "ligne": texte.count("\n", 0, position) + 1 if position >= 0 else None,
                "commande": str(conf.get("command") or ""), "args": [str(a) for a in conf.get("args") or []],
                "url": str(conf.get("url") or ""), "env": {k: _masquer(str(v)) for k, v in env.items()},
                "_env_brut": env,
            })
    return serveurs


def _paquet_epingle(paquet: str) -> bool:
    nom = paquet.split("/", 1)[1] if paquet.startswith("@") and "/" in paquet else paquet  # @scope/paquet@1.2.3
    return bool(re.search(r"(==|@)\d", nom))


def analyser_config_mcp(chemin: Path) -> list[dict]:
    constats = []
    for s in lire_config_mcp(chemin):
        nom, ligne, args = s["nom"], s["ligne"], s["args"]
        commande = Path(s["commande"].replace("\\", "/")).name.lower()
        ligne_cmd = " ".join([s["commande"], *args]).strip()
        if SCRIPT_DISTANT.search(ligne_cmd):
            constats.append(constat("config_script_distant", "critique", "MCP04", "Script distant exécuté au lancement",
                                    "La configuration télécharge et exécute un script (curl | sh) à chaque démarrage : "
                                    "son contenu peut changer à tout moment, sans aucun contrôle.", ligne_cmd, nom, ligne))
        elif commande in SHELLS and any(a.lower() in ("-c", "/c", "-command") for a in args):
            constats.append(constat("config_shell", "eleve", "MCP05", "Serveur lancé via un shell",
                                    "Lancer un serveur par « bash -c » ou équivalent permet d'enchaîner n'importe quelle "
                                    "commande système.", ligne_cmd, nom, ligne))
        if commande in LANCEURS_PAQUETS:
            paquet = next((a for a in args if not a.startswith("-")), "")
            if paquet and not _paquet_epingle(paquet):
                constats.append(constat("config_paquet_non_epingle", "eleve", "MCP04", "Paquet non épinglé (version flottante)",
                                        f"« {commande} » installe la dernière version publiée de {paquet} à chaque lancement : "
                                        "une mise à jour malveillante serait exécutée sans audit (rug pull).", ligne_cmd, nom, ligne))
        if OPTIONS_DANGEREUSES.search(ligne_cmd):
            constats.append(constat("config_protections_desactivees", "critique", "MCP02", "Protections désactivées",
                                    "Une option de la commande désactive les confirmations ou le bac à sable.", ligne_cmd, nom, ligne))
        if any(a.strip() and a.strip().lower().rstrip("/\\") in RACINES_LARGES for a in args):
            constats.append(constat("config_acces_disque", "eleve", "MCP02", "Accès à tout le disque",
                                    "Le serveur reçoit la racine du disque ou le dossier personnel : il peut lire et modifier "
                                    "bien plus que nécessaire (moindre privilège).", ligne_cmd, nom, ligne))
        for cle, valeur in s["_env_brut"].items():
            valeur = str(valeur)
            deja_detecte = any(re.search(m, valeur) for _, m in MOTIFS_SECRETS)  # déjà signalé par detecter_secrets
            if CLE_SECRETE.search(cle) and len(valeur) >= 8 and not VALEUR_FACTICE.fullmatch(valeur) and not deja_detecte:
                constats.append(constat("config_secret_clair", "eleve", "MCP01", "Secret en clair dans la configuration",
                                        "Le secret est écrit dans le fichier au lieu d'être lu depuis le gestionnaire de "
                                        "secrets ou une variable d'environnement.", f"{cle} = {_masquer(valeur)}", nom, ligne))
        hote = re.match(r"http://([^/:]+)", s["url"])
        if hote and hote.group(1) not in ("localhost", "127.0.0.1", "::1"):
            constats.append(constat("config_http_clair", "eleve", "MCP07", "Serveur distant sans chiffrement (http://)",
                                    "Les échanges (et les éventuels jetons) circulent en clair sur le réseau.", s["url"], nom, ligne))
    return constats


# ---------------------------------------------------------------------------
# 6. Empreinte (détection du rug pull, MCP04)
# ---------------------------------------------------------------------------
def empreinte(chemin: Path) -> dict:
    tools = extraire_tools(chemin)
    canonique = json.dumps(
        sorted(({"nom": t["nom"], "description": t["description"], "parametres": t["parametres"]} for t in tools),
               key=lambda x: x["nom"]),
        ensure_ascii=False, sort_keys=True)
    h_fichiers = hashlib.sha256()
    for f in fichiers_a_auditer(chemin):
        h_fichiers.update(f.read_bytes())
    return {
        "empreinte_tools": hashlib.sha256(canonique.encode("utf-8")).hexdigest(),
        "empreinte_fichiers": h_fichiers.hexdigest(),
        "tools": {t["nom"]: hashlib.sha256((t["description"] + json.dumps(t["parametres"])).encode()).hexdigest()[:16]
                  for t in tools},
    }


def comparer_empreintes(ancienne: dict, nouvelle: dict) -> dict:
    a, n = ancienne.get("tools", {}), nouvelle.get("tools", {})
    return {
        "modifie": ancienne["empreinte_tools"] != nouvelle["empreinte_tools"],
        "code_modifie": ancienne["empreinte_fichiers"] != nouvelle["empreinte_fichiers"],
        "tools_ajoutes": sorted(set(n) - set(a)),
        "tools_supprimes": sorted(set(a) - set(n)),
        "tools_modifies": sorted(k for k in set(a) & set(n) if a[k] != n[k]),
    }


def evaluer_modification(ancienne: dict, chemin: Path) -> dict:
    """Compare un serveur approuvé à l'empreinte mémorisée lors de son approbation.

    Toute modification compte comme un rug pull potentiel (politique d'approbation) : celle des
    définitions de tools, mais aussi celle du code seul. Une mise à jour peut garder des
    descriptions identiques et ajouter une exfiltration dans le corps d'une fonction.
    Si le code a changé, la nouvelle version est réauditée (analyse statique, sans LLM).
    """
    diff = comparer_empreintes(ancienne, empreinte(chemin))
    diff["rug_pull"] = diff["modifie"] or diff["code_modifie"]
    if diff["code_modifie"]:
        nouvel_audit = audit_complet(chemin)
        diff["nouveau_score"], diff["nouveau_verdict"] = nouvel_audit["score"], nouvel_audit["verdict"]
    return diff


def resume_modification(diff: dict) -> str:
    """Texte lisible d'une modification détectée (alerte, e-mail)."""
    lignes = [f"Tools ajoutés : {', '.join(diff['tools_ajoutes']) or 'aucun'}",
              f"Tools modifiés : {', '.join(diff['tools_modifies']) or 'aucun'}",
              f"Tools supprimés : {', '.join(diff['tools_supprimes']) or 'aucun'}",
              f"Code source modifié : {'oui' if diff['code_modifie'] else 'non'}"]
    if "nouveau_verdict" in diff:
        lignes.append(f"Réaudit statique de la nouvelle version : score {diff['nouveau_score']}/100, "
                      f"verdict {diff['nouveau_verdict']}")
    return "\n".join(lignes)


def installer_copie(source: Path, nom: str) -> Path:
    """Simule l'installation : copie le serveur approuvé dans uploads/installes/<nom>/.

    C'est cette copie « installée » que le réaudit planifié surveille ; une mise à jour
    malveillante de cette copie représente un rug pull.
    """
    import shutil
    slug = re.sub(r"[^a-zA-Z0-9_-]", "-", nom).strip("-")[:60] or "serveur"
    cible = ROOT / "uploads" / "installes" / slug
    if cible.exists():
        shutil.rmtree(cible)
    cible.mkdir(parents=True)
    for f in fichiers_a_auditer(source):
        shutil.copy2(f, cible / f.name)
    return cible


# ---------------------------------------------------------------------------
# 7. Audit complet et scoring (knowledge/02_grille_scoring.md)
# ---------------------------------------------------------------------------
def calculer_score(constats: list[dict]) -> dict:
    uniques = {}
    for c in constats:
        uniques.setdefault((c["regle"], c["tool"], c["ligne"] if c["regle"] == "secret_en_dur" else None), c)
    liste = sorted(uniques.values(), key=lambda c: -c["points"])
    score = min(100, sum(c["points"] for c in liste))
    critique_bloquant = any(c["gravite"] == "critique" and c["owasp"] in ("MCP03", "MCP04", "MCP10")
                            or c["regle"] in ("exfiltration",) for c in liste)
    if score >= 60 or critique_bloquant:
        niveau, verdict = ("Critique" if score >= 60 else "Élevé"), "REJETER"
    elif score >= 30:
        niveau, verdict = "Élevé", "CORRIGER"
    elif score >= 10:
        niveau, verdict = "Modéré", "CORRIGER"
    else:
        niveau, verdict = "Faible", "INSTALLER"
    return {"score": score, "niveau": niveau, "verdict": verdict, "constats": liste,
            "repartition": {g: sum(1 for c in liste if c["gravite"] == g) for g in POINTS}}


def audit_complet(chemin: Path) -> dict:
    fichiers = fichiers_a_auditer(chemin)
    est_skill = any(f.name.upper() == "SKILL.MD" for f in fichiers)
    constats = []
    tools = extraire_tools(chemin)
    if est_skill:
        for f in fichiers:
            if f.name.upper() == "SKILL.MD":
                constats += analyser_skill_texte(lire_texte(f))
    constats += analyser_descriptions(tools)
    constats += analyser_secrets(chemin)
    constats += analyser_code(chemin)
    configs = lire_config_mcp(chemin)
    if configs:
        constats += analyser_config_mcp(chemin)
    resultat = calculer_score(constats)
    resultat.update({
        "cible": chemin.name,
        "type": "skill" if est_skill else "configuration_mcp" if configs and not tools else "serveur_mcp",
        "fichiers": [f.name for f in fichiers],
        "tools": [{"nom": t["nom"], "parametres": [p["nom"] for p in t["parametres"]]} for t in tools],
        "imports": lister_imports(chemin),
        "serveurs_configures": [s["nom"] for s in configs],
        "empreinte": empreinte(chemin)["empreinte_tools"],
    })
    return resultat

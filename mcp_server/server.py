"""Serveur MCP « mcp-guard » — les tools de l'agent auditeur.

Lancé automatiquement par le Claude Agent SDK (transport stdio) depuis le
backend web. Peut aussi être branché à Claude Desktop ou Claude Code.

Principe de sécurité : aucun tool n'exécute le code audité. Tout est analysé
de manière statique (AST + expressions régulières).
"""
from __future__ import annotations

import json
import re
import sys
import unicodedata
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp.server.mcpserver import MCPServer  # noqa: E402

from mcp_server import analyzers as az  # noqa: E402
from mcp_server import registry  # noqa: E402

KNOWLEDGE_DIR = az.ROOT / "knowledge"

serveur = MCPServer(
    name="mcp-guard",
    instructions=(
        "Outils d'audit de sécurité pour serveurs MCP et skills. "
        "Les chemins acceptés sont relatifs au projet et limités à samples/ et uploads/."
    ),
)


def _erreur(e: Exception) -> dict:
    return {"erreur": f"{type(e).__name__} : {e}"}


# ---------------------------------------------------------------------------
# Tools d'analyse
# ---------------------------------------------------------------------------
@serveur.tool()
def lister_elements_disponibles() -> dict:
    """Liste les serveurs MCP et skills disponibles pour un audit (dossiers samples/ et uploads/)."""
    resultat = {}
    for zone in az.ZONES_AUTORISEES:
        if zone.exists():
            resultat[zone.name] = sorted(p.name for p in zone.iterdir() if not p.name.startswith("."))
    return resultat


@serveur.tool()
def scanner_descriptions(chemin: str) -> dict:
    """Extrait les tools d'un serveur MCP (nom, description, paramètres) et détecte le tool poisoning
    (instructions cachées, exfiltration, dissimulation, caractères invisibles, paramètres fourre-tout).

    Args:
        chemin: dossier ou fichier à analyser, ex. "samples/02_serveur_empoisonne".
    """
    try:
        p = az.chemin_sur(chemin)
        tools = az.extraire_tools(p)
        return {"tools": [{k: t[k] for k in ("nom", "description", "parametres", "ligne")} for t in tools],
                "constats": az.analyser_descriptions(tools)}
    except Exception as e:
        return _erreur(e)


@serveur.tool()
def detecter_secrets(chemin: str) -> dict:
    """Recherche les secrets écrits en dur (clés AWS, jetons GitHub, clés API, clés privées).
    Les valeurs trouvées sont masquées dans le résultat.

    Args:
        chemin: dossier ou fichier à analyser.
    """
    try:
        return {"constats": az.analyser_secrets(az.chemin_sur(chemin))}
    except Exception as e:
        return _erreur(e)


@serveur.tool()
def analyser_code(chemin: str) -> dict:
    """Analyse statique (AST) du code Python d'un serveur MCP : injection de commande (shell=True,
    os.system, eval), path traversal, désérialisation dangereuse, exfiltration réseau, incohérence
    entre la description d'un tool et son comportement réel. Le code n'est jamais exécuté.

    Args:
        chemin: dossier ou fichier à analyser.
    """
    try:
        p = az.chemin_sur(chemin)
        return {"constats": az.analyser_code(p), "imports": az.lister_imports(p)}
    except Exception as e:
        return _erreur(e)


@serveur.tool()
def analyser_skill(chemin: str) -> dict:
    """Analyse une skill (fichier SKILL.md) : exécution de script distant, désactivation des
    confirmations, vol d'identifiants, exfiltration, dissimulation, prise de priorité abusive.

    Args:
        chemin: dossier de la skill ou chemin du SKILL.md, ex. "samples/04_skill_suspecte".
    """
    try:
        p = az.chemin_sur(chemin)
        fichier = p / "SKILL.md" if p.is_dir() else p
        return {"constats": az.analyser_skill_texte(az.lire_texte(fichier))}
    except Exception as e:
        return _erreur(e)


@serveur.tool()
def analyser_config_mcp(chemin: str) -> dict:
    """Analyse un fichier de configuration MCP en JSON (claude_desktop_config.json, .mcp.json, mcp.json de
    VS Code) : serveurs déclarés, commandes de lancement, paquets non épinglés, scripts distants, secrets en
    clair (valeurs masquées), URL non chiffrées, accès trop larges. Lecture seule : rien n'est exécuté.

    Args:
        chemin: dossier ou fichier JSON, ex. "samples/06_config_mcp_suspecte".
    """
    try:
        p = az.chemin_sur(chemin)
        serveurs = [{k: v for k, v in s.items() if k != "_env_brut"} for s in az.lire_config_mcp(p)]
        if not serveurs:
            return {"info": "Aucun fichier de configuration MCP (clé mcpServers) trouvé. Pour la description JSON "
                            "d'un serveur distant (format tools/list), utilisez scanner_descriptions."}
        return {"serveurs": serveurs, "constats": az.analyser_config_mcp(p)}
    except Exception as e:
        return _erreur(e)


@serveur.tool()
def audit_complet(chemin: str) -> dict:
    """Lance toutes les analyses sur un serveur MCP ou une skill et calcule le score de risque
    (0-100), le niveau et le verdict selon la grille de scoring (INSTALLER, CORRIGER ou REJETER).

    Args:
        chemin: dossier ou fichier à auditer.
    """
    try:
        resultat = az.audit_complet(az.chemin_sur(chemin))
        registry.journaliser("audit_tool", {"chemin": chemin, "score": resultat["score"]})
        return resultat
    except Exception as e:
        return _erreur(e)


# ---------------------------------------------------------------------------
# Mémoire à long terme : empreintes et détection du rug pull
# ---------------------------------------------------------------------------
@serveur.tool()
def calculer_empreinte(chemin: str) -> dict:
    """Calcule l'empreinte SHA-256 des définitions de tools (noms, descriptions, paramètres) et du code.

    Args:
        chemin: dossier ou fichier du serveur MCP.
    """
    try:
        return az.empreinte(az.chemin_sur(chemin))
    except Exception as e:
        return _erreur(e)


@serveur.tool()
def approuver_serveur(nom: str, chemin: str) -> dict:
    """Enregistre un serveur MCP comme approuvé, avec son empreinte, dans la mémoire à long terme.
    À n'utiliser QUE si l'utilisateur le demande explicitement et que le verdict est INSTALLER.

    Args:
        nom: nom d'usage du serveur, ex. "meteo-tunisie".
        chemin: dossier ou fichier du serveur MCP.
    """
    try:
        p = az.chemin_sur(chemin)
        verdict = az.audit_complet(p)["verdict"]
        if verdict != "INSTALLER":
            return {"refuse": True, "raison": f"Verdict {verdict} : la politique interdit l'approbation."}
        installe = az.installer_copie(p, nom)
        e = az.empreinte(installe)
        registry.approuver(nom, installe.relative_to(az.ROOT).as_posix(), e)
        return {"approuve": True, "nom": nom, "installe_dans": installe.relative_to(az.ROOT).as_posix(),
                "empreinte_tools": e["empreinte_tools"]}
    except Exception as e:
        return _erreur(e)


@serveur.tool()
def verifier_rug_pull(nom: str, chemin: str = "") -> dict:
    """Compare l'état actuel d'un serveur approuvé avec l'empreinte mémorisée lors de son approbation.
    Détecte les tools ajoutés, supprimés ou modifiés, ainsi que toute modification du code source
    depuis l'approbation (attaque « rug pull ») ; une nouvelle version du code est réauditée.

    Args:
        nom: nom du serveur approuvé.
        chemin: nouvelle version à comparer (facultatif ; par défaut, le chemin enregistré).
    """
    try:
        approuve = registry.obtenir_approuve(nom)
        if not approuve:
            return {"erreur": f"Aucun serveur approuvé nommé « {nom} ».",
                    "serveurs_approuves": [s["nom"] for s in registry.lister_approuves()]}
        p = az.chemin_sur(chemin or approuve["chemin"])
        diff = az.evaluer_modification(approuve["empreinte"], p)
        diff["date_approbation"] = approuve["date_approbation"]
        if diff["rug_pull"]:
            registry.changer_statut(nom, "suspendu (rug pull)")
            registry.ajouter_alerte(nom, "rug_pull", f"Modification depuis l'approbation du "
                                    f"{approuve['date_approbation']} :\n{az.resume_modification(diff)}")
            diff["action"] = "Approbation suspendue et alerte enregistrée."
        return diff
    except Exception as e:
        return _erreur(e)


@serveur.tool()
def lister_serveurs_approuves() -> list[dict]:
    """Liste les serveurs MCP approuvés enregistrés dans la mémoire à long terme, avec leur statut."""
    return registry.lister_approuves()


@serveur.tool()
def consulter_historique_audits(cible: str = "", limite: int = 10) -> list[dict]:
    """Consulte l'historique des audits déjà réalisés (mémoire à long terme) : date, cible, score,
    verdict et lien du rapport archivé dans Google Drive. Lecture seule.

    Args:
        cible: filtre sur le nom de l'élément (ex. "02_serveur_empoisonne"), vide = tous.
        limite: nombre maximal d'audits retournés (1 à 50).
    """
    return registry.rechercher_audits(cible, limite)


@serveur.tool()
def lister_alertes(limite: int = 10) -> list[dict]:
    """Liste les dernières alertes de sécurité (rug pulls détectés, alertes envoyées). Lecture seule.

    Args:
        limite: nombre maximal d'alertes retournées (1 à 50).
    """
    return registry.lister_alertes(max(1, min(limite, 50)))


@serveur.tool()
def lire_preferences() -> dict:
    """Lit les préférences de l'utilisateur mémorisées (mémoire à long terme) : niveau de détail
    attendu pour les rapports (synthétique, standard, détaillé). Lecture seule."""
    prefs = registry.lire_preferences()
    return {"niveau_detail": prefs["niveau_detail"],
            "notification_email": "adresse personnalisée" if prefs["email_notification"] else "adresse du fichier .env"}


# ---------------------------------------------------------------------------
# Knowledge (RAG) et vulnérabilités connues
# ---------------------------------------------------------------------------
def _normaliser(texte: str) -> list[str]:
    t = unicodedata.normalize("NFKD", texte.lower())
    t = "".join(c for c in t if not unicodedata.combining(c))
    return [m for m in re.findall(r"[a-z0-9]+", t) if len(m) > 2]


def _segments() -> list[dict]:
    segments = []
    for f in sorted(KNOWLEDGE_DIR.glob("*.md")):
        parties = re.split(r"\n(?=##\s)", f.read_text(encoding="utf-8"))
        for partie in parties:
            titre = partie.strip().splitlines()[0].lstrip("# ").strip() if partie.strip() else ""
            segments.append({"source": f.name, "titre": titre, "texte": partie.strip()})
    return segments


@serveur.tool()
def rechercher_knowledge(question: str, nombre: int = 3) -> list[dict]:
    """Recherche dans la base de connaissances (OWASP MCP Top 10, grille de scoring, politique
    d'approbation) les passages les plus pertinents pour une question (RAG).

    Args:
        question: question ou mots-clés, ex. "tool poisoning remédiation".
        nombre: nombre de passages à retourner (1 à 5).
    """
    mots = set(_normaliser(question))
    notes = []
    for s in _segments():
        contenu = _normaliser(s["titre"] + " " + s["texte"])
        score = sum(contenu.count(m) for m in mots) + 3 * sum(m in _normaliser(s["titre"]) for m in mots)
        if score:
            notes.append((score, s))
    notes.sort(key=lambda x: -x[0])
    return [dict(s, pertinence=sc) for sc, s in notes[: max(1, min(nombre, 5))]]


@serveur.tool()
def verifier_vulnerabilites_osv(paquet: str, version: str = "", ecosysteme: str = "PyPI") -> dict:
    """Interroge la base publique OSV.dev pour connaître les vulnérabilités connues (CVE, GHSA)
    d'un paquet utilisé par un serveur MCP.

    Args:
        paquet: nom du paquet, ex. "requests".
        version: version précise (facultatif).
        ecosysteme: "PyPI" ou "npm".
    """
    corps = {"package": {"name": paquet, "ecosystem": ecosysteme}}
    if version:
        corps["version"] = version
    try:
        req = urllib.request.Request("https://api.osv.dev/v1/query", data=json.dumps(corps).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=15) as r:
            vulns = json.loads(r.read()).get("vulns", [])
        return {"paquet": paquet, "version": version or "toutes", "nombre": len(vulns),
                "vulnerabilites": [{"id": v.get("id"), "alias": v.get("aliases", [])[:3],
                                    "resume": (v.get("summary") or "")[:200]} for v in vulns[:10]]}
    except Exception as e:
        return {"erreur": f"OSV.dev injoignable : {e}"}


if __name__ == "__main__":
    serveur.run("stdio")

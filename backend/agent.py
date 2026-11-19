"""Liaison entre le backend web et Claude, via le Claude Agent SDK.

Le SDK pilote Claude Code installé sur le PC : l'authentification se fait avec
le compte Claude de l'utilisateur (abonnement), sans clé API.
"""
from __future__ import annotations

import asyncio
import json
import os
import smtplib
import ssl
import sys
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    ResultMessage,
    TextBlock,
    ToolUseBlock,
    create_sdk_mcp_server,
    tool,
)

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from mcp_server import registry  # noqa: E402  (préférences utilisateur, mémoire à long terme)

INSTRUCTIONS = (ROOT / "backend" / "instructions.md").read_text(encoding="utf-8")
SERVEUR_MCP = ROOT / "mcp_server" / "server.py"
PLUGINS = [ROOT / "plugin" / "mcp-guard", ROOT / "plugin" / "osv-scanner"]
SKILLS = ["mcp-guard:rapport-audit-mcp", "mcp-guard:analyse-skill-md", "mcp-guard:analyse-json-mcp"]
OUTBOX = ROOT / "data" / "outbox"

OUTILS_MCP_GUARD = [
    "lister_elements_disponibles", "scanner_descriptions", "detecter_secrets", "analyser_code",
    "analyser_skill", "analyser_config_mcp", "audit_complet", "calculer_empreinte", "approuver_serveur",
    "verifier_rug_pull", "lister_serveurs_approuves", "consulter_historique_audits", "lister_alertes",
    "lire_preferences", "rechercher_knowledge", "verifier_vulnerabilites_osv",
]
# Tool apporté par le serveur MCP du plugin osv-scanner (nommage Claude Code : mcp__plugin_<plugin>_<serveur>__<tool>)
OUTILS_PLUGINS = ["mcp__plugin_osv-scanner_osv__analyser_dependances"]
OUTILS_AUTORISES = ([f"mcp__mcp-guard__{t}" for t in OUTILS_MCP_GUARD] + OUTILS_PLUGINS
                    + ["mcp__connecteurs__envoyer_alerte_email"])

CONSIGNES_DETAIL = {
    "synthétique": "rapports courts : en-tête, synthèse, tableau des constats et décision ; pas de code "
                   "corrigé ni d'analyse détaillée, sauf si l'utilisateur le demande.",
    "standard": "rapports complets au format de la skill rapport-audit-mcp.",
    "détaillé": "rapports approfondis : pour chaque constat critique ou élevé, scénario d'attaque pas à pas, "
                "code corrigé complet et référence OWASP citée depuis la base de connaissances.",
}


def instructions_agent() -> str:
    """System prompt + préférences de l'utilisateur lues dans la mémoire à long terme (à chaque appel)."""
    niveau = registry.lire_preferences()["niveau_detail"]
    return (f"{INSTRUCTIONS}\n\n## Préférences de l'utilisateur (mémoire à long terme)\n"
            f"- Niveau de détail des rapports : **{niveau}** — {CONSIGNES_DETAIL.get(niveau, CONSIGNES_DETAIL['standard'])}\n")


def destinataire_alertes() -> str:
    """Adresse FIXÉE par l'utilisateur (préférence de l'interface, sinon .env) : jamais choisie par l'agent."""
    return registry.lire_preferences()["email_notification"] or os.getenv("ALERTE_DESTINATAIRE", "")


# ---------------------------------------------------------------------------
# Connecteur e-mail (Gmail SMTP) — exposé à l'agent comme tool in-process
# ---------------------------------------------------------------------------
def envoyer_email(sujet: str, corps: str) -> dict:
    """Envoie un e-mail via Gmail (SMTP + mot de passe d'application).

    Sans configuration SMTP, l'e-mail est enregistré dans data/outbox/ (mode démonstration).
    """
    destinataire = destinataire_alertes()
    utilisateur = os.getenv("SMTP_UTILISATEUR", "")
    mot_de_passe = os.getenv("SMTP_MOT_DE_PASSE", "")
    msg = EmailMessage()
    msg["Subject"] = sujet
    msg["From"] = utilisateur or "mcp-guard@localhost"
    msg["To"] = destinataire or "equipe-securite@localhost"
    msg.set_content(corps)

    if utilisateur and mot_de_passe and destinataire:
        hote = os.getenv("SMTP_HOTE", "smtp.gmail.com")
        port = int(os.getenv("SMTP_PORT", "465"))
        # Contexte TLS vérifié (certificat + nom d'hôte) : sans lui, SMTP_SSL ne vérifie rien
        # et le mot de passe d'application pourrait être intercepté (attaque de l'homme du milieu).
        with smtplib.SMTP_SSL(hote, port, timeout=20, context=ssl.create_default_context()) as smtp:
            smtp.login(utilisateur, mot_de_passe)
            smtp.send_message(msg)
        return {"envoye": True, "destinataire": destinataire}

    OUTBOX.mkdir(parents=True, exist_ok=True)
    fichier = OUTBOX / f"alerte_{len(list(OUTBOX.glob('*.eml'))) + 1:03d}.eml"
    fichier.write_bytes(bytes(msg))
    return {"envoye": False, "mode": "démonstration", "fichier": fichier.relative_to(ROOT).as_posix(),
            "info": "SMTP non configuré dans .env : e-mail enregistré localement."}


@tool(
    "envoyer_alerte_email",
    "Envoie une alerte de sécurité par e-mail à l'équipe sécurité (connecteur Gmail). "
    "Le destinataire est fixé par l'utilisateur (préférences / .env) : tu fournis seulement l'objet "
    "et le contenu. À utiliser après un verdict REJETER ou un rug pull, ou si l'utilisateur le demande.",
    {"sujet": str, "corps": str},
)
async def outil_envoyer_alerte(args: dict[str, Any]) -> dict[str, Any]:
    try:
        resultat = await asyncio.to_thread(envoyer_email, args["sujet"], args["corps"])
    except Exception as e:  # erreur SMTP, réseau, authentification
        resultat = {"envoye": False, "erreur": str(e)}
    return {"content": [{"type": "text", "text": json.dumps(resultat, ensure_ascii=False)}]}


CONNECTEURS = create_sdk_mcp_server(name="connecteurs", version="1.0.0", tools=[outil_envoyer_alerte])


# ---------------------------------------------------------------------------
# Configuration de l'agent
# ---------------------------------------------------------------------------
def options_agent(session_id: str | None = None) -> ClaudeAgentOptions:
    return ClaudeAgentOptions(
        system_prompt=instructions_agent(),
        model=os.getenv("MCPGUARD_MODELE", "sonnet"),
        cwd=str(ROOT),
        # Outils intégrés : uniquement Skill. Pas de Bash, Read ni Write : l'agent ne peut
        # ni exécuter le code audité ni sortir de son périmètre (moindre privilège, MCP02).
        tools=["Skill"],
        mcp_servers={
            "mcp-guard": {"type": "stdio", "command": sys.executable, "args": [str(SERVEUR_MCP)]},
            "connecteurs": CONNECTEURS,
        },
        # Liste blanche : tout tool absent de cette liste est refusé sans demander (dontAsk).
        allowed_tools=OUTILS_AUTORISES,
        permission_mode="dontAsk",
        plugins=[{"type": "local", "path": str(p)} for p in PLUGINS],
        skills=SKILLS,
        # Aucun réglage utilisateur ou projet chargé (ni leurs serveurs MCP, ni leurs plugins).
        setting_sources=[],
        env={
            # Pas de connecteurs claude.ai du compte (Gmail, Drive…) dans l'agent : moindre privilège
            # et économie de jetons. (Remplace --strict-mcp-config, qui bloquait aussi le serveur
            # MCP du plugin osv-scanner.)
            "ENABLE_CLAUDEAI_MCP_SERVERS": "false",
            # Interpréteur Python du venv, utilisé par le .mcp.json du plugin osv-scanner.
            "MCPGUARD_PYTHON": sys.executable,
        },
        max_turns=int(os.getenv("MCPGUARD_MAX_TOURS", "20")),
        resume=session_id,
    )


async def _executer(prompt: str, session_id: str | None) -> dict:
    textes, outils = [], []
    resultat: dict[str, Any] = {}
    async with ClaudeSDKClient(options=options_agent(session_id)) as client:
        await client.query(prompt)
        async for message in client.receive_response():
            if isinstance(message, AssistantMessage):
                for bloc in message.content:
                    if isinstance(bloc, TextBlock):
                        textes.append(bloc.text)
                    elif isinstance(bloc, ToolUseBlock):
                        outils.append({"outil": bloc.name.split("__")[-1], "entree": bloc.input})
            elif isinstance(message, ResultMessage):
                resultat = {
                    "reponse": message.result or "\n\n".join(textes),
                    "session_id": message.session_id,
                    "erreur": message.is_error,
                    "cout_equivalent_usd": message.total_cost_usd,
                    "tours": message.num_turns,
                    "duree_ms": message.duration_ms,
                }
    resultat.setdefault("reponse", "\n\n".join(textes))
    resultat["outils_utilises"] = outils
    return resultat


def _boucle_dediee(prompt: str, session_id: str | None) -> dict:
    """Exécute l'agent dans une boucle asyncio dédiée.

    Sous Windows, le lancement d'un sous-processus (Claude Code, serveur MCP) exige une
    ProactorEventLoop : on la crée explicitement, indépendamment de la boucle d'uvicorn.
    """
    boucle = asyncio.ProactorEventLoop() if sys.platform == "win32" else asyncio.new_event_loop()
    try:
        return boucle.run_until_complete(_executer(prompt, session_id))
    finally:
        boucle.close()


async def interroger_agent(prompt: str, session_id: str | None = None) -> dict:
    try:
        return await asyncio.to_thread(_boucle_dediee, prompt, session_id)
    except Exception as e:
        nom = type(e).__name__
        conseil = ""
        if nom == "CLINotFoundError":
            conseil = " Claude Code est introuvable : vérifiez l'installation avec « claude --version »."
        elif "auth" in str(e).lower() or "login" in str(e).lower():
            conseil = " Connectez-vous à Claude Code avec « claude » puis « /login »."
        return {"reponse": f"Erreur de l'agent ({nom}) : {e}.{conseil}", "erreur": True,
                "outils_utilises": [], "session_id": session_id}

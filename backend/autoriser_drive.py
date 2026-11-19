"""Autorisation OAuth2 de Google Drive pour MCP-Guard — à lancer UNE SEULE FOIS.

Usage (depuis le dossier du projet, venv activé) :
    python -m backend.autoriser_drive

Prérequis : credentials.json (ID client OAuth de type « Application de bureau ») à la racine du projet.
Le navigateur s'ouvre ; après votre accord, token.json est créé. Scope demandé : drive.file uniquement
(MCP-Guard ne voit que les fichiers qu'il crée lui-même, jamais le reste de votre Drive).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / ".env")

from backend.connecteurs import SCOPES, chemin_credentials, chemin_token, tester  # noqa: E402


def main() -> int:
    identifiants = chemin_credentials()
    if not identifiants.exists():
        print(f"❌ {identifiants.name} introuvable dans {identifiants.parent}.\n"
              "   Google Cloud Console > API et services > Identifiants > ID client OAuth "
              "(type « Application de bureau ») > Télécharger le JSON, renommé en credentials.json.")
        return 1
    try:
        type_client = next(iter(json.loads(identifiants.read_text(encoding="utf-8"))))
    except (ValueError, StopIteration):
        print("❌ credentials.json illisible (JSON invalide).")
        return 1
    if type_client != "installed":
        print(f"❌ ID client de type « {type_client} » : créez un ID client de type « Application de bureau ».")
        return 1

    from google_auth_oauthlib.flow import InstalledAppFlow

    print("Ouverture du navigateur pour autoriser MCP-Guard (scope : drive.file uniquement)…")
    flux = InstalledAppFlow.from_client_secrets_file(str(identifiants), SCOPES)
    creds = flux.run_local_server(
        host="localhost", port=0, open_browser=True,
        authorization_prompt_message="Si le navigateur ne s'ouvre pas, ouvrez ce lien : {url}",
        success_message="Autorisation accordée à MCP-Guard. Vous pouvez fermer cet onglet.")
    if set(creds.scopes or []) != set(SCOPES):
        print(f"❌ Scopes accordés inattendus : {creds.scopes}")
        return 1
    chemin_token().write_text(creds.to_json(), encoding="utf-8")
    print(f"✅ {chemin_token().name} créé (ne le partagez jamais : il est exclu par .gitignore).")

    resultat = tester("drive")
    print(("✅ " if resultat["ok"] else "❌ ") + resultat["message"])
    return 0 if resultat["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

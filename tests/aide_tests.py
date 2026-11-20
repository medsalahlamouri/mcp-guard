"""Environnement isolé commun aux tests (importé en premier par chaque module de test).

- Aucun secret réel : les variables sensibles sont vidées AVANT tout import du backend.
  load_dotenv() n'écrase jamais une variable déjà définie, même vide : le .env local est ignoré.
- Aucun envoi : Drive et e-mail désactivés, SMTP vide, boîte d'envoi de démonstration temporaire.
- Base SQLite et dossier uploads/ temporaires : la base et les fichiers réels ne sont jamais touchés.
"""
from __future__ import annotations

import atexit
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

TMP = Path(tempfile.mkdtemp(prefix="mcpguard-tests-"))
atexit.register(shutil.rmtree, TMP, ignore_errors=True)

MOT_DE_PASSE_TEST = "mot-de-passe-de-test"
ENV_TEST = {
    "MCPGUARD_MOT_DE_PASSE": MOT_DE_PASSE_TEST,
    "SMTP_UTILISATEUR": "", "SMTP_MOT_DE_PASSE": "", "ALERTE_DESTINATAIRE": "",
    "GITHUB_TOKEN": "",
    "DRIVE_ACTIVE": "0", "NOTIFICATION_CHAQUE_AUDIT": "0",
    "DRIVE_CREDENTIALS": str(TMP / "absent_credentials.json"),
    "DRIVE_TOKEN": str(TMP / "absent_token.json"),
    "MCPGUARD_REAUDIT_MINUTES": "0",
    # Base temporaire, transmise aussi aux sous-processus (serveur MCP lancé en stdio).
    "MCPGUARD_BASE": str(TMP / "mcp_guard_test.db"),
}
os.environ.update(ENV_TEST)
logging.disable(logging.INFO)  # journaux INFO (TestClient, APScheduler) : sortie des tests lisible

from mcp_server import registry  # noqa: E402

assert registry.DB_PATH == TMP / "mcp_guard_test.db"  # jamais data/mcp_guard.db
_compteur = 0


def nouvelle_base() -> Path:
    """Base SQLite vierge, propre à un test."""
    global _compteur
    _compteur += 1
    registry.DB_PATH = TMP / f"base_{_compteur}.db"
    return registry.DB_PATH


def nouveau_dossier(nom: str) -> Path:
    dossier = TMP / f"{nom}_{len(list(TMP.iterdir()))}"
    dossier.mkdir(parents=True)
    return dossier

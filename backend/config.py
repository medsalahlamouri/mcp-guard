"""Configuration commune du backend : chemins du projet, chargement du .env et limites des dépôts.

Importé en premier par les autres modules du backend : le .env est chargé avant toute lecture
de variable d'environnement. Les variables déjà définies ne sont jamais écrasées par le .env.
"""
from __future__ import annotations

import sys
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

FRONTEND = ROOT / "frontend"
SAMPLES = ROOT / "samples"
UPLOADS = ROOT / "uploads"
DOSSIER_INSTALLES = "installes"  # uploads/installes/ : copies des serveurs approuvés, surveillées

# Dépôts de fichiers et imports GitHub
EXTENSIONS_AUTORISEES = frozenset({".py", ".json", ".md", ".js", ".ts", ".txt", ".toml"})
TAILLE_MAX = 1_000_000  # 1 Mo par fichier
MAX_FICHIERS_DEPOT = 20
MAX_FICHIERS_GITHUB = 30
PROFONDEUR_MAX_GITHUB = 3
DOSSIERS_IGNORES_GITHUB = frozenset({"node_modules", ".git", "tests", "docs"})


def extensions_lisibles() -> str:
    return ", ".join(sorted(EXTENSIONS_AUTORISEES))

"""Point d'entrée : lance l'interface web locale de MCP-Guard.

Usage :  python run.py   puis ouvrir http://127.0.0.1:8000
"""
import uvicorn

from backend.app import app

if __name__ == "__main__":
    # 127.0.0.1 uniquement : l'interface n'est jamais exposée sur le réseau (usage personnel).
    uvicorn.run(app, host="127.0.0.1", port=8000)

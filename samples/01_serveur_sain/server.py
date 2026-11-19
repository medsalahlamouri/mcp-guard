"""Serveur MCP « meteo-tunisie » — échantillon SAIN (aucune faille attendue).

Échantillon de démonstration pour MCP-Guard : il n'est jamais exécuté,
seulement analysé de manière statique.
"""
import os

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("meteo-tunisie")

API_URL = "https://api.open-meteo.com/v1/forecast"
VILLES = {
    "tunis": (36.80, 10.18),
    "nabeul": (36.45, 10.73),
    "sfax": (34.74, 10.76),
}


@mcp.tool()
def obtenir_meteo(ville: str) -> dict:
    """Retourne la température actuelle et la vitesse du vent pour une ville tunisienne.

    Args:
        ville: nom de la ville (tunis, nabeul ou sfax).
    """
    ville = ville.strip().lower()
    if ville not in VILLES:
        return {"erreur": f"Ville inconnue. Villes disponibles : {', '.join(VILLES)}"}
    lat, lon = VILLES[ville]
    reponse = httpx.get(
        API_URL,
        params={"latitude": lat, "longitude": lon, "current_weather": "true"},
        timeout=10,
    )
    reponse.raise_for_status()
    return reponse.json()["current_weather"]


@mcp.tool()
def lister_villes() -> list[str]:
    """Liste les villes prises en charge par ce serveur."""
    return sorted(VILLES)


if __name__ == "__main__":
    mcp.run()

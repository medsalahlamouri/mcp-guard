"""Serveur MCP du plugin « osv-scanner » (chargé par Claude Code via .mcp.json du plugin).

Extrait de façon STATIQUE les dépendances d'un serveur MCP ou d'une skill audité
(requirements*.txt, pyproject.toml, package.json, imports Python), puis interroge la base
publique OSV.dev (https://osv.dev) pour lister leurs vulnérabilités connues (CVE, GHSA).
Le code audité n'est jamais exécuté ; l'accès reste limité à samples/ et uploads/.
"""
from __future__ import annotations

import json
import re
import sys
import tomllib
import urllib.request
from pathlib import Path

RACINE_PROJET = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(RACINE_PROJET))

from mcp.server.mcpserver import MCPServer  # noqa: E402

from mcp_server import analyzers as az  # noqa: E402

serveur = MCPServer(
    name="osv",
    instructions="Vulnérabilités connues des dépendances d'un élément audité (base OSV.dev). "
                 "Chemins limités à samples/ et uploads/.",
)

API_OSV = "https://api.osv.dev/v1"
MAX_DEPENDANCES = 60
MAX_DETAILS = 15  # nombre maximal de fiches de vulnérabilité détaillées par analyse

# Nom du module importé -> nom du paquet PyPI (quand ils diffèrent). None = ignorer.
CORRESPONDANCES_PYPI = {
    "yaml": "PyYAML", "bs4": "beautifulsoup4", "PIL": "Pillow", "sklearn": "scikit-learn",
    "cv2": "opencv-python", "dotenv": "python-dotenv", "jwt": "PyJWT", "dateutil": "python-dateutil",
    "Crypto": "pycryptodome", "OpenSSL": "pyOpenSSL", "attr": "attrs", "magic": "python-magic",
    "serial": "pyserial", "docx": "python-docx", "git": "GitPython", "jose": "python-jose",
    "multipart": "python-multipart", "google": None, "mcp_server": None,
}
SPEC_PYTHON = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(==\s*([A-Za-z0-9.*+!-]+))?")
VERSION_EXACTE_NPM = re.compile(r"^\d+\.\d+\.\d+$")


def _ajouter(deps: dict, paquet: str, version: str | None, ecosysteme: str, origine: str) -> None:
    cle = (ecosysteme, paquet.lower())
    if cle not in deps or (version and not deps[cle]["version"]):
        deps[cle] = {"paquet": paquet, "version": version or "", "ecosysteme": ecosysteme, "origine": origine}


def extraire_dependances(cible: Path) -> list[dict]:
    """Lit les fichiers de dépendances et les imports Python, sans rien exécuter."""
    deps: dict = {}
    fichiers = [cible] if cible.is_file() else sorted(p for p in cible.rglob("*") if p.is_file())
    for f in fichiers:
        nom = f.name.lower()  # les imports GitHub sont « aplatis » : src__requirements.txt
        try:
            if re.search(r"requirements[\w.-]*\.txt$", nom):
                for ligne in az.lire_texte(f).splitlines():
                    ligne = ligne.split("#")[0].strip()
                    if ligne.startswith(("-", "git+", "http://", "https://")):  # option, dépôt Git ou URL
                        continue
                    if ligne and (m := SPEC_PYTHON.match(ligne)):
                        _ajouter(deps, m.group(1), m.group(4), "PyPI", f.name)
            elif nom.endswith("pyproject.toml"):
                projet = tomllib.loads(az.lire_texte(f))
                for spec in projet.get("project", {}).get("dependencies", []):
                    if m := SPEC_PYTHON.match(spec):
                        _ajouter(deps, m.group(1), m.group(4), "PyPI", f.name)
                for paquet in projet.get("tool", {}).get("poetry", {}).get("dependencies", {}):
                    if paquet.lower() != "python":
                        _ajouter(deps, paquet, None, "PyPI", f.name)
            elif nom.endswith("package.json"):
                donnees = json.loads(az.lire_texte(f))
                for section in ("dependencies", "devDependencies"):
                    for paquet, version in (donnees.get(section) or {}).items():
                        exacte = str(version) if VERSION_EXACTE_NPM.match(str(version)) else None
                        _ajouter(deps, paquet, exacte, "npm", f.name)
        except (ValueError, tomllib.TOMLDecodeError, AttributeError):
            continue  # fichier mal formé : ignoré, l'analyse continue

    modules_locaux = {p.stem for p in (cible.rglob("*.py") if cible.is_dir() else [cible])}
    for module in az.lister_imports(cible):
        if module in sys.stdlib_module_names or module in modules_locaux or module.startswith("_"):
            continue
        paquet = CORRESPONDANCES_PYPI.get(module, module)
        if paquet:
            _ajouter(deps, paquet, None, "PyPI", "import Python")
    return list(deps.values())[:MAX_DEPENDANCES]


def _osv(chemin: str, corps: dict | None = None) -> dict:
    donnees = json.dumps(corps).encode() if corps is not None else None
    requete = urllib.request.Request(f"{API_OSV}/{chemin}", data=donnees, method="POST" if donnees else "GET",
                                     headers={"Content-Type": "application/json", "User-Agent": "mcp-guard-osv"})
    with urllib.request.urlopen(requete, timeout=20) as r:
        return json.loads(r.read())


def interroger_osv(deps: list[dict]) -> list[dict]:
    """Une seule requête groupée (querybatch), puis le détail des premières vulnérabilités."""
    requetes = [{"package": {"name": d["paquet"], "ecosystem": d["ecosysteme"]},
                 **({"version": d["version"]} if d["version"] else {})} for d in deps]
    resultats = _osv("querybatch", {"queries": requetes}).get("results", [])
    details_restants = MAX_DETAILS
    sortie = []
    for dep, res in zip(deps, resultats, strict=False):  # OSV renvoie une réponse par requête
        ids = [v["id"] for v in res.get("vulns", [])]
        exemples = []
        for id_ in ids[:3]:
            if details_restants <= 0:
                break
            details_restants -= 1
            try:
                v = _osv(f"vulns/{id_}")
                exemples.append({"id": id_, "alias": v.get("aliases", [])[:2],
                                 "resume": (v.get("summary") or "")[:160]})
            except (OSError, ValueError):  # réseau, HTTP ou JSON : la fiche détaillée est facultative
                exemples.append({"id": id_})
        sortie.append({**dep, "version": dep["version"] or "non fixée", "vulnerabilites": len(ids),
                       "exemples": exemples})
    return sortie


@serveur.tool()
def analyser_dependances(chemin: str) -> dict:
    """Extrait les dépendances d'un serveur MCP ou d'une skill (requirements*.txt, pyproject.toml,
    package.json, imports Python) SANS exécuter le code, puis interroge OSV.dev pour lister leurs
    vulnérabilités connues (CVE, GHSA). À utiliser pendant l'audit d'un élément qui a des dépendances.

    Args:
        chemin: dossier ou fichier audité, ex. "samples/01_serveur_sain" ou "uploads/github-org-depot".
    """
    try:
        cible = az.chemin_sur(chemin)
    except (OSError, ValueError) as e:  # hors de samples/ et uploads/, introuvable, chemin invalide
        return {"erreur": f"{type(e).__name__} : {e}"}
    deps = extraire_dependances(cible)
    if not deps:
        return {"chemin": chemin, "nombre_dependances": 0, "info": "Aucune dépendance tierce détectée."}
    try:
        resultats = interroger_osv(deps)
    except (OSError, ValueError, KeyError) as e:  # réseau, HTTP, réponse JSON inattendue
        return {"chemin": chemin, "erreur": f"OSV.dev injoignable : {e}", "dependances": deps}
    vulnerables = [r for r in resultats if r["vulnerabilites"]]
    return {
        "chemin": chemin,
        "source": "OSV.dev (https://osv.dev)",
        "nombre_dependances": len(resultats),
        "paquets_vulnerables": len(vulnerables),
        "dependances": sorted(resultats, key=lambda r: -r["vulnerabilites"]),
        "remarque": "Version « non fixée » : OSV renvoie les failles de toutes les versions publiées du paquet. "
                    "C'est un signal à vérifier avec la version réellement installée, pas une preuve.",
    }


if __name__ == "__main__":
    serveur.run("stdio")

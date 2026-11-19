# Plugin osv-scanner

Plugin Claude Code de MCP-Guard : il recherche les **vulnérabilités connues** (CVE, GHSA) des dépendances
d'un serveur MCP ou d'une skill audité, dans la base publique [OSV.dev](https://osv.dev).

Il complète l'analyse du code par celle de la **chaîne d'approvisionnement** (OWASP MCP04) : un serveur au code
irréprochable peut dépendre d'une bibliothèque vulnérable.

## Contenu

| Fichier | Rôle |
|---|---|
| `.claude-plugin/plugin.json` | Manifeste du plugin (nom, version, description) |
| `.mcp.json` | Déclare le serveur MCP `osv`, lancé en stdio par Claude Code |
| `serveur_osv.py` | Serveur MCP : un tool, `analyser_dependances` |

## Le tool `analyser_dependances(chemin)`

1. **Extraction statique** des dépendances, sans jamais exécuter ni importer le code audité :
   - `requirements*.txt` (y compris les fichiers « aplatis » par l'import GitHub, ex. `src__requirements.txt`) ;
   - `pyproject.toml` (`[project].dependencies` et `[tool.poetry.dependencies]`) ;
   - `package.json` (`dependencies` et `devDependencies`, écosystème npm) ;
   - imports Python : la bibliothèque standard et les modules locaux sont ignorés, et le nom du module est
     converti en nom de paquet PyPI quand ils diffèrent (`yaml` → `PyYAML`, `bs4` → `beautifulsoup4`…).
2. **Une requête groupée** à l'API OSV.dev (`/v1/querybatch`), puis le détail des 15 premières vulnérabilités
   au plus (`/v1/vulns/<id>`).
3. **Résultat** : pour chaque dépendance, le nombre de vulnérabilités connues et quelques exemples (identifiant,
   alias CVE, résumé).

Une version exacte (`==1.2.3` ou `1.2.3` pour npm) donne un résultat précis. Sans version exacte, OSV renvoie les
failles de **toutes** les versions publiées : le résultat est alors un signal à vérifier, pas une preuve.

## Sécurité

- Accès limité à `samples/` et `uploads/` : le tool réutilise `chemin_sur()` du serveur MCP principal (anti path
  traversal) et refuse tout autre chemin, avant toute requête réseau.
- Seuls les noms et les versions des paquets sont envoyés à OSV.dev, jamais le code audité.
- Au plus 60 dépendances analysées ; délai de 20 secondes par requête.

## Chargement

L'agent charge le plugin via `plugins=[...]` dans `backend/agent.py`. Le serveur est lancé avec l'interpréteur
Python du projet, transmis par la variable `MCPGUARD_PYTHON` (définie automatiquement par `backend/agent.py`).
Dans Claude Code, le tool apparaît sous le nom `mcp__plugin_osv-scanner_osv__analyser_dependances`.

## Tests

`tests/test_osv.py` vérifie l'extraction de chaque format de fichier, la conversion des noms de modules, le
refus des chemins hors périmètre et le traitement des réponses OSV.dev (simulées : aucune requête réseau).

```bash
python -m unittest discover -s tests -p "test_osv.py" -v
```

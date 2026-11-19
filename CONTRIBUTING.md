# Contribuer à MCP-Guard

## Installation pour le développement

```bash
python -m venv .venv
# Windows : .\.venv\Scripts\Activate.ps1      Linux / macOS : source .venv/bin/activate
pip install -r requirements-dev.txt
```

Les tests n'ont besoin d'aucun fichier `.env` ni d'aucun compte. Pour lancer l'interface, voir le README
(section « Installation »).

## Avant chaque commit

```bash
python -m ruff check .                          # analyse statique et style (ruff.toml)
python -m unittest discover -s tests -v         # tous les tests (environ 3 secondes)
python -m coverage run -m unittest discover -s tests && python -m coverage report
```

La CI GitHub Actions lance les mêmes commandes à chaque push.

## Écrire un test

- Placer le fichier dans `tests/`, sous le nom `test_<sujet>.py`, et importer `aide_tests` **avant** tout module
  du backend. Ce module vide les secrets, désactive Drive et l'e-mail, et redirige la base SQLite vers un
  dossier temporaire.
- `aide_tests.nouvelle_base()` donne une base vierge par test ; `aide_tests.nouveau_dossier()` donne un dossier
  temporaire (à substituer à `config.UPLOADS` avec `mock.patch.object`).
- Aucun test ne doit appeler l'agent (quota Claude), envoyer un e-mail ou contacter un service réel : simuler
  `urllib.request.urlopen`, `smtplib.SMTP_SSL` ou les fonctions Drive avec `unittest.mock`.

## Conventions

- **Langue** : code, commentaires, messages et documentation en français (noms anglais conservés pour les
  termes techniques : tool, skill, rug pull…).
- **Style** : lignes de 120 caractères au plus, annotations de type sur les fonctions publiques,
  `from __future__ import annotations` en tête de module.
- **Sécurité** :
  - ne jamais exécuter le code audité (analyse statique uniquement) ;
  - tout chemin reçu de l'extérieur passe par `analyzers.chemin_sur()` ;
  - toute valeur SQL passe en paramètre `?` ;
  - toute route de l'API dépend de `verifier_session`, sauf la connexion et les pages de l'interface.
- **Exceptions** : intercepter des exceptions précises. Un `except Exception` n'est admis qu'à une frontière
  documentée (`# noqa: BLE001` et la raison sur la même ligne).
- **Échantillons** : `samples/` contient du code volontairement vulnérable, exclu de ruff. Ne pas le corriger :
  les tests vérifient que chaque échantillon garde son verdict.
- **Secrets** : ne jamais committer `.env`, `credentials.json` ni `token.json` (exclus par `.gitignore`).

## Organisation

Voir le tableau « Organisation du code » du README et le schéma d'architecture.

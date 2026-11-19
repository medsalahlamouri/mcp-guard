# Historique des versions

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).

## [1.1.0] — 2026-11-19

Amélioration de la partie 1 (agent IA) : structure, tests, qualité et sécurité du code, documentation.
Les 9 fonctionnalités de l'énoncé sont inchangées et toutes les URL de l'API sont conservées.

### Structure
- `backend/app.py` découpé en modules : `config.py`, `securite.py` (mot de passe et sessions),
  `planification.py` (ré-audit), `routes/` (`elements`, `audits`, `serveurs`, `systeme`). `app.py` ne fait plus
  qu'assembler l'application ; les 27 routes ont les mêmes URL et les mêmes méthodes.
- `backend/fonctionnalites.py` déplacé dans `backend/demo/` (code de démonstration séparé de la production).
- `frontend/index.html` séparé en `index.html`, `style.css` et `app.js`, avec un contenu identique.
- README allégé : le détail des 9 fonctionnalités n'est plus que dans `docs/FONCTIONNALITES.md`.

### Ajouté
- 87 nouveaux tests (99 au total) : mémoire SQLite, connecteurs (Drive, Gmail et GitHub simulés), sécurité
  de l'API (TestClient), plugin osv-scanner, tâche planifiée, vrai serveur MCP en stdio.
- `requirements-dev.txt`, `ruff.toml`, `.coveragerc` ; la CI lance ruff, les tests et publie la couverture.
- Schéma d'architecture Mermaid, `CONTRIBUTING.md`, `plugin/osv-scanner/README.md`, ce fichier.
- Variable facultative `MCPGUARD_BASE` (chemin de la base SQLite) : les tests, serveur MCP compris, travaillent
  sur une base temporaire et ne touchent jamais `data/mcp_guard.db`.
- Détection du rug pull « par le code seul » : une modification du code qui laisse les descriptions de
  tools intactes suspend aussi l'approbation, et la nouvelle version est réauditée.

### Modifié (comportement visible)
- Sessions de l'interface : expiration au bout de 12 h (cookie `max_age`), 50 sessions au plus, pause d'une
  seconde après un mot de passe faux. Un mot de passe accentué ne provoque plus d'erreur 500.
- Corps de requête JSON validés par Pydantic : un corps invalide renvoie **422** (au lieu de 500).
- Dépôt de fichiers : tout est validé avant d'écrire. Si un fichier est refusé (extension, taille), **rien**
  n'est enregistré (auparavant, les fichiers refusés étaient ignorés sans rien dire et les autres enregistrés).
- Import GitHub :
  - URL validée strictement (« .. » refusé, liens `/blob/` refusés avec un message explicite) ;
  - dépôt sans fichier analysable : erreur 404 au lieu d'un succès vide ;
  - le dossier vide créé en cas d'échec est supprimé.
- Connecteur Gmail considéré comme configuré si le destinataire vient des Préférences (même règle que l'envoi).
- `claude_desktop_config.example.json` : chemins remplacés par `<CHEMIN_DU_PROJET>` (exemple portable).

### Corrigé
- Plugin osv-scanner (version 1.0.1) : les paquets dont le nom commence par « http » (`httpx`, `httplib2`, `httpcore`…)
  étaient ignorés dans les fichiers `requirements*.txt`.
- Mémoire SQLite : les connexions n'étaient jamais fermées ; le schéma était réappliqué à chaque requête.
- Import GitHub : `github.com/../../x` était accepté et produisait une requête vers une URL invalide.
- Analyse statique : un fichier contenant un octet nul faisait échouer l'audit.

### Sécurité et qualité
- Noms de tables SQL contrôlés par une liste blanche (les valeurs restent passées en paramètres).
- Exceptions précises (SMTP, Drive, réseau, analyse) à la place des `except Exception`. Les quatre qui
  restent sont des frontières volontaires et documentées : agent, ré-audit, cartes de démonstration.
- Code SMTP factorisé (`connexion_smtp`), lecture des fichiers déposés bornée à 1 Mo.
- Ruff sans avertissement sur tout le code (hors `samples/`, volontairement vulnérable).

## [1.0.0] — 2026-11-18

Première version publiée : agent d'audit, 16 tools MCP, 3 skills, 2 plugins, connecteurs GitHub, Google Drive
et Gmail, mémoire SQLite, tâche planifiée, interface web et 12 tests du moteur d'analyse.

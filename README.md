# MCP-Guard — agent d'audit de sécurité des serveurs MCP et des skills

**Auteur** : Mohamed Salah Lamouri — RSI3, ISET Nabeul

MCP-Guard est un agent IA qui audite un **serveur MCP** ou une **skill** *avant* son installation. Il détecte
le tool poisoning, l'injection de commande, le path traversal, les secrets en dur, l'exfiltration de données,
les dépendances vulnérables et les modifications après approbation (« rug pull »), puis recommande une
décision — **INSTALLER**, **CORRIGER** ou **REJETER** — selon l'OWASP MCP Top 10 (2025). Chaque rapport est
archivé dans Google Drive et notifié par e-mail.


---

## 1. Architecture

```
Navigateur (http://127.0.0.1:8000, mot de passe)
        │
        ▼
Backend FastAPI (backend/app.py) ─── SQLite : mémoire à long terme (data/mcp_guard.db)
   │   ├─ APScheduler : ré-audit planifié (rug pull, sans LLM)
   │   └─ Connecteurs (backend/connecteurs.py), après CHAQUE audit :
   │        audit → SQLite → Google Drive (rapport) → Gmail (notification + lien Drive)
   │        + GitHub (import d'un dépôt à auditer)
   ▼
Claude Agent SDK (backend/agent.py) ── compte Claude (OAuth Claude Code, sans clé API)
   │   outils natifs : Skill uniquement (ni Bash, ni Read, ni Write) · mode dontAsk
   ├── MCP stdio « mcp-guard »         (mcp_server/server.py)  : 16 tools d'analyse et de mémoire
   ├── MCP in-process « connecteurs »  (backend/agent.py)      : alerte e-mail (destinataire fixé)
   ├── Plugin « mcp-guard »            (plugin/mcp-guard)      : skills rapport-audit-mcp, analyse-skill-md
   └── Plugin « osv-scanner »          (plugin/osv-scanner)    : serveur MCP → API OSV.dev
```

## 2. Les 9 fonctionnalités de l'énoncé

| # | Fonctionnalité | Réalisation | Fichiers |
|---|---|---|---|
| 1 | Instructions | System prompt : rôle, 14 règles numérotées, contraintes, préférences injectées | `backend/instructions.md` |
| 2 | Skills | `rapport-audit-mcp` (méthode + format du rapport), `analyse-skill-md` (audit d'un SKILL.md), `analyse-json-mcp` (audit d'un fichier JSON MCP) | `plugin/mcp-guard/skills/` |
| 3 | Tools | 16 tools Python : analyse AST/regex/JSON, empreintes, SQL, RAG, API OSV | `mcp_server/` |
| 4 | Connecteurs | GitHub (API + jeton), Google Drive (archivage), Gmail (notification), déclenchés par le backend | `backend/connecteurs.py`, `backend/app.py` |
| 5 | Plugins | Plugins Claude Code `mcp-guard` et `osv-scanner` (dépendances → OSV.dev) | `plugin/` |
| 6 | MCP | 3 serveurs (stdio, in-process, plugin), moindre privilège | `mcp_server/server.py`, `backend/agent.py` |
| 7 | Knowledge base | OWASP MCP Top 10, grille de scoring, politique d'approbation + `rechercher_knowledge` | `knowledge/` |
| 8 | Mémoire | Court terme : sessions reprises. Long terme : SQLite (audits, empreintes, alertes, journal, préférences) | `mcp_server/registry.py` |
| 9 | Authentification | OAuth Claude, OAuth2 Google (`drive.file`), mot de passe d'application Gmail, jeton GitHub, mot de passe de l'interface | `.env`, `credentials.json`, `token.json` |
| ★ | Bonus | Tâche planifiée de ré-audit (détection du rug pull) | `backend/app.py` |

L'onglet **Fonctionnalités** de l'interface affiche chaque fonctionnalité, sa justification, son état en direct
et un bouton *Tester* (tests réels **sans LLM** : aucun quota consommé, aucun e-mail envoyé). *Tout tester* doit
afficher **9/9**.

## 3. Installation sous Windows (PowerShell)

**Prérequis** : Python 3.11+ et Claude Code installé et connecté à votre compte Claude (`claude` puis `/login`).

```powershell
cd C:\chemin\vers\mcp-guard
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env      # puis renseigner .env (voir ci-dessous)
python run.py                    # puis ouvrir http://127.0.0.1:8000
```

### Configuration (`.env`, jamais partagé)

| Variable | Rôle | Obligatoire |
|---|---|---|
| `MCPGUARD_MOT_DE_PASSE` | Mot de passe de l'interface | oui |
| `SMTP_UTILISATEUR`, `SMTP_MOT_DE_PASSE`, `ALERTE_DESTINATAIRE` | Gmail : adresse, **mot de passe d'application** (compte Google → Sécurité → validation en 2 étapes → Mots de passe des applications), destinataire | pour les e-mails |
| `GITHUB_TOKEN` | Jeton GitHub (5 000 requêtes/h au lieu de 60) | conseillé |
| `NOTIFICATION_CHAQUE_AUDIT`, `DRIVE_ACTIVE` | `1`/`0` : activer ou couper l'e-mail et l'archivage après chaque audit | non (défaut 1) |
| `MCPGUARD_MODELE` | `sonnet` (recommandé) ou `opus` | non |
| `MCPGUARD_REAUDIT_MINUTES` | Ré-audit toutes les N minutes (démonstration) ; `0` = chaque jour à `MCPGUARD_REAUDIT_HEURE` | non |

Sans SMTP, les e-mails sont enregistrés dans `data/outbox/` (mode démonstration).

### Google Drive (OAuth2, une seule fois)

1. Google Cloud Console → nouveau projet → *API et services* → activer **Google Drive API**.
2. *Écran de consentement OAuth* : type **Externe**, ajouter votre adresse dans **Utilisateurs test**.
3. *Identifiants* → **ID client OAuth** de type **« Application de bureau »** → télécharger le JSON, le renommer
   **`credentials.json`** et le placer à la racine du projet (attention à Windows qui masque les extensions :
   le fichier ne doit pas s'appeler `credentials.json.json`).
4. `python -m backend.autoriser_drive` → accepter dans le navigateur → `token.json` est créé (scope `drive.file`
   uniquement : MCP-Guard ne voit que les fichiers qu'il crée).

En mode « Test », Google fait expirer le jeton après 7 jours : relancer l'étape 4.

> **Quota** : l'Agent SDK consomme les limites d'usage de l'abonnement Claude, comme le chat. Désactivez les
> « usage credits » dans claude.ai/settings/usage pour ne jamais être facturé. Les tests de l'onglet
> Fonctionnalités, la tâche planifiée, Drive et Gmail ne consomment aucun quota.

## 4. Utilisation

| Onglet | Usage |
|---|---|
| **Audit** | Choisir un élément (échantillon, dépôt de fichiers, import GitHub) → *Lancer l'audit* → rapport, constats, liens Drive/e-mail ; poser des questions de suivi (conversation reprenable) |
| **Historique** | Tous les audits, avec le lien du rapport dans Drive et l'état de l'e-mail |
| **Serveurs approuvés** | Serveurs installés et surveillés (empreinte SHA-256) ; simulation d'une mise à jour malveillante |
| **Planification et alertes** | Ré-audit planifié, exécution manuelle, alertes |
| **Fonctionnalités** | Les 9 fonctionnalités de l'énoncé, état en direct, *Tester* / *Tout tester* |
| **Préférences** | Niveau de détail des rapports (synthétique, standard, détaillé), adresse de notification |

Le panneau **Connecteurs** (barre latérale) affiche l'état de Gmail, Drive et GitHub ; un clic lance un test.

**Détection du rug pull** : le ré-audit compare l'empreinte des définitions de tools *et* celle du code source.
Une mise à jour qui garde des descriptions identiques mais ajoute une exfiltration dans le code est donc aussi
détectée ; la nouvelle version est alors réauditée (analyse statique) et son verdict est cité dans l'alerte.

### Tests automatisés

```powershell
python -m unittest discover -s tests -v
```

12 tests de non-régression, sans LLM ni réseau : verdict attendu de chaque échantillon, détection du rug pull
(tools modifiés, code seul modifié), refus du path traversal, masquage des secrets. Ils sont exécutés par
GitHub Actions à chaque push (`.github/workflows/tests.yml`).

## 5. Sécurité de l'agent lui-même

- Analyse **statique** uniquement : le code audité n'est jamais exécuté.
- Outils natifs réduits à `Skill`, liste blanche de 18 tools, mode `dontAsk`, aucun réglage ni connecteur du
  compte utilisateur chargé dans l'agent.
- Accès fichiers limité à `samples/` et `uploads/` (`chemin_sur`, anti path traversal), y compris pour le plugin.
- Destinataire des e-mails fixé par l'utilisateur, jamais par l'agent ; secrets masqués dans les e-mails et les
  rapports archivés ; SMTP avec vérification du certificat TLS.
- Interface liée à `127.0.0.1`, mot de passe comparé à temps constant, cookie HttpOnly/SameSite, rapports
  assainis contre le XSS (DOMPurify), journal de toutes les actions.

## 6. Livrable : archive sans secrets

```powershell
$tmp = "$env:TEMP\mcp-guard-livrable"; robocopy . $tmp /E /XD .venv data uploads __pycache__ /XF .env credentials.json token.json | Out-Null
Compress-Archive -Path "$tmp\*" -DestinationPath "$HOME\Desktop\mcp-guard-livrable.zip" -Force; Remove-Item $tmp -Recurse -Force
```

## 7. Utilisation dans Claude Desktop (facultatif)

Le serveur MCP fonctionne aussi dans Claude Desktop : copier `claude_desktop_config.example.json` dans
`%APPDATA%\Claude\claude_desktop_config.json`, adapter les chemins, redémarrer Claude Desktop.

## 8. Limites

- Analyse statique par règles : faux positifs ou négatifs possibles ; le verdict est une aide à la décision
  soumise à validation humaine.
- Analyse de code approfondie limitée au **Python** (autres langages : secrets et dépendances seulement).
- Knowledge base interrogée par recherche lexicale (suffisante pour 3 documents).
- La base OWASP MCP Top 10 est en version **bêta** : ses catégories peuvent évoluer.

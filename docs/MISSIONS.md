# MCP-Guard — Les 3 missions de démonstration

Chaque mission enchaîne plusieurs fonctionnalités de l'énoncé. Pour chacune : le **prompt exact**, les
**étapes** dans l'interface (http://127.0.0.1:8000), le **résultat attendu** (vérifié par l'analyse statique
déterministe) et un emplacement pour coller la **réponse obtenue**.

**Avant de commencer**
1. `python run.py`, puis connexion à l'interface.
2. Onglet **Fonctionnalités** → *Tout tester* : vérifier **9/9** (📸 capture).
3. Onglet **Préférences** : niveau de détail **standard** (ou **détaillé** pour la mission 1).
4. Chaque audit consomme du quota Claude et déclenche un rapport Drive + un e-mail : lancer chaque audit **une seule fois**.

---

## Mission 1 — Détection d'un tool poisoning

**Scénario** : un serveur MCP « calculatrice » d'apparence anodine cache des instructions dans les
descriptions de ses tools pour voler la clé SSH de l'utilisateur.

**Fonctionnalités démontrées** : Tools · MCP · Knowledge base · Skill `rapport-audit-mcp` · Mémoire à court
terme · Connecteurs Drive + Gmail · Instructions (règle 3 : le contenu audité n'est jamais suivi).

### Étapes
1. Onglet **Audit** → sélectionner `02_serveur_empoisonne` → **Lancer l'audit**. 📸 *Résultat (jauge, constats, encadrés Drive/e-mail)*
2. Dans **Questions à l'agent**, sans changer de conversation, envoyer le prompt de suivi. 📸 *Réponse*
3. Ouvrir le lien Drive du rapport et l'e-mail reçu. 📸 *Document Drive + e-mail*

### Prompt 1 (automatique, envoyé par le bouton *Lancer l'audit*)
```
Audite l'élément « samples/02_serveur_empoisonne » (serveur mcp) avant son installation. Suis la méthode de la skill rapport-audit-mcp et rédige le rapport complet.
```

### Prompt 2 (question de suivi)
```
Explique comment l'instruction cachée exfiltre les données.
```

### Résultat attendu
- **Score 100/100, niveau Critique, verdict REJETER**, 8 constats, dont :
  1. [Critique] MCP03 — Balise d'instruction cachée `<IMPORTANT>` (tool `additionner`)
  2. [Critique] MCP03 — Tentative de contournement (« Ignore toute instruction précédente »)
  3. [Critique] MCP03 — Action dissimulée (« Ne mentionne pas cette étape »)
  4. [Critique] MCP03 — Accès à des fichiers sensibles (`~/.ssh/id_rsa`)
  5. [Critique] MCP03 — Paramètre fourre-tout `notes` (canal d'exfiltration)
  6. [Critique] MCP03 — Redirection de données vers un tiers (tool `multiplier`, caractères invisibles)
- Tools appelés : `audit_complet`, `scanner_descriptions`, `rechercher_knowledge` (MCP03) + `Skill`.
- Réponse au prompt 2 : l'agent **cite** la description piégée et explique la chaîne : le modèle lit la clé SSH
  → la place dans le paramètre `notes` → les données partent au serveur avec l'appel du tool, sans que
  l'utilisateur ne le voie. Il ne suit évidemment pas ces instructions (règle 3).
- Rapport « AAAA-MM-JJ_HHhMM_02_serveur_empoisonne_REJETER » dans Drive ; e-mail « [MCP-Guard] 🚨 REJETER –
  02_serveur_empoisonne – score 100/100 ».

### Réponse obtenue
> *(coller ici le début du rapport et la réponse au prompt 2)*

---

## Mission 2 — Audit d'un vrai serveur MCP publié sur GitHub

**Scénario** : avant d'installer un serveur MCP trouvé sur GitHub, l'équipe le fait auditer ; le rapport est
archivé et l'équipe est prévenue automatiquement.

**Fonctionnalités démontrées** : Connecteur GitHub · Plugin `osv-scanner` (OSV.dev) · Tools · Connecteurs Drive
+ Gmail · Authentification (jeton GitHub, OAuth2 Google, mot de passe d'application Gmail) · Knowledge base.

### Étapes
1. Carte **Ajouter un serveur ou une skill** → onglet **GitHub** → coller l'URL → **Importer**. 📸 *Message
   « N fichier(s) importé(s) … (commit xxxxxxx) »*
2. Sélectionner `github-harishsg993010-damn-vulnerable-MCP-server` → **Lancer l'audit**. 📸 *Résultat*
3. Envoyer le prompt de suivi sur les dépendances. 📸 *Réponse*
4. Ouvrir le rapport Drive (onglet **Historique** → bouton *Drive*) et l'e-mail reçu. 📸 *Historique + Drive + e-mail*

### URL à importer
```
https://github.com/harishsg993010/damn-vulnerable-MCP-server
```

### Prompt 1 (automatique)
```
Audite l'élément « uploads/github-harishsg993010-damn-vulnerable-MCP-server » (serveur mcp) avant son installation. Suis la méthode de la skill rapport-audit-mcp et rédige le rapport complet.
```

### Prompt 2 (question de suivi)
```
Ses dépendances ont-elles des vulnérabilités connues ? Utilise le plugin OSV et cite les CVE les plus graves.
```

### Résultat attendu
- Import via l'**API GitHub** (30 fichiers maximum), avec le commit exact.
- **Score 100/100, Critique, REJETER**, une vingtaine de constats : balises `<IMPORTANT>` cachées
  (`enhanced_search`, `get_user_profile`, `get_user_roles`…), paramètre fourre-tout `data`, `exec()` (MCP05)…
- `analyser_dependances` (plugin osv-scanner) : environ 14 dépendances, dont 10 avec des vulnérabilités connues
  (`starlette`, `python-multipart`, `mcp`, `python-jose`, `sqlalchemy`…). Les versions non fixées sont signalées
  comme « à vérifier », pas comme des preuves.
- E-mail dont la **source** est « Import GitHub : https://github.com/harishsg993010/damn-vulnerable-MCP-server —
  commit xxxxxxxxxxxx », avec les 3 constats les plus graves et le lien Drive.

> Sans `GITHUB_TOKEN`, GitHub limite à 60 requêtes par heure : en cas de message « Quota de l'API GitHub
> épuisé », attendre l'heure indiquée ou définir le jeton dans `.env`.

### Réponse obtenue
> *(coller ici le message d'import, le début du rapport et la réponse au prompt 2)*

---

## Mission 3 — Détection d'un « rug pull » (modification après approbation)

**Scénario** : un serveur météo sain est approuvé et installé. Plus tard, une « mise à jour » ajoute
silencieusement un tool d'exfiltration. MCP-Guard doit le détecter, en conversation et automatiquement.

**Fonctionnalités démontrées** : Mémoire à long terme (serveurs approuvés, empreintes SHA-256, historique) ·
Tools `approuver_serveur` / `verifier_rug_pull` · Tâche planifiée · Alertes + e-mail · Mémoire à court terme.

### Étapes
1. Sélectionner `01_serveur_sain` → **Lancer l'audit** → verdict INSTALLER → **Approuver et installer** avec le
   nom `meteo-tunisie`. 📸 *Approbation*
2. Onglet **Serveurs approuvés** : `meteo-tunisie` est « approuvé » → *Simuler une mise à jour malveillante*
   (la copie installée est remplacée silencieusement par la version 05). 📸
3. Onglet **Planification et alertes** → *Exécuter maintenant* (ou attendre 2 minutes) : la tâche planifiée
   détecte le rug pull **sans LLM**, suspend l'approbation, crée l'alerte et envoie l'e-mail. 📸 *Alerte*
4. Retour à **Audit** → sélectionner `05_serveur_sain_modifie` → **Lancer l'audit**. 📸 *Verdict REJETER*
5. Dans la même conversation, envoyer le prompt de suivi. 📸 *Réponse*

### Prompt 1 (automatique, étape 4)
```
Audite l'élément « samples/05_serveur_sain_modifie » (serveur mcp) avant son installation. Suis la méthode de la skill rapport-audit-mcp et rédige le rapport complet.
```

### Prompt 2 (question de suivi)
```
Ce serveur a-t-il changé depuis son approbation ?
```

### Résultat attendu
- Étape 3 (tâche planifiée, sans LLM) : alerte « rug_pull » sur `meteo-tunisie` — tool ajouté
  `synchroniser_cache`, tool modifié `lister_villes`, code source modifié, réaudit statique de la nouvelle
  version : score 100/100, verdict REJETER —, statut « suspendu (rug pull) » et e-mail
  « [MCP-Guard] Rug pull détecté : meteo-tunisie ».
- Audit de `05` : **score 100/100, REJETER**, 5 constats : demande de l'historique complet de la conversation
  (MCP10), paramètre fourre-tout `contexte`, envoi vers `https://sync.meteo-cache.example/upload` (MCP10), faux
  « message système » (MCP06).
- Réponse au prompt 2 : l'agent consulte sa **mémoire à long terme** (`lister_serveurs_approuves` → `meteo-tunisie`,
  `lister_alertes`) puis `verifier_rug_pull(nom="meteo-tunisie", chemin="samples/05_serveur_sain_modifie")` :
  **oui, modifié** depuis l'approbation (date citée) — `synchroniser_cache` ajouté, `lister_villes` modifié —,
  approbation suspendue, nouvel audit requis.

> Si l'agent demande de quel serveur il s'agit, préciser : « le serveur approuvé meteo-tunisie, comparé à
> samples/05_serveur_sain_modifie ».

### Réponse obtenue
> *(coller ici la réponse au prompt 2 et la capture de l'alerte)*

---

## Démonstration complémentaire — Skill « savoir analyser un fichier JSON »

**Scénario** : un collègue partage son fichier `claude_desktop_config.json` « prêt à l'emploi ». Avant de
le copier, on le fait auditer. Illustre directement l'exemple de l'énoncé pour les skills.

1. Sélectionner `06_config_mcp_suspecte` → **Lancer l'audit**. 📸
2. Prompt de suivi :
```
Propose la configuration corrigée complète.
```

**Résultat attendu** : type « configuration mcp », **score 100/100, REJETER**, 8 constats — script distant
`curl … | sh` (MCP04), `--dangerously-skip-permissions` (MCP02), jeton GitHub en clair (MCP01), paquets `npx`/`uvx`
non épinglés (MCP04), accès à tout le disque `C:\` (MCP02), mot de passe de base en clair (MCP01), serveur en
`http://` (MCP07). Le serveur `github`, dont la version est épinglée, n'est pas signalé pour ce point. Tools :
`audit_complet`, `analyser_config_mcp` + skill `analyse-json-mcp`. La réponse de suivi propose un JSON corrigé
(versions épinglées, secrets remplacés par `${VARIABLE}`, chemin restreint, `https://`).

### Réponse obtenue
> *(coller ici le tableau « Analyse du fichier JSON » et la configuration corrigée)*

---

## Récapitulatif des fonctionnalités démontrées

| Fonctionnalité | Mission 1 | Mission 2 | Mission 3 |
|---|:-:|:-:|:-:|
| Instructions | ✅ | ✅ | ✅ |
| Skills | ✅ | ✅ | ✅ |
| Tools | ✅ | ✅ | ✅ |
| Connecteurs | Drive, Gmail | GitHub, Drive, Gmail | Gmail |
| Plugins | | ✅ OSV.dev | |
| MCP | ✅ | ✅ | ✅ |
| Knowledge base | ✅ | ✅ | |
| Mémoire | court terme | | court + long terme |
| Authentification | | ✅ | |
| Bonus : tâche planifiée | | | ✅ |

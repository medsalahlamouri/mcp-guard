# Référentiel — OWASP MCP Top 10 (2025, version bêta)

Source : projet OWASP « MCP Top 10 » (owasp.org/www-project-mcp-top-10), version bêta v0.1,
phase 3 « Beta Release and Pilot Testing ». Les intitulés peuvent encore évoluer.
Résumé rédigé pour MCP-Guard : chaque catégorie indique ce que l'auditeur doit rechercher.

---

## MCP01:2025 — Token Mismanagement & Secret Exposure
**Risque** : jetons, clés API ou mots de passe exposés (en dur dans le code, dans les logs,
dans la mémoire du modèle ou dans une description de tool).
**Indicateurs** : chaînes `AKIA…`, `ghp_…`, `sk-…`, `xox…`, blocs `-----BEGIN PRIVATE KEY-----`,
variables `*_TOKEN = "…"`, secret envoyé dans une requête sortante.
**Remédiation** : variables d'environnement ou coffre de secrets, jetons à courte durée de vie
et à portée minimale, rotation immédiate de tout secret exposé.

## MCP02:2025 — Privilege Escalation via Scope Creep
**Risque** : un serveur ou un tool obtient plus de droits que nécessaire, ou ses droits
s'élargissent avec le temps (lecture seule → écriture → suppression).
**Indicateurs** : un tool dont le nom ou la description annonce une lecture mais dont le code
supprime, écrit ou exécute ; permissions OAuth trop larges ; accès au système de fichiers entier.
**Remédiation** : moindre privilège, portées explicites, revue de chaque mise à jour.

## MCP03:2025 — Tool Poisoning
**Risque** : des instructions malveillantes sont cachées dans les métadonnées d'un tool
(nom, description, schéma des paramètres). Le modèle lit ces métadonnées comme un contexte
de confiance et peut être amené à exfiltrer des données ou contourner l'utilisateur.
**Indicateurs** : balises `<IMPORTANT>`, « ignore les instructions précédentes »,
« ne le dis pas à l'utilisateur », références à `~/.ssh`, `.env`, `id_rsa`, `credentials`,
caractères invisibles (zero-width), paramètres fourre-tout (`notes`, `contexte`, `metadata`)
sans lien avec la fonction, instructions visant d'autres tools (shadowing).
**Remédiation** : analyser et épingler (hash) les descriptions, refuser les serveurs non signés,
afficher à l'utilisateur la description complète des tools.

## MCP04:2025 — Software Supply Chain Attacks & Dependency Tampering
**Risque** : paquet ou serveur compromis, typosquatting, mise à jour malveillante après
approbation (« rug pull »).
**Indicateurs** : empreinte des définitions de tools ou du code modifiée depuis l'approbation, dépendance
inconnue ou récente, script d'installation `curl … | bash`.
**Remédiation** : épingler les versions et les empreintes, réauditer chaque mise à jour,
vérifier les vulnérabilités connues (OSV, CVE).

## MCP05:2025 — Command Injection & Execution
**Risque** : une entrée contrôlée par le modèle ou l'utilisateur atteint un shell ou un
interpréteur.
**Indicateurs** : `subprocess(..., shell=True)` avec une f-string, `os.system`, `os.popen`,
`eval`, `exec`, `pickle.loads`, `yaml.load` non sécurisé, chemins de fichiers non normalisés
(path traversal `../`).
**Remédiation** : listes d'arguments sans shell, validation stricte (liste blanche, regex),
`os.path.realpath` + vérification du répertoire racine, formats de données sûrs (JSON).

## MCP06:2025 — Prompt Injection via Contextual Payloads
**Risque** : des contenus lus par l'agent (résultats de tools, fichiers, pages web, e-mails)
contiennent des instructions que le modèle exécute.
**Indicateurs** : tool qui renvoie du texte externe brut sans le marquer comme donnée.
**Remédiation** : traiter tout résultat de tool comme une donnée, jamais comme une instruction ;
confirmation humaine pour les actions sensibles.

## MCP07:2025 — Insufficient Authentication & Authorization
**Risque** : serveur MCP distant sans authentification, ou qui ne vérifie pas les droits de
l'appelant.
**Indicateurs** : transport HTTP/SSE sans jeton, absence d'OAuth 2.1, endpoints publics.
**Remédiation** : OAuth 2.1, vérification du jeton à chaque requête, contrôle d'accès par tool.

## MCP08:2025 — Lack of Audit and Telemetry
**Risque** : absence de journalisation des appels de tools, impossible d'enquêter après incident.
**Remédiation** : journal immuable des appels (qui, quel tool, quels paramètres, quand).

## MCP09:2025 — Shadow MCP Servers
**Risque** : serveurs non approuvés connectés en dehors de toute gouvernance.
**Remédiation** : inventaire, liste blanche des serveurs approuvés, découverte continue.

## MCP10:2025 — Context Injection & Over-Sharing
**Risque** : des données sensibles d'une tâche, d'un utilisateur ou d'un tenant fuient vers
un autre via le contexte partagé.
**Indicateurs** : tool qui demande « tout l'historique de la conversation », l'environnement
complet (`os.environ`) ou plus de contexte que sa fonction ne l'exige.
**Remédiation** : contexte minimal par tâche, mémoire éphémère, filtrage des données sensibles.

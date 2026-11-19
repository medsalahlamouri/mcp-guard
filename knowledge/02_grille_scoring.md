# Grille de scoring des risques — MCP-Guard

Cette grille transforme les constats techniques en un **score de risque sur 100** et en un
**verdict**. Elle est appliquée de la même façon à chaque audit pour garantir des résultats
reproductibles.

## 1. Gravité d'un constat

| Gravité | Points | Définition | Exemples |
|---|---|---|---|
| **Critique** | 40 | Exploitation directe possible : exfiltration, exécution de code, prise de contrôle | Tool poisoning avec exfiltration, `shell=True` sur une entrée, `eval` sur une entrée, rug pull |
| **Élevée** | 20 | Faille exploitable sous conditions ou fuite de secret | Secret en dur, path traversal, `pickle.loads`, envoi de données vers un hôte inconnu |
| **Moyenne** | 10 | Mauvaise pratique qui affaiblit la sécurité | Description incohérente avec le code, paramètre fourre-tout, accès à `os.environ` |
| **Faible** | 3 | Point d'amélioration sans impact direct | Absence de validation de type, journalisation absente |
| **Info** | 0 | Observation neutre | Dépendance réseau légitime documentée |

## 2. Calcul du score

```
score = min(100, somme des points de tous les constats)
```

Un constat identique répété dans plusieurs tools n'est compté **qu'une fois par tool**.

## 3. Niveau de risque et verdict

| Score | Niveau | Verdict | Action attendue |
|---|---|---|---|
| 0 – 9 | Faible | **INSTALLER** | Installation autorisée, empreinte enregistrée |
| 10 – 29 | Modéré | **CORRIGER** | Installation après correction des constats |
| 30 – 59 | Élevé | **CORRIGER** | Correction obligatoire et nouvel audit |
| 60 – 100 | Critique | **REJETER** | Installation interdite, alerte à l'équipe sécurité |

**Règle absolue** : tout constat de gravité **Critique** de type tool poisoning, exfiltration
ou rug pull impose le verdict **REJETER**, quel que soit le score total.

## 4. Correspondance avec l'OWASP MCP Top 10

Chaque constat doit être rattaché à une catégorie : MCP01 (secrets), MCP02 (privilèges),
MCP03 (tool poisoning), MCP04 (chaîne d'approvisionnement, rug pull), MCP05 (injection de
commande), MCP06 (prompt injection), MCP07 (authentification), MCP08 (journalisation),
MCP09 (serveurs fantômes), MCP10 (sur-partage de contexte).

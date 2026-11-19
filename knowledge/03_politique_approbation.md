# Politique d'approbation des serveurs MCP et des skills

**Organisation** : ISET Nabeul — Laboratoire RSI (organisation fictive de démonstration)
**Version** : 1.0 — novembre 2026
**Propriétaire** : équipe sécurité du laboratoire

## 1. Objet

Tout serveur MCP ou toute skill destiné à être connecté à un agent IA du laboratoire doit être
**audité par MCP-Guard avant installation**. Cette politique fixe les règles d'approbation.

## 2. Règles d'approbation

1. **Audit préalable obligatoire** : aucun serveur MCP ni aucune skill n'est installé sans un
   rapport d'audit MCP-Guard daté.
2. **Verdict contraignant** : seul le verdict **INSTALLER** autorise l'installation.
   Un verdict **CORRIGER** impose un nouvel audit après correction. Un verdict **REJETER**
   interdit l'installation.
3. **Empreinte d'approbation** : à l'approbation, l'empreinte SHA-256 des définitions de tools
   est enregistrée dans le registre des serveurs approuvés.
4. **Réaudit automatique** : les serveurs approuvés sont réaudités automatiquement chaque jour.
   Toute modification d'empreinte suspend l'approbation (scénario « rug pull ») et déclenche
   une alerte.
5. **Interdictions absolues** : sont refusés sans discussion les serveurs ou skills qui
   - contiennent des instructions cachées destinées au modèle ;
   - lisent ou transmettent des secrets (`~/.ssh`, `.env`, identifiants cloud, variables
     d'environnement) sans nécessité documentée ;
   - exécutent des commandes shell construites à partir d'entrées non validées ;
   - demandent de désactiver les confirmations de l'utilisateur ;
   - envoient des données vers des hôtes non documentés.

## 3. Alerte de sécurité

En cas de verdict **REJETER** ou de rug pull détecté, une alerte est envoyée par e-mail à
l'équipe sécurité. Elle contient : le nom du serveur, le score, les constats critiques,
le verdict et la recommandation.

## 4. Rôles

| Rôle | Responsabilité |
|---|---|
| Demandeur | Soumet le serveur ou la skill à MCP-Guard |
| MCP-Guard (agent) | Réalise l'audit, rédige le rapport, propose un verdict |
| Équipe sécurité | Valide le verdict et décide de l'approbation finale |

## 5. Limite

MCP-Guard réalise une **analyse statique** : il ne peut pas garantir l'absence de toute faille.
Le verdict de l'agent reste une **aide à la décision** soumise à validation humaine.

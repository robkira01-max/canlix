# ADR 0001 — Architecture du SaaS Canlix (M7)

**Statut :** PROPOSÉ — noyau implémenté et testé (`saas/`), couche HTTP et base de données à faire.
**Date :** 2026-11-12
**Relecture requise avant toute mise en production :** `security-reviewer` (authentification, isolation des tenants, ingestion).

## Contexte

Canlix est un scanner local-first : il fonctionne sans compte, sans clé et sans envoi de fichiers. Le SaaS ajoute ce qu'un CLI ne peut pas offrir : historique, comparaison entre scans, multi-projets, équipes. Le cahier de cadrage (§15) précise de ne le construire qu'après une adoption récurrente de l'outil open source. Ce document fixe les décisions de conception pour que le moment venu l'implémentation soit mécanique, sans remettre en cause le principe « local-first ».

## Décisions

### 1. Monolithe modulaire FastAPI + PostgreSQL
Un seul service, un seul schéma. **Pourquoi :** une équipe d'une personne, aucun besoin de mise à l'échelle indépendante démontré. Les microservices ajouteraient de l'exploitation sans bénéfice. Même schéma d'architecture que LexBouti, ce qui réduit la charge de maintenance.

### 2. Le SaaS ingère des rapports, jamais du code ni des configurations
Le point d'entrée accepte le JSON produit par `canlix scan/analyze`. Le modèle d'ingestion (`saas/ingest.py`) utilise `extra="ignore"` : `code_snippet`, `evidence` et les détails de sondes sont **supprimés par construction**, pas par filtrage. Les chaînes conservées (message, emplacement, remédiation) sont re-masquées côté serveur avec le même détecteur de secrets que le Runtime Analyzer. Le score est **recalculé** côté serveur.
**Pourquoi :** un rapport peut contenir du code propriétaire ou des secrets collés par erreur. Ne jamais stocker ce qui n'est pas indispensable est la seule défense qui ne dépend pas d'une configuration correcte. Un client malveillant ou bogué ne peut pas non plus truquer son score.
**Alternative rejetée :** téléverser les sources pour analyse serveur — détruit l'argument de confidentialité face à Snyk et Cisco, et déplace la responsabilité d'une fuite chez nous.

### 3. Isolation multi-tenant par organisation
- `org_id` est **dérivé du jeton d'API**, jamais lu dans le corps ou l'URL.
- Chaque méthode du `Store` reçoit `org_id` et renvoie `None` pour une ligne d'un autre tenant ; la couche HTTP traduit en **404** (pas 403), afin de ne pas révéler l'existence d'une ressource.
- PostgreSQL : ajouter la sécurité au niveau des lignes (RLS) avec `org_id` comme défense en profondeur, en plus du filtrage applicatif.
**Pourquoi :** l'erreur classique d'un SaaS multi-tenant est une requête sans filtre. Le contrat « org_id obligatoire » rend cette erreur impossible à écrire par inadvertance, et la RLS la rend inoffensive si elle survient.

### 4. Jetons d'API
Format `cnx_` + 256 bits aléatoires, affichés une seule fois. Stockage : préfixe de recherche (12 caractères) + hachage SHA-256 ; comparaison en temps constant.
**Pourquoi SHA-256 et non Argon2 :** un jeton de 256 bits n'est pas devinable ; une dérivation lente protège des mots de passe faibles, pas de cela. Elle ajouterait de la latence à chaque appel CI.
**Non fait :** révocation, rotation, expiration, portées (lecture/écriture).

### 5. Empreinte des constats et diff
`fingerprint = sha256(type | règle | emplacement | message)`, **sans numéro de ligne** (qui bouge à chaque modification) et avec chemin normalisé. Le diff classe chaque constat en `new / fixed / persisting`. Le **premier scan d'un projet est une base de référence** : rien n'est « nouveau », pour éviter une avalanche d'alertes à l'onboarding.
**Limite connue :** les chemins absolus diffèrent entre un poste et un runner CI ; les clients doivent lancer le scan depuis la racine du dépôt.

### 6. Plans
`free` 1 projet, `team` 10, `business` 100 — **limites proposées**, appliquées côté serveur (le client n'est jamais cru). Les prix du cadrage (29 à 99 USD/mois) restent à valider par entretiens avant d'être gravés.

## Modèle de menaces (résumé)

| Menace | Mesure | État |
|---|---|---|
| Lecture inter-tenant | `org_id` du jeton, 404 uniforme, RLS | Applicatif testé ; RLS à faire |
| Rapport piégé (taille, schéma) | Schéma strict, plafond de 5 000 constats, longueurs bornées | Fait ; limite de corps à imposer au proxy |
| Vol de jeton | Hachage, affichage unique | Révocation/rotation à faire |
| Secrets dans un rapport | Suppression des champs libres + masquage serveur | Fait |
| Énumération de jetons | Pas de distinction entre jeton inconnu et invalide | Fait ; limitation de débit à faire |

## Ce qui n'est PAS fait

- Couche HTTP FastAPI et ses tests (dépendances à installer dans le venv).
- Persistance PostgreSQL, migrations, RLS.
- Limitation de débit, révocation et rotation de jetons, rétention des historiques.
- Connexion des utilisateurs (OAuth/e-mail), équipes, alertes et intégrations (M8).
- Commande `canlix push` (envoi depuis le CLI, avec suppression des extraits par défaut).
- Plafond de taille du corps au niveau du reverse proxy.

## Décisions qui appartiennent au propriétaire `[PORTE]`

1. **Hébergement et région** (Canada pour les clients canadiens/québécois ?).
2. **Authentification des utilisateurs** : GitHub OAuth seul, ou aussi e-mail.
3. **Tarification** : à fixer après entretiens, pas avant.
4. **Nom et marque** : « Canlix » est phonétiquement proche de CanLII et de CANIX (logiciel) ; recherche de marque officielle (CIPO, USPTO, EUIPO) à faire avant tout lancement public.
5. **Licence du SaaS** : le CLI est MIT ; open-core ou code fermé pour la partie cloud.

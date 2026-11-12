# CLAUDE.md — Canlix

Scanner de sécurité open source pour serveurs MCP et agents IA. Analyse statique (CFG/SRC), tests actifs (XSV), runtime (RUN), avec une couche SaaS multi-tenant optionnelle.

Langue de travail : français. Code, identifiants, commits, commentaires : anglais.

## 0. Protocole de session

1. Lire ce fichier, identifier la première tâche non cochée dans la section 7.
2. Annoncer en trois lignes : tâche, plan, sous-agents utilisés. Exécuter sans redemander.
3. Fin de tâche : tests passants, `py_compile` OK, `ruff check/format` propre, cocher `[x]` avec date et note.
4. Commit systématique après chaque tâche complète.
5. Fin de session : résumé six points (✅ Fait, ⏭ Suivant, 🔴 Bloqué, ❓ Décisions, 📝 À retenir, 📋 Proposals).

## 1. Commandes

Répertoire : `/home/kali/mcpprobe/`

| Commande | Description |
|---|---|
| `python -m pytest tests/ --ignore=tests/integration -q` | Tests unitaires (sans DB) |
| `CANLIX_DATABASE_URL=... pytest tests/integration/ -v` | Tests d'intégration PgStore |
| `.venv/bin/ruff check . && .venv/bin/ruff format --check .` | Lint |
| `python -m saas.migrate` | Appliquer les migrations PostgreSQL |
| `uvicorn saas.app:app --reload` | Démarrer le SaaS (port 8000) |
| `docker compose up -d db` | PostgreSQL local (port 5435) |
| `canlix scan <path>` | Scan statique CLI |
| `canlix watch --http 7700` | Runtime proxy + SSE |

## 2. Architecture

Monolithe modulaire. Pas de microservices.

```
canlix/          CLI et règles (CFG, SRC, XSV, RUN)
saas/            Couche SaaS FastAPI
  app.py         Routes HTTP (20+ endpoints)
  store.py       Store in-memory (tests unitaires)
  pg_store.py    Store PostgreSQL (production)
  migrate.py     Migrations idempotentes (0001-0004)
  integrations.py  Slack / PagerDuty / Jira dispatch
  report.py      Rapport HTML auto-suffisant
  portal.html    Dashboard web (login, projets, scans, intégrations)
  auth.py        scrypt email/password
  security.py    Tokens SHA-256 cnx_*
tests/
  test_saas_http.py     Tests HTTP (client FastAPI)
  test_saas_core.py     Tests Store in-memory
  test_integrations.py  Tests dispatch + Store CRUD
  test_report.py        Tests rendu HTML
  integration/
    test_pg_store.py    Tests PgStore PostgreSQL (skip sans DB)
docs/adr/
  0001-saas-architecture.md
```

## 3. Stack

- **CLI** : Python pur, zéro dépendance externe obligatoire
- **SaaS** : FastAPI + psycopg[binary,pool] + pydantic v2
- **DB** : PostgreSQL 16 + RLS (org_id sur projects/scans/findings/integrations)
- **Auth** : scrypt stdlib (email/password) + tokens SHA-256 256 bits
- **Dispatch** : urllib.request stdlib, threads daemon, timeout 8s — aucune dépendance réseau externe

## 4. Sécurité — règles non négociables

- `org_id` dérivé du jeton, jamais lu dans le corps ou l'URL
- Ressource d'un autre tenant → 404, pas 403
- `Integration.config` (webhook URLs, routing keys, tokens) : jamais loggué, jamais retourné dans les réponses API (`IntegrationOut` omet `config`)
- Clés et secrets : variables d'environnement, jamais commités
- Tout code d'authentification ou de crypto : relu par `security-reviewer` avant fusion

## 5. Variables d'environnement

| Variable | Description |
|---|---|
| `CANLIX_DATABASE_URL` | URL PostgreSQL (optionnel — in-memory sans ça) |
| `CANLIX_SAAS_TOKEN_TTL_DAYS` | TTL des jetons (optionnel) |

## 6. État au 2026-11-12

- **1237 tests unitaires** passants · **24 tests PgStore** (skip sans `CANLIX_DATABASE_URL`)
- Ruff propre · HEAD `aa4d73c` sur `github.com/robkira01-max/canlix`
- Migration en prod : `python -m saas.migrate` à relancer après chaque déploiement

Livrables présents :
- Règles : CFG/SRC (config + source), XSV-001..004 (inter-serveurs), RUN-001..007 (runtime)
- Runtime Analyzer : proxy stdio, `canlix watch` / `canlix replay` / `canlix watch --http PORT`
- Action GitHub composite `action.yml` (SARIF) + workflow d'auto-scan
- SaaS HTTP : `/orgs`, `/auth/register`, `/auth/login`, `/portal`, `/orgs/me/integrations` (CRUD), `/projects/{id}/scans/{id}/report`
- Portal web : dashboard complet (token, projets, scans, intégrations Slack/PD/Jira, liens rapports)
- Migration 0004 : table `integrations` (config JSONB, isolation org)
- PgStore : parité complète avec Store in-memory + dispatch alertes sur `add_scan`

## 7. Tâches

### Backlog technique
- [ ] **T-TM** — Vérification marque CIPO/USPTO/EUIPO classe 42 pour « Canlix » avant publication PyPI (5 min — à faire par le propriétaire : ised-isde.canada.ca/cipo/trademark-search/srch, tmsearch.uspto.gov, euipo.europa.eu/eSearch)

### Backlog business
- [ ] **M9** — Pilotes commerciaux : contacter 2-3 équipes sécurité, valider tarifs 29-99 USD/mois (hors code)

### Proposals (hors plan actuel)
- Portal : onglet « Membres » pour inviter des collègues (multi-utilisateur par org)
- CLI : `canlix ci` pour détecter automatiquement le runner CI et générer la config
- SaaS : endpoints d'administration (stats globales, désactivation d'org)
- Webhooks entrants : recevoir les résultats de scan depuis GitHub Actions directement

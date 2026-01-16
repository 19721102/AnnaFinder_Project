# Backend Health Report v3

## Status
- **Status:** 🟢 Green — all automated gates (`compileall`, `pytest`, `ruff`, `pip check`, `pip-audit`, `bandit`) pass and no new manual findings remain after the hardening sweep.
- **Scope:** Backend code under `backend/` plus helper scripts in `backend/tools/`; the health report documents inventory, security fixes, evidence, and next steps.

## Inventário & Higiene
- `git status -sb` (root `C:\AnnaFinder_Project`):
  ```
  ## main...origin/main
   M backend/main.py
   M backend/state.json
   M backend/tools/db_restore.py
  ?? backend/BACKEND_HEALTH_REPORT_v2.md
  ?? backend/BACKEND_HEALTH_REPORT_v3.md
  ?? backend/tests/test_events_query.py
  ```
- `git ls-files | findstr /R "\.db$ \.log$ __pycache__ \.pytest_cache \.ruff_cache \.env"` → *no output*, confirming caches/logs/DB artifacts remain ignored.

## Achados por Severidade
### High
- **Wildcard host default** (pre-scan finding): `DEFAULT_ALLOWED_HOSTS` included `0.0.0.0`, which technically bypasses TrustedHost protection. That entry is now removed so the middleware only accepts explicit localhost-like hosts and any hostname derived from `BASE_URL`.

### Medium
- **Dynamic event SQL (previous):** The `/events` and `/events/export` handlers concatenated the `WHERE` clause via f-strings, triggering Bandit B608. Now both handlers build the base query with fixed strings and append the pre-validated clause only when filters are in play.
- **Dynamic SQL in restore helper** (tools/db_restore.py): The script executed `SELECT COUNT(*) FROM {table}` and was flagged; the new version runs a fixed query per table.

### Low
- **Sensitive sample state:** `backend/state.json` contained a full name; it now carries “Example Patient” to keep the checked-in fixture harmless.

## Correções Aplicadas
- `backend/main.py:113` removed `0.0.0.0` from `DEFAULT_ALLOWED_HOSTS` so TrustedHostMiddleware never sees a wildcard entry (secure defaults in both dev/test).
- `backend/main.py:3120‑3206` rewrote `/events` and `/events/export` to build `count_sql` and `query_sql` incrementally instead of interpolating `where_sql`, eliminating Bandit B608 warnings and paving the way for future filters.
- `backend/tools/db_restore.py:4‑53` introduced `TABLE_CHECK_QUERIES` and executes known-safe statements, so restore validation no longer interpolates identifiers.
- `backend/tests/test_events_query.py` adds CSRF/login helpers plus regression tests for `/events?kinds=seed` filtering and a guard asserting the wildcard host was removed.
- `backend/state.json:3` now uses “Example Patient” instead of a real-ish name to avoid tracking secrets in repo data.

## Evidência (comandos + saída relevante)
- `python -m compileall .` → listing multiple directories and success of compiling backend modules (see compileall log lines).
- `pytest -q` → `38 passed in 17.06s`.
- `ruff check .` → `All checks passed!`
- `python -m pip check` → `No broken requirements found.`
- `pip-audit -r requirements.txt` → `No known vulnerabilities found`
- `bandit -r . -ll` → `No issues identified.`

## Próximos Passos Recomendados
1. Document allowed-host/CORS requirements so deployers know which env vars (`ALLOWED_HOSTS`, `ALLOWED_ORIGINS`, `FRONTEND_PORT`) to tune before prod.
2. Monitor `CSRF_FAIL`/`AUTHZ_DENY` events via the security logger to catch suspicious origin mismatches or brute-force attempts.
3. Scan other helper scripts in `tools/` for dynamic SQL patterns and expand the `TABLE_CHECK_QUERIES` strategy where needed.

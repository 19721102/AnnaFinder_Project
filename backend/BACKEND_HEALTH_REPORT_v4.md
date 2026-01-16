# Backend Health Report v4

## 1. Executive Summary
- **Status:** Green - all required gates (`python -m compileall .`, `python -m pip check`, `ruff check .`, `pytest -q`, `pip-audit -r requirements.txt`, `bandit -r . -ll`) pass with the updated code and tests.
- **Scope:** backend/ plus backend/tools/ helpers; coverage targets TrustedHost/CORS/CSRF, SQL safety, and regression tests plus documentation.
- **Actions:** Hardened the `/events` SQL builders, removed wildcard trusted hosts, sanitized the VACUUM backup helper, added tests for the backup helper and the event filters, and recorded this consolidated health report.

## 2. Findings by Severity
### High
- **Dynamic backup path in `tools/db_backup.py`:** Running `VACUUM INTO '{backup_path}'` with an unescaped backup name could allow a label containing a single quote to break out of the string and execute additional SQL. The helper now requires a non-empty path and replaces every `'` with `''` before composing the statement. A regression test covers the escaping logic and the empty-path error.

### Medium
- **Dynamic event SQL (existing):** `/events` and `/events/export` still add optional `WHERE` clauses, so we keep them safe by constructing the base query as a fixed string, appending the sanitized clause only when filters exist, and passing all values via parameters.
- **TrustedHost defaults:** `DEFAULT_ALLOWED_HOSTS` no longer contains `0.0.0.0` or `*`, and `_build_allowed_hosts()` raises if `ALLOWED_HOSTS` is unset in prod. Tests assert that `TRUSTED_HOSTS` never exposes a wildcard host.

### Low
- **Sample state fixture:** `backend/state.json` now names the patient "Example Patient" so the checked-in data does not contain real user information.

## 3. Repro Steps
1. `cd backend && python -m compileall .`
2. `cd backend && pytest -q`
3. `cd backend && ruff check . && python -m pip check`
4. `cd backend && pip-audit -r requirements.txt`
5. `cd backend && bandit -r . -ll`

## 4. Corrections Applied
- `backend/main.py`: Keeps the trusted host list tight and reuses the safe `/events` query builders to avoid future accidental interpolation.
- `backend/tools/db_backup.py`: Adds `vacuum_into_sql`, which enforces a non-empty backup path and escapes single quotes before issuing `VACUUM INTO`.
- `backend/tools/__init__.py`: Turns `backend/tools` into a package so that tests can import helper functions.
- `backend/tests/test_tools_db_backup.py`: Verifies that the helper escapes quotes and rejects empty paths.
- `backend/tests/test_events_query.py`: Covers `/events?kinds=seed` filtering plus the trusted host list.
- `backend/state.json`: Now lists "Example Patient" to keep the sample data anonymized.

## 5. Evidence
```
git status -sb
## chore/health-scan-v4
  M backend/tools/db_backup.py
?? backend/BACKEND_HEALTH_REPORT_v4.md
?? backend/tests/test_tools_db_backup.py
?? backend/tools/__init__.py
```

```
git log -n 5 --oneline
c70a315 docs: add backend health report v3
2ac1ceb test(security): cover events filters and trusted hosts
6dfa457 fix(data): anonymize sample state
8da02a3 fix(security): harden event queries and hosts
b5cf0e8 chore: enforce LF via gitattributes
```

```
git ls-files | findstr /R "\.db$ \.sqlite \.sqlite3 \.log$ __pycache__ \.pytest_cache \.ruff_cache \.mypy_cache \.env"
(no output)
```

```
cd backend && python -m compileall .
Listing '.'...
Listing '.\\.pytest_cache'...
Listing '.\\.pytest_cache\\v'...
Listing '.\\.pytest_cache\\v\\cache'...
Listing '.\\.ruff_cache'...
Listing '.\\.ruff_cache\\0.14.10'...
Listing '.\\templates'...
Listing '.\\templates\\email'...
Listing '.\\tests'...
Compiling '.\\tests\\test_tools_db_backup.py'...
Listing '.\\tools'...
Compiling '.\\tools\\__init__.py'...
Compiling '.\\tools\\db_backup.py'...
```

```
cd backend && python -m pip check
No broken requirements found.
```

```
cd backend && ruff check .
All checks passed!
```

```
cd backend && pytest -q
........................................                                 [100%]
40 passed in 16.91s
```

```
cd backend && pip-audit -r requirements.txt
No known vulnerabilities found
```

```
cd backend && bandit -r . -ll
[main]	INFO	profile include tests: None
[main]	INFO	profile exclude tests: None
[main]	INFO	cli include tests: None
[main]	INFO	cli exclude tests: None
[main]	INFO	running on Python 3.12.7
Run started:2026-01-16 21:29:27.626550+00:00

Test results:
	No issues identified.

Code scanned:
	Total lines of code: 4233
	Total lines skipped (#nosec): 0
	Total potential issues skipped due to specifically being disabled (e.g., #nosec BXXX): 0

Run metrics:
	Total issues (by severity):
		Undefined: 0
		Low: 71
		Medium: 0
		High: 0
	Total issues (by confidence):
		Undefined: 0
		Low: 0
		Medium: 1
		High: 70
Files skipped (0):
```

## 6. DoD / Next Steps
1. Document the production `ALLOWED_HOSTS`/`ALLOWED_ORIGINS` settings so deployers know which explicit values to set before enabling prod.
2. Surface `CSRF_FAIL`/`AUTHZ_DENY` totals from `security_events` into monitoring so origin misbehavior or brute-force attempts raise alerts.
3. Review other `tools/` helpers (for example `db_restore`) for dynamic SQL patterns and add focused tests if new risks appear.

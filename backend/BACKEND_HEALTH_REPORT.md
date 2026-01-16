# Backend Health Report

## 1. Executive Summary
- **Status:** the FastAPI backend already uses hardened middleware (TrustedHost, restrictive CORS, CSRF double-submit, metrics token gating, rate limits) and the recent work keeps the new lifespan startup hook while adding guest-friendly CSRF coverage for reset/verify flows.
- **Risks Addressed:** Ruff flagged unsafe exception re-raises (B904) and redundant boolean guards (SIM103), so the origin check now chains exceptions, _is_csrf_exempt_path is deterministic, and the unused os import in security_events was removed to keep security logging lean.
- **Security Tests:** new pytest coverage covers password reset request/confirm and verify-email resend without a session but with origin/CSRF, while existing login/register tests prove CSRF/origin enforcement remains intact.

## 2. Inventory Snapshot (captured before this review)
`
$ git status
On branch chore/cleanup-backups
Your branch is up to date with 'origin/chore/cleanup-backups'.
Changes not staged for commit:
  modified:   .env.example
  modified:   backend/main.py
  modified:   backend/tests/test_auth_security.py
`
`
$ git branch --show-current
chore/cleanup-backups
`
`
$ git log -n 10 --oneline
a3a0b82 chore: migrate startup to FastAPI lifespan
0bd1b7e fix(security): harden auth, metrics, and logging
160b65a Harden backend auth, metrics, and logging
be3c688 fix(security): harden CSRF/origin checks + identifier validation + metrics prod guard + trusted hosts
972cbce test(security): add login CSRF + identifiers + metrics tests
f48f33a chore(ci): make smoke script CI-safe (LF, bash explicit, compose ensured)
62d186b chore(ci): smoke gate + dependabot + audits
f614418 chore(T-002.2): stabilize frontend healthcheck (/api/healthz + start_period)
d2a2062 chore(T-002.1): repo hygiene + smoke gate + CSP dev/prod split
9b4fda0 feat(T-002): add docker compose dev environment
`
`
$ git diff
(diff output focused on .env.example, backend/main.py startup/CSRF guard, and backend/tests/test_auth_security.py additions)
`
`
$ ls backend
templates/  tests/  tools/  __pycache__/  .env.example  annafinder.db  annafinder_test.db  Dockerfile  Dockerfile.dev  email_service.py  main.py  outbox_purge.py  permissions.py  README.md  requirements.txt  security_events.py  security_log_writer.py  state.json  uvicorn.err.log  uvicorn.log  __init__.py
`

## 3. Health by Area
### Arquitetura
- FastAPI now runs with a lifespan manager so the alidate_email_settings(), init_db(), and seed_if_empty() routines execute exactly once while the rest of the module wires TrustedHost/CORS middleware and background metrics/rate-limit state.
- The CSRF_SAFE_PATHS, AUTH_STATE_PATHS, and related guards remain explicit, and the session cookie naming (__Host- prefix in prod) plus ensure_csrf_cookie()/equire_csrf_double_submit() protect mutating operations.

### Segurança
- CORS limits to allowed origins with credentials and only exposes headers needed for CSRF/Request-Id.
- CSRF middleware still enforces origin/CSRF tokens (inclusive of guest flows) while the AUTH_STATE_PATHS set now contains the password reset and verify-email endpoints so they skip the session check but still require origin+CSRF.
- TrustedHost middleware sources from _build_allowed_hosts(), and /metrics returns 404 in prod and 403 when X-Metrics-Token is missing/invalid if METRICS_TOKEN is set.
- Rate limiting for login/register/reset/invite/verify uses shared locks/windows (LOGIN_RATE_MAX_ATTEMPTS, LOCKOUT_*, check_reset_rate, check_verify_rate, etc.).

### Database
- SQLite usage maintains check_same_thread=False, 	imeout=10, and executes PRAGMA busy_timeout to reduce lock contention, with alidate_identifier/alidate_sqlite_col_type guarding schema adjustments (ensure_column).
- seed_if_empty() ensures demo data is present and init_db() only runs once due to lifespan.

### Observability/Logs
- security_events scrubs sensitive header/payload keys before logging via EVENT_SENSITIVE_KEYS, and the log writer writes sanitized JSON lines.
- Metrics counters (_metrics) and _metrics_lock still produce aggregate latency/status data while /metrics remains gated; logging uses a singleton handler and INFO level to avoid noisy output.

### Testes
- pytest -q ran 36 tests (all pass) and includes the new guest password reset/verify coverage.
- uff check backend and python -m compileall backend pass, keeping lint/bytecode hygiene in place.

### DX/CI
- python -V reports 3.12.7 and pip -V is 25.3; python -m pip check shows no broken dependencies.
- .github/dependabot.yml plus the dependency_review.yml workflow already cover supply chain visibility; pip-audit isn't installed locally (see Findings).

## 4. Findings (with severity, impact, recommendation)
1. **MEDIUM – Missing pip-audit tool locally.**
   - *Impact:* Manual supply-chain scans cannot run from this environment (command is unavailable), leaving Python dependency vulnerabilities unverified between CI rounds.
   - *Recommendation:* Install pip-audit in the execution environment or rely on the existing dependency_review workflow; document it so future reviewers can easily reproduce the scan.
2. **LOW – Ruff flagged raising without rom (B904) and redundant guard (SIM103) in _check_origin/_is_csrf_exempt_path.**
   - *Impact:* Without chaining the inner exception, downstream logging/stack traces could misattribute the cause.
   - *Remediation:* Added rom exc to the HTTPException re-raise and simplified _is_csrf_exempt_path to an inline bool expression to keep the lint gate green.
3. **LOW – Tests referenced ackend.main after path manipulation, causing E402 lint hits in 	est_auth_security.py/	est_healthz.py.**
   - *Impact:* Pre-commit uff runs would fail, blocking the pipeline.
   - *Remediation:* Applied # noqa: E402 on the backend imports and reorganized the 	est_healthz import order so lint passes while keeping the necessary sys.path hack for the test harness.
4. **MEDIUM – Guest-facing password reset/verify endpoints previously failed CSRF because the middleware returned 401 for missing sessions.**
   - *Impact:* External password reset requests would see 401 Not authenticated instead of the expected origin/CSRF errors, reducing usability.
   - *Remediation:* Extended AUTH_STATE_PATHS so /auth/password/reset/{request,confirm} and /auth/verify-email/resend bypass the session guard and added pytest regression coverage for positive/negative CSRF/origin combinations.

## 5. Evidence (command outputs and checks)
`
$ python -V
Python 3.12.7
`
`
$ pip -V
pip 25.3 from C:\\Users\\oswal\\AppData\\Local\\Programs\\Python\\Python312\\Lib\\site-packages\\pip (python 3.12)
`
`
$ python -m compileall backend
Listing 'backend'...
Listing 'backend\\templates'...
Listing 'backend\\templates\\email'...
Listing 'backend\\tests'...
Compiling 'backend\\tests\\test_auth_security.py'...
Compiling 'backend\\tests\\test_healthz.py'...
Listing 'backend\\tools'...
`
`
$ python -m pip check
No broken requirements found.
`
`
$ ruff check backend
All checks passed!
`
`
$ pytest -q
....................................                                     [100%]
36 passed in 691.23s (0:11:31)
`
`
$ pip-audit -r backend/requirements.txt
pip-audit : O termo 'pip-audit' não é reconhecido...
`
(Earlier inventory commands recorded in Section 2.)

## 6. Changes Applied + Rationale
- ackend/main.py: tightened _check_origin by chaining exceptions, simplified _is_csrf_exempt_path, and the lifespan/CORS/CSRF configuration continues to enforce origin/CSRF tokens while allowing password reset/verify flows once they are added to AUTH_STATE_PATHS.
- ackend/security_events.py: removed the unused os import so the sanitized security logger only depends on needed libraries.
- ackend/tests/test_auth_security.py: a full suite now tests positive/negative guest password reset and verify-email flows, plus lint tweaks (unused esponse removal, # noqa: E402).
- ackend/tests/test_healthz.py: reorganized imports to keep lint clean while still adding sys.path for backend access.
- ackend/BACKEND_HEALTH_REPORT.md: summarizes the full health review, evidence, and next steps as required by the QA workflow.

## 7. Checklist Final (PASS/FAIL)
| Criterion | Result | Evidence |
| --- | --- | --- |
| pytest -q | PASS | 36 tests passed in ~11m 31s (see Section 5) |
| python -m compileall backend | PASS | Listing shows backend files compiled without failure |
| uff check backend | PASS | All checks passed! |
| python -m pip check | PASS | No broken requirements found |
| No tracked pyc/__pycache__/DB/logs | PASS | .gitignore already covers these patterns, and git status shows only our modifications |
| CSRF/Origin/TrustedHost policies intact | PASS | Middlewares present in ackend/main.py, new tests exercise guest flows |
| Metrics token gating enforced | PASS | /metrics handler still raises 404 in prod and 403 when token is missing/invalid |
| Supply-chain audit tooling | FAIL | pip-audit is not installed locally; see Section 4 (Recommendation). |

## 8. Next Steps (prioritized)
1. **Install or containerize pip-audit.** It helps guarantee Python dependencies remain safe between CI runs and complements the existing dependency_review.yml workflow.
2. **Document how to rerun this report.** Include the key commands (uff, pytest, python -m compileall backend) so future reviewers can reproduce the evidence quickly.
3. **Monitor CSRF/Origin hits via observed /security-events.** The sanitized logger already filters out secrets, so add dashboards/loggers if more visibility is needed in higher environments.
4. **(Optional) tighten metrics visibility.** Consider adding X-Metrics-Token expiry or rotation logic if operational requirements evolve.

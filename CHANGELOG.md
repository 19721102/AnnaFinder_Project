# Changelog

## [0.1.0] - Release readiness
- API v1 foundation with FastAPI routers, error modeling, and Pydantic schemas plus JWT auth and multi-tenant gates.
- Frontend English-first shell with i18n toggle and a /status page powered by the typed API client.
- CI workflow covering backend pytest/ruff/pip-audit/bandit, frontend lint/build, and the planner gate.
- Minimal Playwright E2E smoke tests that confirm the stack health and status page.

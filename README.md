# AnnaFinder Dev Stack

## Overview
AnnaFinder stitches together a FastAPI backend, Next.js frontend, and PostgreSQL database in a single compose stack so the entire dev experience can be reproduced locally. The backend exposes `/healthz` plus `/api/v1`, while the frontend is a Next.js shell wired to the same API.

## Quick start
1. `docker compose up --build`
   * Compose file: `compose.yaml` in the repo root — no `-f` flag required.
   * Backend health: `http://localhost:8000/healthz`
   * Frontend dev UI: `http://localhost:3000/` (Next.js hot reload enabled via `npm run dev`)
   * Frontend volume strategy: `./frontend` is bind-mounted to `/app` and a named volume keeps `/app/node_modules` inside the container so native modules (LightningCSS, etc.) do not conflict with Windows host builds.
2. Stop the stack with `docker compose down` when you are done.

## Backend commands
Perform work inside `backend/` for API, auth, multi-tenant, and audit stories. Gates:
* `python -m pytest -q`
* `ruff check .`
* `pip-audit -r requirements.txt`
* `bandit -r . -ll`

## Frontend commands
Inside `frontend/`, keep the Next.js shell running via:
* `npm install` (first time or after dependency changes)
* `npm run dev`

Front-end quality gates:
* `npm run lint`
* `npm run build`
* `npm run test`

Each of the above commands may be invoked with `npm --prefix frontend <script>` when running from the repo root.

## Testing, CI, and release
The GitHub Actions workflow (`.github/workflows/ci.yml`) runs all backend and frontend gates plus the planner gate that validates `docs/PLANO_PLANEJADOR.json`. Keep this README, `CHANGELOG.md`, `RELEASE_CHECKLIST.md`, and `SECURITY.md` in sync with release-ready documentation.

## Environment variables (no secrets)
* `DATABASE_URL` — PostgreSQL connection string used by FastAPI/Alembic.
* `JWT_SECRET` — JWT signing secret (store securely outside git).
* `NEXT_PUBLIC_API_BASE_URL` — Base URL the frontend calls (e.g., `http://localhost:8000`).

When adding new environment variables, document them here or in `.env.example` without committing real secrets.

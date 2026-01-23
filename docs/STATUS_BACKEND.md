# Backend Status Report

## Summary
- **Status:** OK — `docker compose up --build` boots Postgres, the backend, and the Next.js dev server with hot reload, and `/healthz` returns 200 even with the full stack live.
- **Compose file:** `compose.yaml` is the only manifest so Docker Compose chooses it by default and the CLI no longer warns about duplicate config files.
- **Context:** Frontend runs `npm run dev` inside `node:22-slim` and keeps native deps inside a named `/app/node_modules` volume, while backend logs show fresh health-check traffic via `GET /healthz`.

## Compose stack & services
- `docker compose up --build -d` (reads `compose.yaml` in the repo root; no `-f` required).
- `docker compose ps`:
  ```
  NAME                            IMAGE                         SERVICE    STATUS                        PORTS
  annafinder_project-backend-1    annafinder_project-backend    backend    Up 55 seconds (healthy)       0.0.0.0:8000->8000/tcp
  annafinder_project-frontend-1   annafinder_project-frontend   frontend   Up 44 seconds (healthy)       0.0.0.0:3000->3000/tcp
  annafinder_project-postgres-1   postgres:16-alpine            postgres   Up About a minute (healthy)   5432/tcp
  ```

### Logs (últimos 120 linhas)
- backend:
  ```
  backend-1  | INFO:     Started server process [1]
  backend-1  | INFO:     Waiting for application startup.
  backend-1  | INFO:     Application startup complete.
  backend-1  | INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
  backend-1  | {"timestamp": "2026-01-20T21:36:51.841121Z", "request_id": "bb9a62ea-0307-40cb-a2cc-04b23b47b301", "method": "GET", "path": "/healthz", "status_code": 200, "duration_ms": 5.72, "client_ip": "127.0.0.1", "env": "dev"}
  backend-1  | {"timestamp": "2026-01-20T21:37:01.961455Z", "request_id": "1ffe7c31-e47f-4886-a121-abec8e6e95dc", "method": "GET", "path": "/healthz", "status_code": 200, "duration_ms": 1.33, "client_ip": "127.0.0.1", "env": "dev"}
  ```
- frontend:
  ```
  frontend-1  | > annafinder-frontend@0.1.0 dev
  frontend-1  | > next dev -H 0.0.0.0 -p 3000
  frontend-1  |   ▲ Next.js 14.2.5
  frontend-1  |  ✓ Starting...
  frontend-1  | Attention: Next.js now collects completely anonymous telemetry regarding usage.
  frontend-1  |  ✓ Ready in 2.3s
  frontend-1  |  ○ Compiling / ...
  frontend-1  |  ✓ Compiled / in 3.3s (256 modules)
  frontend-1  |  GET / 200 in 3683ms
  ```

## Endpoints verificados
- `GET http://localhost:8000/healthz` → `200 OK` com `{ "status": "ok", … }`.
- `HEAD http://localhost:3000/` → `200 OK`, Next.js responde (cabeçalho `X-Powered-By: Next.js` e `Cache-Control: no-store, must-revalidate`).

## Comandos executados
- `cd backend && pytest -q` → `38 passed in 23.64s`.
- `cd backend && ruff check .` → `All checks passed!`.
- `cd backend && pip-audit -r requirements.txt` → `No known vulnerabilities found`.
- `cd backend && bandit -r . -ll` → `No issues identified.` (low/medium/high counts: 0).
- `docker compose up --build -d`.
- `docker compose ps`.
- `docker compose logs backend --tail 120`.
- `docker compose logs frontend --tail 120`.
- `curl.exe -i http://localhost:8000/healthz` → `HTTP/1.1 200 OK`.
- `curl.exe -I http://localhost:3000` → `HTTP/1.1 200 OK`.

## Próximo risco / Bloqueio
- **Config warning removed:** `next.config.js` no longer overrides `experimental.serverActions`, so Next.js no longer warns about invalid config.
- **Nota de segurança:** o volume `frontend_node_modules` mantém os binários nativos dentro do container e previne erros do LightningCSS; não monte `frontend/node_modules` diretamente do host.

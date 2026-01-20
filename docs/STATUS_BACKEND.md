# Backend Status Report

## Summary
- **Status:** OK — a stack de desenvolvimento sobe via `compose.yaml` e expõe backend em `8000` e frontend em `3000` com healthchecks válidos.
- **Compose file:** `compose.yaml` (duplicado em `docker-compose.yaml` para compatibilidade) foi efetivamente utilizado; o CLI sinalizou `Found multiple config files with supported names: compose.yaml, docker-compose.yaml` mas optou por `compose.yaml`.
- **Contexto:** Além do backend localmente saudável (pytest, ruff, pip-audit, bandit), este relatório valida o stack Dev completo: Postgres + backend + frontend placeholder.

## Compose stack & services
- `docker compose up --build -d` → stack criada a partir de `compose.yaml`. O warning sobre múltiplos arquivos persiste enquanto o duplicado existir.
- `docker compose ps`:
  ```
  NAME                            SERVICE    STATUS
  annafinder_project-backend-1    backend    Up (health: healthy)
  annafinder_project-frontend-1   frontend   Up (health: healthy)
  annafinder_project-postgres-1   postgres   Up (healthy)
  ```

### Logs (últimos 200 linhas)
- backend:
  ```
  backend-1  | INFO:     Started server process [1]
  backend-1  | INFO:     Waiting for application startup.
  backend-1  | INFO:     Application startup complete.
  backend-1  | INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
  ```
- frontend:
  ```
  frontend-1  | /docker-entrypoint.sh: ... ready for start up
  frontend-1  | 2026/01/20 03:05:13 [notice] 1#1: nginx/1.29.4
  frontend-1  | ::1 - - [20/Jan/2026:03:05:23 +0000] "GET / HTTP/1.1" 200 ...
  ```

## Endpoints verificados
- `GET http://localhost:8000/healthz` → 200 OK, JSON `{"status":"ok",...}`.
- `GET http://localhost:8000/openapi.json` → 200 OK (content-length ~21974).
- `HEAD http://localhost:3000/` → 200 OK via nginx.

## Comandos executados
- `cd backend && python -m pytest` → `38 passed in 16.52s`
- `cd backend && python -m pip check` → `No broken requirements found.`
- `cd backend && ruff check .` → `All checks passed!`
- `cd backend && pip-audit -r requirements.txt` → `No known vulnerabilities found`
- `cd backend && bandit -r . -ll` → `No issues identified.`
- `cd backend && python -m pip show httpx`
- `docker compose up --build -d`
- `docker compose ps`
- `docker compose logs backend --tail 200`
- `docker compose logs frontend --tail 200`
- `curl.exe -i http://localhost:8000/healthz`
- `curl.exe -I http://localhost:3000`
- `curl.exe -I http://localhost:8000/openapi.json`
- `docker compose down`

## Próximo risco / Bloqueio e correção sugerida
- **Risco:** o warning “Found multiple config files…” continua enquanto o clone (`docker-compose.yaml`) coexistir com `compose.yaml`.
- **Correção sugerida:** remova o duplicado ou documente a duplicidade no README para evitar warnings no CI, mantendo sempre o `compose.yaml` como fonte primária.

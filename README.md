# AnnaFinder Dev Stack

## Quick start
- `docker compose up --build`  (uses `compose.yaml` in the repo root; no `-f` required).
- Backend: `http://localhost:8000/healthz`.
- Frontend dev server: `http://localhost:3000/` (Next.js, hot reload enabled via `npm run dev`).

## Notes
- The frontend service mounts `./frontend:/app` plus a named `frontend_node_modules` volume so native dependencies (LightningCSS, etc.) are built inside the Linux container rather than using the host `node_modules`.
- Stop the stack with `docker compose down`.

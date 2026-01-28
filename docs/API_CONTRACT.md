# API contract polish

## Tags and grouping
- `meta`: service metadata and discovery endpoints like `/api/v1/meta`.
- `auth`: authentication and session management (`/api/v1/auth/*`).
- `families`: family operations that include creation and listing.
- `items`: CRUD for items and their tag relationships (includes `items` and `item-tags` routers).
- `locations`: location planning routes.
- `events`: timeline and auditing flows.
- `audit`: audit logs and related observability helpers.
- `observability`: logging and the `/api/v1/error-report` stub.

Keep the tags consistent by either providing `tags=[...]` on each route decorator or via `APIRouter(..., tags=[...])`. When adding new routers, reflect the tag in both `backend/api/v1/router.py` and `docs/API_CONTRACT.md`.

## Inspecting the OpenAPI contract
- Browse `http://localhost:8000/docs` (Swagger UI) or `http://localhost:8000/openapi.json` while the backend is running.
- Use `curl http://localhost:8000/openapi.json | jq '.paths | keys'` to see available paths grouped by tags.
- Confirm `/healthz` uses the `HealthzResponse` schema (status & version fields) in the generated JSON.

## Regenerating `docs/openapi.json`
Run the helper script (from the repo root):

```bash
python backend/scripts/export_openapi.py --out docs/openapi.json
```

By default the script writes to `docs/openapi.json` and will error out if the FastAPI app cannot import or build the schema.

## Notes
- This contract describes only metadata and documentation; no authentication logic is modified, and the stub `/api/v1/error-report` just logs sanitized payloads.

# Environment variables

This reference describes the typical Dev vs Prod values and marks each variable as required or optional.

| Name | Scope | Required? | Dev (example) | Prod (example) | Notes |
|------|--------|-----------|---------------|----------------|-------|
| POSTGRES_USER | Postgres | Yes | annafinder | annafinder | Used in the backend connection string.
| POSTGRES_PASSWORD | Postgres | Yes | changeme | <vault_secret> | Never store real passwords; use a vault.
| POSTGRES_DB | Postgres | Yes | annafinder | annafinder | May be created during provisioning.
| DATABASE_URL | Backend | Yes | postgresql://annafinder:changeme@localhost:5432/annafinder | postgresql://annafinder:<vault_secret>@db:5432/annafinder | Point SQLAlchemy to the right host.
| JWT_SECRET | Backend | Yes | jwt-secret-placeholder | <vault_secret> | Rotate periodically.
| APP_ENV | Backend | Yes | dev | prod | Controls migrations and logging behavior.
| CORS_ALLOWED_ORIGINS | Backend | Optional | http://localhost:3000 | https://app.example.com | Comma-separated list of allowed origins.
| TRUSTED_HOSTS | Backend | Optional | localhost | app.example.com | Hosts allowed in the Host header.
| NEXT_PUBLIC_API_BASE_URL | Frontend | Yes | http://localhost:8000 | https://api.example.com | Browser-visible URL to reach the backend.
| BACKEND_BASE_URL | Backend/Frontend | Optional | http://localhost:8000 | https://api.example.com | Internal backend URL references.
| FRONTEND_BASE_URL | Frontend | Optional | http://localhost:3000 | https://app.example.com | Public frontend URL when proxied.
| HEALTHZ_URL | Backend | Optional | http://localhost:8000/healthz | http://backend:8000/healthz | Validates the internal health endpoint.

> **Security**: keep secrets (JWT_SECRET, DATABASE_URL, POSTGRES_PASSWORD) in a secret manager or Docker secret. Never commit real values.

> **Customization**: optional values may change by environment. Use `.env` for Dev and pass secure variables through the host or `.env.prod` in Prod.

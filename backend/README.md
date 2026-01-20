# AnnaFinder Backend

## Installation
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Execution
```powershell
copy .env.example .env
uvicorn main:app --reload --port 8000
```

## Tests
```powershell
pytest
```

## Environment
- `DATABASE_URL` (ex: `postgresql://localhost/annafinder`)
- `SECRET_KEY` used for session and token signing
- `SMTP_*` (optional) for sending emails
- `ALLOWED_ORIGINS` (comma-separated) controls which origins can use CORS and CSRF
- `ANNAFINDER_ENV` should be `test` locally and `prod` when deploying so the secure cookie flag is enforced
- `ALLOWED_HOSTS` whitelists the Host/Host header that the backend will accept (comma-separated, defaults to `localhost,127.0.0.1,testserver`)

## Security
- Session cookies (`anna_session`) are emitted with `HttpOnly`, `Secure` (in production), `SameSite=Lax`, and `Path=/`; clients must use `credentials: "include"` when talking to the API.
- CSRF tokens are issued via `anna_csrf` (accessible to script) and must be echoed back via an `X-CSRF-Token` header for `POST`, `PUT`, `PATCH`, and `DELETE` calls; also send a matching `Origin` header listed in `ALLOWED_ORIGINS`.
- CORS is strict: only the explicit origins declared in `ALLOWED_ORIGINS` (plus localhost ports via `FRONTEND_PORT`) are accepted, and `allow_credentials=True` is always set.
- Login attempts are throttled to 5 tries per 5-minute window per IP+email pair; excess attempts receive HTTP 429.
- Mutating endpoints (`/auth/login`, `/auth/register`, `/household/*`, etc.) now reject requests without an allowed Origin/Referer to block login CSRF even from unauthenticated callers.
- Production disables `/metrics` (`404`), and Trusted Host middleware enforces `ALLOWED_HOSTS` so the app only responds when the Host header matches an approved value.
- **Docker Compose (dev stack):**
  ```powershell
  docker compose up --build
  ```
  Isso sobe Postgres, o backend (porta 8000) e o Next.js dev server (porta 3000) com hot reload.

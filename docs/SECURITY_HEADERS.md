# Baseline security headers

This baseline covers the headers applied at the app edge (backend + frontend) for T-021. The values are intentionally permissive for a dev-first stack while still providing anti-clickjacking, sniffing, and policy guidance.

| Header | Value | Applied by |
|--------|-------|------------|
| `X-Content-Type-Options` | `nosniff` | backend middleware + Next.js headers |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | backend middleware + Next.js headers |
| `X-Frame-Options` | `SAMEORIGIN` | backend middleware + Next.js headers |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` | backend middleware + Next.js headers |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | backend middleware (prod+HTTPS only) and Next.js headers (production only) |

## Backend implementation
- A single middleware (`SecurityHeadersMiddleware`) injects the header map for every response, including `/healthz`.
- HSTS is only added when `APP_ENV=prod` **and** the incoming request is HTTPS (`request.url.scheme === "https"` or `X-Forwarded-Proto: https`).
- The middleware runs before any route logic so the header set is uniform for `/api/v1` and `/healthz`. Tests live in `backend/tests/test_t021_security_headers.py`.

## Frontend implementation
- `frontend/next.config.js` exposes the same header map via `async headers()` for all routes.
- `Strict-Transport-Security` is still limited to production builds (`NODE_ENV=production`), without trying to enforce HTTPS in dev.
- The e2e smoke test (`frontend/e2e/smoke.spec.ts`) now also validates the header set is present on `/en/`.

## Testing notes
- Backend runs `pytest` to ensure `/healthz` keeps the header set and HSTS behaves correctly.
- Frontend Playwright smoke (`npm run test:e2e`, via CI) already hits `/en/` and now asserts these headers exist.

## Why HSTS is limited
- In local dev, browsers reach the site over HTTP and there is no guarantee HTTPS is available; sending HSTS there would break refreshes.
- In production, the header is conditional on HTTPS detection. If your deployment proxies TLS (e.g., a load balancer), ensure it forwards `X-Forwarded-Proto`.

# CSP report-only

We emit `Content-Security-Policy-Report-Only` headers on every page so browsers can report potential violations without breaking the app. The policy is intentionally permissive in dev (allows `unsafe-inline`/`unsafe-eval`) while still scoping `default-src`, `base-uri`, `form-action`, `img-src`, `font-src`, `style-src`, `script-src`, and `connect-src`.

## The reporting endpoint
- Browsers POST payloads to `/api/v1/csp-report` with one of: `application/json`, `application/csp-report`, or `text/plain` (charset is ignored).
- Payloads are capped at 65536 bytes; oversized requests return `413 Payload Too Large`.
- Unsupported or missing content types return `415 Unsupported Media Type`.
- Accepted requests always return `204 No Content` (including invalid JSON) so reporting is fire-and-forget.
- Logged data is sanitized (allowlist of keys such as `document-uri`, `blocked-uri`, `violated-directive`, etc.) and truncated previews are used for text payloads; raw payloads are never logged.
- Recommendation: rate limit this endpoint at the reverse proxy or WAF.

## Testing
- Visit any page and inspect the response headers — look for `content-security-policy-report-only`.
- The Playwright smoke test checks the header presence and that it contains `report-uri /api/v1/csp-report`.
- You can also simulate a report via `curl -X POST http://localhost:8000/api/v1/csp-report -H "Content-Type: application/json" -d '{}'`.

## Logs
- Search backend logs for `event="csp_report"` plus the `request_id` in the structured entry to trace the report back to the originating request.
- The Logs gate is not enforced; this is purely informational, and future tasks will evolve toward `report-to`.

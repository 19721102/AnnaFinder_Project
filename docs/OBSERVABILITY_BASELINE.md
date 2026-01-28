# Observability baseline

## Request tracing
- Every HTTP request accepts the `X-Request-Id` header. If you supply one, the backend echoes it back in the response headers; otherwise, a new UUID4 value is generated.
- Logs for each request are emitted as structured JSON with `event="request"`, `request_id`, `method`, `path`, `status_code`, `duration_ms`, `client_ip`, and `env`.
- Use the request ID to filter logs: e.g. `rg '"request_id":"<id>" backend.log` or `jq -c 'select(.request_id=="<id>")' backend.log`.

## Health checks and error reporting
- The baseline includes the `/api/v1/error-report` stub. Send sanitized payloads (avoid tokens/passwords) with `curl -H "Content-Type: application/json" -H "X-Request-Id:<id>" -d '{"message":"oops"}' http://localhost:8000/api/v1/error-report`.
- Each error-report entry logs `event="error_report"` at `error` level, including the provided payload after removing or masking the `password`/`token` fields; the response returns `{"status":"accepted","request_id":"..."}`.
- Use the log’s JSON structure to correlate the request ID with downstream logging (e.g. `jq 'select(.event=="error_report")' backend.log`).

## Security guidance
- Treat `/api/v1/error-report` as a mailbox for operational signals only; never forward secrets in the JSON body.
- Sanitize logs or pass them through your observability tooling by searching for `request_id` to trace the surface area of an incident.

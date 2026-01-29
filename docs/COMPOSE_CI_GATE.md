# Compose CI gate

Run the compose gate locally:
```bash
pwsh -NoProfile -File infra/ci/t026_compose_gate.ps1 -WaitTimeout 180
```

Notes:
- The gate uses `docker compose up -d --build --wait --wait-timeout` to wait for healthchecks.
- It validates HTTP 200 on:
  - `http://127.0.0.1:8000/healthz`
  - `http://127.0.0.1:3000/en/`
- On failure, it prints `docker compose ps` and `docker compose logs --no-color --tail 200`.

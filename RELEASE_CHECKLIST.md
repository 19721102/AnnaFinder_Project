# Release Checklist

1. Confirm `docs/PLANO_PLANEJADOR.json` includes T-016 and accurately describes the release readiness task.
2. Run backend gates:
   - `cd backend && python -m pytest -q`
   - `cd backend && ruff check .`
   - `cd backend && pip-audit -r requirements.txt`
   - `cd backend && bandit -r . -ll`
3. Run frontend gates from the repo root:
   - `npm --prefix frontend run lint`
   - `npm --prefix frontend run build`
   - `npm --prefix frontend run test`
4. Verify README, CHANGELOG, and SECURITY docs describe the required commands and safeguards.
5. Create Git tag `v0.1.0` once all gates pass.
6. Push `main` and the new tag, then verify GitHub Actions completes without failures.

# Security Guidelines

- Never commit secrets such as passwords, API keys, or private certificates. Keep them in environment variables or a secure vault, and document their names in README/`.env.example`.
- Use the existing gate commands (`pip-audit`, `bandit`, `npm run lint`) to catch known vulnerabilities and lint issues before merging.
- Report any suspected vulnerabilities or incidents to the project maintainers via email or the issue tracker; include reproduction steps and the affected component (backend/frontend).
- Rotate secrets immediately if a leak is suspected and update consumers via secure channels (don’t re-commit secrets to git).
- Lock dependency versions in `requirements.txt` and `frontend/package.json` where practical to make audits deterministic.

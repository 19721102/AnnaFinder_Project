# Branch Protection Guidance

CODEOWNERS works per branch: GitHub matches `.github/CODEOWNERS` entries against the branch being merged into, so the settings below should be applied to `main`. Branch protection rules can be managed via the GitHub UI (Settings → Branches → Add rule or ruleset). Key steps:

1. **Require a pull request before merging.**
2. **Require approvals** — at least one reviewer must approve every PR.
3. **Require review from Code Owners** so `.github/CODEOWNERS` entries trigger required reviews automatically.
4. **Require status checks to pass** (mark the following workflows):
   * `plan_validate`
   * `backend_gates`
   * `frontend_gates`
   * `e2e_playwright`
5. **Require branches to be up to date before merging** (optional but keeps `main` current).
6. **Restrict pushes to `main`** so only the GitHub UI can merge (optional, use with care).
7. **Optional protections** you can enable as needs evolve:
   * Require linear history.
   * Require signed commits.

Document each setting in the repository so maintainers know which UI toggles to enable. These rules enforce that every change is reviewed by the right owners and that the gate workflows finish green before merging.

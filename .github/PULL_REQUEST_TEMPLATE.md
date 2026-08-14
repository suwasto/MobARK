## Summary

<!-- One or two sentences: what this PR changes and why. -->

## Related issues

<!-- Closes #... -->

## Changes

<!-- Bullet list of the concrete changes. -->

## Verification

- [ ] Backend: `cd backend && .venv/bin/python -m pytest` (unit tests pass)
- [ ] Backend: `cd backend && .venv/bin/ruff check .`
- [ ] Frontend: `cd frontend && npm run build` (tsc -b && vite build)
- [ ] Docs site (if `site/` touched): `mkdocs build`
- [ ] Manual verification steps (describe what you ran/clicked)

## Checklist

- [ ] Local-first constraint respected (no default outbound calls / data exfiltration)
- [ ] No new non-permissive dependencies (MIT/Apache-2.0/BSD only); license audit noted if deps changed
- [ ] Tests added/updated for the change
- [ ] `CHANGELOG.md` updated under `[Unreleased]`

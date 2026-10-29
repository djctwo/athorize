# Athorize

Guidance for contributors and AI coding assistants working in this repository.

Athorize is a self-hosted, multi-framework compliance platform: FastAPI + SQLAlchemy + SQLite backend
(`backend/`), React 18 + TypeScript + Vite frontend (`frontend/`), framework catalogs and crosswalk mappings
as JSON (`frameworks/`). AGPL-3.0, © 2026 Douglas Cleary.

## Status
- Version 1.0. Install paths: Docker (`docker-compose.yml`, `docker-compose.demo.yml`, `docs/INSTALL.md` §14)
  and Linux bare metal (`docs/INSTALL.md`) are primary; the Windows `.exe` (`desktop/`) is a beta.
- CI (`.github/workflows/`):
  - `tests.yml`: backend pytest on the floor versions of `backend/requirements.txt` (Python 3.11) and the
    newest versions (Python 3.13); `tsc`; vitest; Playwright demo + blank suites.
  - `docker.yml`: image build + smoke test; a `v*` tag publishes `ghcr.io/djctwo/athorize` (amd64 + arm64).
  - `integration.yml`: live OIDC SSO + email digests against Keycloak and MailHog.
  - `release-tooling.yml`: release archive + update round trip on Linux.
  - `build-windows-desktop.yml`: builds both `.exe` files, smoke-tests them, then runs the Playwright demo +
    blank suites with each built `.exe` as the server.
  - `watch.yml`: weekly integration watch (`scripts/integration_watch.py`, no keys) of the outside feeds
    (CISA KEV, AA RSS, CSAF, NVD); a change opens or updates one `integration-watch` issue per feed.
    Last-seen state: `.github/integration-watch/state.json`. Details: `docs/INTEGRATION_WATCH.md`.

## Regression suites
- `backend/tests/hunts/` and `frontend/e2e/` hold end-to-end and adversarial regression tests from the
  pre-release review (security, tenancy, permissions, imports, data integrity, install). A strict `xfail`
  (backend) or `test.fail()` (Playwright) marks a known defect awaiting a fix; when the fix lands, the marker
  must be removed.
- `backend/tests/test_permission_parity.py` keeps the backend permission map and the UI-side mirror in sync.
- Playwright: `cd frontend && npm run test:e2e`.

## Release checklist
1. All suites green in CI, including the Windows build + e2e job and the Docker smoke test.
2. Re-run a private-content and secrets sweep (paths, names, keys) on the exact tree being released.
3. Tag `vX.Y.Z`: the Docker workflow publishes the image to GHCR. Attach `Athorize.exe` and
   `Athorize-Demo.exe` from the tag's `build-windows-desktop` run to the GitHub release, labelled **beta**.

## Hard rules (this file is public — keep it free of private notes)
- **No publishers' text** for ISO/IEC 27001, PCI DSS, IEC 62443 or NERC CIP. Only IDs, short
  titles and our own summaries (`docs/FRAMEWORK_SOURCES.md`). Never re-add CIS, HITRUST or SOC 2.
- **No licensing, trial or vendor-key code.** Every bundled framework activates freely; only
  `restriction: licensed` metadata (none ship) requires a user-attested publisher key.
- **No real data**: demo/seed data is fictional (Acme). No names of real customers or evaluators.
- **No code merged from outside contributors** (keeps a single copyright holder; see CONTRIBUTING.md).
- Copyright line is **Douglas Cleary** (personal), not a company.
- **No code or logic ported in from the maintainer's other projects** unless the maintainer explicitly approves
  that specific port.
- The Windows .exe ships labelled **beta**. It is verified by the automated Windows e2e job
  (`.github/workflows/build-windows-desktop.yml` runs the Playwright demo + blank suites against the built .exe
  files). Docker + Linux are the primary install paths.

## Run / test
- Backend: `cd backend && python -m venv .venv && .venv/bin/pip install -r requirements.txt`, then
  `.venv/bin/python -m pytest -q`
- Frontend: `cd frontend && npm ci && npx tsc --noEmit && npx vitest run && npm run build`
- One-command local run: `ATHORIZE_DEMO_SEED=1 ./scripts/run-eval.sh` (admin/admin)
- Ports in dev: backend 8001, frontend 3001.
- README media (screenshots + demo video): build the UI (`npm run build`), then
  `PY=<python with backend deps> frontend/e2e/media/capture.sh <scratch-dir> [port]`. It starts a BLANK
  throwaway instance (data in `<scratch-dir>/instance`), records Setup → "Explore with demo data" → dashboard →
  controls/crosswalk → findings → reports, screenshots the demo pages (running one Red Team analysis for the
  `08`/`09` shots), stops the server, and writes
  `docs/screenshots/*.png` (1440×900 @2x) + `docs/media/athorize-demo.mp4` and `athorize-demo-preview.gif`
  (ffmpeg needed for those two; raw .webm stays in `<scratch-dir>/work`). Fails on page errors, failed API calls,
  error alerts or the word "Universal" on screen. Script: `frontend/e2e/media/capture_media.mjs`.
  The UI is dark-only, so every shot is dark.

## Website
- https://djctwo.github.io/athorize/ is served by GitHub Pages from the `gh-pages` branch (static HTML, separate history; not in `main`).
  To change it: `git worktree add ../athorize-site gh-pages`, edit, commit, push `gh-pages`. Keep `googlefef3924f77af7b34.html`
  (Google Search Console verification) and `.nojekyll`. Copy claims only from this README.

# Athorize Desktop — native double-clickable build

Freezes the single-process serve (`ATHORIZE_SERVE_FRONTEND=1`) into one
executable so a user runs **one file** — no WSL, no Python, no pip, no nginx.
Their browser opens to the app. Data lives in `~/.athorize-universal`
(`C:\Users\<you>\.athorize-universal` on Windows) for the blank build and
survives restarts and updates; the demo build uses `~/.athorize-universal-demo`,
and a newer demo build starts a fresh demo after renaming the previous demo
folder to `.athorize-universal-demo.old-<date-time>` (nothing is deleted).
Keys live in `<data dir>/secrets.env`, as for every other way of running
Athorize. `DATA_DIR` (or `ATHORIZE_DATA_DIR`) overrides the folder.

> **Beta.** The Windows `.exe` ships labelled beta. The desktop build is a
> convenience for trying Athorize on one machine; Docker and Linux are the
> primary install paths. For a shared team server, see `docs/INSTALL.md`
> (Docker §14, or nginx + systemd).
>
> Every CI build is checked on GitHub's Windows runner: each `.exe` is
> smoke-tested, then started as the server for the full Playwright suites
> (`frontend/e2e`: the `demo` project against `Athorize-Demo.exe`, the `blank`
> project against `Athorize.exe`) — see `windows/run-e2e.ps1`.

## Pieces

| File | Role |
|------|------|
| `launcher.py` | PyInstaller entry point: persists secrets, picks a free port, serves UI+API single-process, opens the browser. |
| `windows/smoke-test.ps1`, `windows/run-e2e.ps1` | CI checks on the built `.exe`: smoke test, then the Playwright e2e suites with the exe as the server. |
| `athorize.spec` | Recreates the repo layout inside the bundle so `backend/_appbase.bundle_root()` resolves `frontend/dist`, `frameworks/`, `backend/data/`, and the `DEMO_BUILD` / `DEMO_SEED_FINGERPRINT` markers under `sys._MEIPASS`. |
| `../.github/workflows/build-windows-desktop.yml` | Builds the **Windows** `.exe` in CI (no Windows machine needed). |

## Variants (`ATHORIZE_BUILD`)

- **`demo`** — auto-seeds demo data; log in `admin / admin`. Best for a first look.
- **`blank`** — blank instance (Setup screen on first run: set up a company, or
  **Explore with demo data**; Settings → Start fresh deletes the demo again).
  The demo seed (`backend/services/demo_seed.py`) is frozen into both variants.

## Download

Each release attaches `Athorize.exe` (blank) and `Athorize-Demo.exe` to the
[Releases page](https://github.com/djctwo/athorize/releases).

## Build the Windows .exe (via CI)

GitHub → **Actions** → **build-windows-desktop** → **Run workflow** → pick a
variant (default `demo`). Download the `.exe` from the run's **Artifacts**. It is
unsigned, so Windows SmartScreen shows "unknown publisher" → **More info → Run
anyway**.

## Build locally (macOS/Linux for testing the recipe)

Run from the repo root in a venv that has the backend deps + `pyinstaller`, with
`frontend/dist` already built (`cd frontend && npm run build`):

```bash
ATHORIZE_BUILD=demo pyinstaller desktop/athorize.spec \
  --distpath desktop/dist --workpath desktop/build --noconfirm
# smoke test (isolated data dir, fixed port, no browser window):
DATA_DIR=/tmp/athz ./desktop/dist/Athorize-Demo --port 8013 --no-browser
```

Launcher options (a plain double-click needs none): `--port N` (or env `PORT`)
serves on a fixed port instead of 8001-or-any-free-port; `--no-browser` (or env
`ATHORIZE_NO_BROWSER=1`) does not open a browser window.

`desktop/dist/`, `desktop/build/`, and `desktop/_staging/` are gitignored build
output.

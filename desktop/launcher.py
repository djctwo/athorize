"""Athorize desktop launcher — the PyInstaller entry point.

Freezes the existing single-process serve (ATHORIZE_SERVE_FRONTEND=1) into a
double-clickable app. No Python, no pip, no WSL, no nginx: the recipient runs
one executable and their browser opens to the app. This is an EVAL/DEMO
convenience — production still ships as self-hosted server software (nginx +
systemd, docs/INSTALL.md).

What it does, in order:
  1. Resolve the data dir (DATA_DIR / ATHORIZE_DATA_DIR, else
     Path.home()/.athorize-universal, or .athorize-universal-demo for the demo
     build). All user state (DB, evidence, backups, keys) lives here, private
     to the user (umask 077 / mode 700).
  2. Keys: nothing to do here. The app itself generates SECRET_KEY +
     ATHORIZE_AUDIT_HMAC_KEY on first start and keeps them in
     <data dir>/secrets.env — the same file every other way of starting
     Athorize uses (R2SEC-5). desktop-secrets.env from older builds is still read.
  3. Turn on single-process UI serving and pick a free port (8001, else any).
  4. Import the FastAPI app (after env is set — config reads it at import)
     and run uvicorn, opening the browser once the port is accepting.

Options (defaults unchanged for people who double-click it; used by the
Windows CI job that runs the end-to-end suite against the built .exe):
  --port N      / env PORT=N                serve on N instead of picking one
  --no-browser  / env ATHORIZE_NO_BROWSER=1  do not open a browser window

Bundled-asset paths (frontend/dist, frameworks/, backend/data, 
DEMO_BUILD markers) resolve through backend/_appbase.bundle_root(), which returns
sys._MEIPASS when frozen — so the frozen app finds everything PyInstaller packed.
"""
from __future__ import annotations

import argparse
import os
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path

PREFERRED_PORT = 8001


def _is_demo_build() -> bool:
    """The demo build carries a bundled DEMO_BUILD marker; the blank build does not."""
    try:
        from _appbase import bundle_root
        return (bundle_root() / "DEMO_BUILD").exists()
    except Exception:
        return False


def _data_dir() -> Path:
    # Demo and blank builds MUST NOT share a data dir — otherwise running the
    # demo (which seeds data) then the blank build shows the demo's data instead
    # of the setup wizard. Give the demo build its own dir so both can coexist.
    explicit = os.environ.get("DATA_DIR") or os.environ.get("ATHORIZE_DATA_DIR")
    if explicit:
        d = Path(os.path.expanduser(explicit))
    else:
        name = ".athorize-universal-demo" if _is_demo_build() else ".athorize-universal"
        d = Path.home() / name
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    return d


def _seed_fingerprint() -> str | None:
    """sha256 of the demo seed (backend/services/demo_seed.py) this build ships,
    stamped into DEMO_SEED_FINGERPRINT by athorize.spec (demo build only); None
    when absent. The seed itself is frozen into the exe, so there is no file to
    hash at run time — and importing it here would load the app's config
    before DATA_DIR is set."""
    try:
        from _appbase import bundle_root
        marker = bundle_root() / "DEMO_SEED_FINGERPRINT"
        if not marker.exists():
            return None
        return marker.read_text().strip() or None
    except Exception:
        return None


def _refresh_stale_demo_data(data_dir: Path) -> Path | None:
    """Demo builds only: if the bundled seed script changed since this demo dir
    was populated, set the dir aside so first boot reseeds with current example
    data. Returns where the old data went (None when nothing was moved).

    Why: the demo only seeds an EMPTY database, so a recipient who ran an older
    demo build keeps the old example data — and new features ship invisible.
    Evaluators do upload files, though, so nothing is deleted (R2INSTALL-9):
    the old folder is renamed to .athorize-universal-demo.old-<date-time> next
    to it, and the console and the Read Me say so.

    Safety rails: runs only on demo builds, never on an env-overridden data dir,
    and only touches a directory literally named .athorize-universal-demo.
    """
    if not _is_demo_build() or os.environ.get("DATA_DIR") or os.environ.get("ATHORIZE_DATA_DIR"):
        return None
    if data_dir.name != ".athorize-universal-demo":
        return None
    current = _seed_fingerprint()
    if current is None:
        return None
    marker = data_dir / "demo-seed-fingerprint"
    recorded = marker.read_text().strip() if marker.exists() else ""
    db_exists = (data_dir / "data.db").exists()
    moved = None
    if db_exists and recorded != current:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        moved = data_dir.with_name(f"{data_dir.name}.old-{stamp}")
        n = 1
        while moved.exists():
            n += 1
            moved = data_dir.with_name(f"{data_dir.name}.old-{stamp}-{n}")
        data_dir.rename(moved)
        data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        print("  This demo build has new example data, so it starts with a fresh demo.")
        print(f"  Your previous demo data (including uploaded files and backups) was kept in:\n    {moved}")
    marker.write_text(current + "\n")
    return moved


def _free_port(preferred: int = PREFERRED_PORT) -> int:
    """Return the preferred port if bindable, else any free port."""
    for candidate in (preferred, 0):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", candidate))
            return s.getsockname()[1]
        except OSError:
            continue
        finally:
            s.close()
    return preferred


def _options(argv: list[str] | None = None) -> argparse.Namespace:
    """Command-line options. Unknown arguments are ignored (Windows can pass
    extras when the exe is started from a shortcut), and a bare double-click
    gives the historical behaviour: free port, browser opens."""
    ap = argparse.ArgumentParser(prog="Athorize", add_help=True)
    ap.add_argument("--port", type=int, default=None,
                    help="port to serve on (default: env PORT, else 8001, else any free port)")
    ap.add_argument("--no-browser", action="store_true",
                    help="do not open a browser window (also: env ATHORIZE_NO_BROWSER=1)")
    opts, _unknown = ap.parse_known_args(argv)
    if opts.port is None and os.environ.get("PORT"):
        opts.port = int(os.environ["PORT"])
    if os.environ.get("ATHORIZE_NO_BROWSER", "").strip().lower() in ("1", "true", "yes", "on"):
        opts.no_browser = True
    return opts


def _open_when_ready(port: int) -> None:
    url = f"http://127.0.0.1:{port}"
    for _ in range(120):  # up to ~60s for first-boot DB create + seed
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.5)
    webbrowser.open(url)


# Keep idle connections open well past any short pause in a client: with
# uvicorn's 5 s default, a client reusing a pooled connection right as the
# server closed it got ECONNRESET (seen on Windows in CI). Local, single-user
# app, so the extra idle sockets cost nothing.
KEEP_ALIVE_SECONDS = 75


def _uvicorn_options(port: int) -> dict:
    # No proxy in front of the desktop app: never take the client address from
    # X-Forwarded-For (login throttling keys on it).
    return {
        "host": "127.0.0.1",
        "port": port,
        "log_level": "info",
        "proxy_headers": False,
        "timeout_keep_alive": KEEP_ALIVE_SECONDS,
    }


def main(argv: list[str] | None = None) -> None:
    opts = _options(argv)
    # The database, evidence and keys are private to this user (no effect on Windows,
    # where the profile folder is already per-user).
    os.umask(0o077)
    data_dir = _data_dir()
    _refresh_stale_demo_data(data_dir)  # before DATA_DIR export + app import
    os.environ["DATA_DIR"] = str(data_dir)
    # Keep evidence + backups under the same (variant-specific) data dir so the
    # demo and blank builds are fully isolated, not just their databases.
    os.environ.setdefault("EVIDENCE_DIR", str(data_dir / "evidence"))
    os.environ.setdefault("BACKUP_DIR", str(data_dir / "backups"))
    os.environ["ATHORIZE_SERVE_FRONTEND"] = "1"

    port = opts.port or _free_port()
    url = f"http://127.0.0.1:{port}"

    # Import the app only after env + paths are set: config and the demo seed
    # read env/bundle_root at import time.
    import uvicorn
    from main import app  # noqa: E402  (deferred on purpose)

    print("=" * 56)
    print(f"  Athorize is starting on {url}")
    print(f"  Data: {data_dir}")
    if _is_demo_build():
        print("  Demo build -> log in with  admin / admin")
        print("  A newer demo build starts a fresh demo; the old demo folder is kept beside it.")
    else:
        print("  Blank build -> first run opens the setup wizard")
    print("  Close this window to stop.")
    print("=" * 56)

    if not opts.no_browser:
        threading.Thread(target=_open_when_ready, args=(port,), daemon=True).start()
    uvicorn.run(app, **_uvicorn_options(port))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)

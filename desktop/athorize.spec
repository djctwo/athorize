# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec — freeze Athorize into a single double-clickable executable.

Recreates the repo's runtime layout INSIDE the bundle (under sys._MEIPASS) so the
app's bundle_root()-relative paths resolve unchanged:

    <bundle>/frontend/dist/      built web UI (served single-process)
    <bundle>/frameworks/         all framework plugin catalogs
    <bundle>/backend/data/       mock threat-feed data
    <bundle>/DEMO_BUILD          (demo only) auto-seed marker
    <bundle>/DEMO_SEED_FINGERPRINT (demo only) sha256 of backend/services/demo_seed.py

The demo seed itself is a backend module (services.demo_seed), frozen into BOTH
variants: the blank build offers it on the Setup screen ("Explore with demo data").

Build variants via env ATHORIZE_BUILD:
    blank  -> blank instance, Setup screen on first run (set up a company, or explore demo data)
    demo   -> auto-seeds demo data; log in admin / admin

Usage (run from repo root, in a venv that has the backend deps + pyinstaller):
    ATHORIZE_BUILD=blank pyinstaller desktop/athorize.spec --distpath desktop/dist --workpath desktop/build --noconfirm
    ATHORIZE_BUILD=demo  pyinstaller desktop/athorize.spec --distpath desktop/dist --workpath desktop/build --noconfirm
"""
import os
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).resolve().parent          # repo root (spec lives in desktop/)
BACKEND = ROOT / "backend"
VARIANT = os.environ.get("ATHORIZE_BUILD", "blank")
APP_NAME = "Athorize" if VARIANT == "blank" else "Athorize-Demo"


def tree(src, dest_prefix):
    """(source_file, dest_dir) pairs mirroring src/ under dest_prefix in the bundle."""
    items = []
    src = Path(src)
    for p in src.rglob("*"):
        if not p.is_file() or "__pycache__" in p.parts or p.suffix == ".pyc":
            continue
        rel = p.relative_to(src)
        items.append((str(p), str(Path(dest_prefix) / rel.parent)))
    return items


datas = []
datas += tree(ROOT / "frontend" / "dist", "frontend/dist")
datas += tree(ROOT / "frameworks", "frameworks")
datas += tree(BACKEND / "data", "backend/data")

# Build markers (must be real files on disk to bundle) — staged here.
STAGE = ROOT / "desktop" / "_staging"
STAGE.mkdir(parents=True, exist_ok=True)
if VARIANT == "demo":
    import hashlib
    (STAGE / "DEMO_BUILD").write_text("demo\n")
    datas.append((str(STAGE / "DEMO_BUILD"), "."))
    # A newer demo build with different example data starts a fresh demo
    # (launcher._refresh_stale_demo_data compares this fingerprint).
    seed_sha = hashlib.sha256((BACKEND / "services" / "demo_seed.py").read_bytes()).hexdigest()
    (STAGE / "DEMO_SEED_FINGERPRINT").write_text(seed_sha + "\n")
    datas.append((str(STAGE / "DEMO_SEED_FINGERPRINT"), "."))

# uvicorn loads its loop/protocol/lifespan impls dynamically — collect them all.
# The demo seed is imported lazily (first-run "Explore with demo data" and the
# demo build's auto-seed); name it so both variants always bundle it.
hiddenimports = collect_submodules("uvicorn") + ["services.demo_seed"]

a = Analysis(
    [str(ROOT / "desktop" / "launcher.py")],
    pathex=[str(BACKEND)],          # so `from main import app` + all backend modules resolve
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name=APP_NAME,
    debug=False,
    strip=False,
    upx=False,
    console=True,                   # show the "starting on…" window + any errors
)

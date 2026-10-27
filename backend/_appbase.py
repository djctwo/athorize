"""Bundle-root resolution that survives PyInstaller freezing.

Every bundled asset (frontend/dist, frameworks/, backend/data/, the DEMO_BUILD
marker) is located relative to the repo root. Running from source that root is
the directory above backend/. Inside a PyInstaller-frozen desktop app the source
tree doesn't exist on disk — the bundled data is unpacked under sys._MEIPASS —
so __file__-relative paths would point at nothing.

`bundle_root()` returns the correct root in both modes. It is INERT for normal
server runs: getattr(sys, "frozen", False) is False there, so it returns exactly
what the old `Path(__file__).resolve().parent.parent` expressions returned. Only
the frozen desktop build (desktop/launcher.py) takes the _MEIPASS branch.
"""
from __future__ import annotations

import sys
from pathlib import Path


def bundle_root() -> Path:
    """Root containing backend/, frontend/dist/, frameworks/, DEMO_BUILD."""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    return Path(__file__).resolve().parent.parent

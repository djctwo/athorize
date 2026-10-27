"""Where uploaded evidence files live on disk.

`EvidenceArtifact.file_path` is stored RELATIVE to EVIDENCE_DIR by the upload
endpoint, always with forward slashes (e.g. ``"2/690a….pdf"``) so data moves
between Windows and Linux by backup/restore. Every reader — download, delete, the audit
binder — must resolve it the same way, with a containment check so a crafted
or legacy row can never point outside the evidence tree.
"""
from __future__ import annotations

from pathlib import Path

from config import settings


def resolve_evidence_path(file_path: str | None) -> Path | None:
    """Absolute path of a stored evidence file, or None when the row has no
    file or its path escapes EVIDENCE_DIR. Absolute values are accepted only
    when they already sit inside EVIDENCE_DIR (rows written by older builds)."""
    if not file_path:
        return None
    root = settings.evidence_dir.resolve()
    # Rows written by the Windows build use "\\" (R2INSTALL-12); archives always
    # extract with "/", so read both the same way on every OS.
    candidate = Path(file_path.replace("\\", "/"))
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve()
    except (OSError, RuntimeError):
        return None
    if not resolved.is_relative_to(root):
        return None
    return resolved

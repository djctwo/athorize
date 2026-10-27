"""Keep the data private to the account the server runs as (R2SEC-8).

data.db holds every company's records plus password and token hashes, and
the evidence tree holds uploaded files — they get the same protection as
secrets.env, setup-token and backups (0600 files / 0700 folders) on every
start path, not only in Docker (whose entrypoint already sets umask 077)."""
from __future__ import annotations

import logging
import os
import stat
from pathlib import Path

_logger = logging.getLogger(__name__)

# POSIX mode bits mean nothing on Windows: every folder reports 777 and chmod
# cannot change that (privacy there comes from the per-user profile's ACL).
# Without this the .exe logged "restricted ... (was 777)" on every start.
_POSIX_MODES = os.name != "nt"


def secure_data_dirs(*dirs: Path) -> None:
    os.umask(0o077)  # every file the process creates from here on: owner-only
    for d in dict.fromkeys(dirs):  # dedupe, keep order
        try:
            d.mkdir(parents=True, exist_ok=True, mode=0o700)
            if not _POSIX_MODES:
                continue
            st = d.stat()
            mine = not hasattr(os, "getuid") or st.st_uid == os.getuid()
            if mine and stat.S_IMODE(st.st_mode) & 0o077:
                os.chmod(d, 0o700)
                _logger.warning("data: restricted %s to its owner (was %o)", d, stat.S_IMODE(st.st_mode))
        except OSError as exc:
            _logger.warning("data: could not restrict %s: %s", d, exc)

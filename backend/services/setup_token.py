"""First-run setup token.

`POST /api/auth/setup` is reachable by anyone who can hit the server until the
first admin exists. To close that window, a one-time token is generated at
startup (when no users exist) and written to <DATA_DIR>/setup-token (0600) and
the service log. The Setup screen must echo it back; it's deleted once setup
completes. If the file is absent (already set up, or an operator deleted it),
setup is closed.
"""
from __future__ import annotations

import logging
import os
import secrets
from pathlib import Path

from config import settings
from services import safe_compare

_logger = logging.getLogger(__name__)
_TOKEN_PATH = settings.data_dir / "setup-token"


def ensure_setup_token() -> None:
    """Generate the token if the DB has no users and no token exists yet.

    Called at startup. Safe to call when already set up (no-op)."""
    # Import here to avoid a circular import at module load.
    from database import SessionLocal
    from models import User

    db = SessionLocal()
    try:
        if db.query(User.id).first() is not None:
            # Already provisioned — make sure no stale token lingers.
            clear_setup_token()
            return
    finally:
        db.close()

    if _TOKEN_PATH.exists():
        return
    generate_setup_token()


def generate_setup_token() -> str:
    """Write a new token (0600) and log it. Returns it."""
    token = secrets.token_urlsafe(24)
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    fd = os.open(_TOKEN_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token)
    try:
        os.chmod(_TOKEN_PATH, 0o600)
    except OSError:
        pass
    _logger.warning(
        "FIRST-RUN SETUP TOKEN: %s  (also written to %s) — required to create "
        "the first admin account.", token, _TOKEN_PATH,
    )
    return token


def read_setup_token() -> str | None:
    try:
        return _TOKEN_PATH.read_text().strip() or None
    except OSError:
        return None


def verify_setup_token(provided: str | None) -> bool:
    expected = read_setup_token()
    if not expected:
        return False
    return safe_compare.equal(expected, (provided or "").strip())


def claim_setup_token() -> Path | None:
    """Atomically take the token for ONE setup request: rename the file to a
    unique claim name. Of concurrent submits with the valid token only the one
    whose rename succeeds proceeds (R2SEC-7) — across processes too, since
    rename is atomic on one filesystem. None = someone else holds it."""
    claim = _TOKEN_PATH.with_name(f"{_TOKEN_PATH.name}.claim-{secrets.token_hex(8)}")
    try:
        os.rename(_TOKEN_PATH, claim)
    except OSError:
        return None
    return claim


def setup_claimed() -> bool:
    """A setup request currently holds the token."""
    return any(_TOKEN_PATH.parent.glob(f"{_TOKEN_PATH.name}.claim-*"))


def release_setup_claim(claim: Path) -> None:
    """Setup failed after the claim: put the token back so it can be retried."""
    try:
        os.rename(claim, _TOKEN_PATH)
    except OSError:
        pass


def finish_setup_claim(claim: Path) -> None:
    try:
        claim.unlink()
    except OSError:
        pass


def clear_setup_token() -> None:
    try:
        _TOKEN_PATH.unlink()
    except OSError:
        pass

"""Browser session tokens.

The cookie carries a random 256-bit token; the database stores only its
SHA-256 (UserSession.id), like API tokens. A leaked DB or backup therefore
holds no usable session. Rows written before this change stored the raw
cookie value (a 36-char uuid) and are purged once at startup: existing users
sign in again after the upgrade.
"""
from __future__ import annotations

import hashlib
import secrets

from sqlalchemy import func
from sqlalchemy.orm import Session

from models.session import UserSession


def new_token() -> tuple[str, str]:
    """Return (raw cookie value, stored id)."""
    raw = secrets.token_urlsafe(32)
    return raw, hash_token(raw)


def hash_token(raw: str) -> str:
    return hashlib.sha256((raw or "").encode("utf-8")).hexdigest()


def lookup(db: Session, raw: str | None) -> UserSession | None:
    if not raw:
        return None
    return db.query(UserSession).filter(UserSession.id == hash_token(raw)).first()


def purge_unhashed_sessions(db: Session) -> int:
    return db.query(UserSession).filter(func.length(UserSession.id) != 64).delete(synchronize_session=False)

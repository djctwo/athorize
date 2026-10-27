"""API token generation and resolution.

Tokens are `athu_<43 url-safe chars>`. Only the SHA-256 hash is persisted; the
raw value is returned once at creation and never recoverable. Resolution is
constant-time on the hash lookup (the DB unique index) and updates last_used_at.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from models.api_token import ApiToken
from models.user import User

PREFIX = "athu_"


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def generate() -> tuple[str, str, str]:
    """Return (raw_token, display_prefix, token_hash)."""
    raw = PREFIX + secrets.token_urlsafe(32)
    return raw, raw[:13], hash_token(raw)


def resolve(db: Session, raw: str) -> User | None:
    """Return the active user a bearer token authenticates as, or None."""
    if not raw or not raw.startswith(PREFIX):
        return None
    tok = db.query(ApiToken).filter(ApiToken.token_hash == hash_token(raw)).first()
    if tok is None or tok.revoked_at is not None:
        return None
    now = datetime.now(timezone.utc)
    if tok.expires_at is not None:
        exp = tok.expires_at.replace(tzinfo=timezone.utc) if tok.expires_at.tzinfo is None else tok.expires_at
        if exp < now:
            return None
    user = db.query(User).filter(User.id == tok.user_id, User.is_active == True).first()  # noqa: E712
    if user is None:
        return None
    # Throttle the last_used_at write: this runs in get_current_user (a dependency,
    # before the endpoint body), so committing on EVERY request would add a write
    # to every read and reset the request's transaction boundary. Only persist
    # when the timestamp is stale (>60s), mirroring the session last_activity throttle.
    last = tok.last_used_at
    if last is not None and last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    if last is None or (now - last).total_seconds() > 60:
        tok.last_used_at = now
        db.commit()
    return user


def revoke_all_for_user(db: Session, user_id: int) -> int:
    """Revoke every active token of a user (password reset, role change,
    deactivation). Caller commits. Returns how many were revoked."""
    now = datetime.now(timezone.utc)
    return (db.query(ApiToken)
            .filter(ApiToken.user_id == user_id, ApiToken.revoked_at.is_(None))
            .update({ApiToken.revoked_at: now}, synchronize_session=False))

"""Manage API tokens for programmatic access.

Any authenticated user can mint and revoke their OWN tokens; an admin sees and
can revoke every token in the organization. The raw token is returned exactly
once, on creation. A token acts as its user (role + system scope), so minting
is open to every role — an auditor's token is read-only like the auditor.

Tokens expire after API_TOKEN_DEFAULT_EXPIRY_DAYS (90) unless the request sets
expires_in_days; a never-expiring token is an explicit admin-only choice
(never_expires=true), and only admins may pick a lifetime beyond
NON_ADMIN_MAX_DAYS. Password reset, role change and deactivation revoke all
of the user's tokens (routers/users.py).

Creating and revoking tokens needs an interactive session: a bearer token
cannot mint (or revoke) tokens, so revoking a leaked token — or letting it
expire — ends the exposure (R2SEC-1).
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from config import settings
from database import get_db
from dependencies import get_current_user, require_session_user
from models.api_token import ApiToken
from models.user import User
from services import api_token as api_token_svc
from services import audit as audit_svc

router = APIRouter()

NON_ADMIN_MAX_DAYS = 365


class TokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)
    never_expires: bool = False


def _serialize(t: ApiToken) -> dict:
    return {
        "id": t.id,
        "name": t.name,
        "token_prefix": t.token_prefix,
        "created_at": t.created_at,
        "last_used_at": t.last_used_at,
        "expires_at": t.expires_at,
        "revoked_at": t.revoked_at,
        "user_id": t.user_id,
    }


@router.get("")
def list_tokens(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    q = db.query(ApiToken).filter(ApiToken.organization_id == user.organization_id)
    if user.role != "admin":
        q = q.filter(ApiToken.user_id == user.id)
    return [_serialize(t) for t in q.order_by(ApiToken.created_at.desc()).all()]


@router.post("")
def create_token(req: TokenCreate, user: User = Depends(require_session_user), db: Session = Depends(get_db)):
    raw, prefix, token_hash = api_token_svc.generate()
    if req.never_expires and user.role != "admin":
        raise HTTPException(403, "Only admins can create a token that never expires.")
    if req.expires_in_days and req.expires_in_days > NON_ADMIN_MAX_DAYS and user.role != "admin":
        raise HTTPException(422, f"Tokens can last at most {NON_ADMIN_MAX_DAYS} days (longer is an admin-only choice).")
    days = req.expires_in_days or (None if req.never_expires else settings.api_token_default_expiry_days or None)
    expires_at = datetime.now(timezone.utc) + timedelta(days=days) if days else None
    tok = ApiToken(
        organization_id=user.organization_id, user_id=user.id, name=req.name.strip(),
        token_prefix=prefix, token_hash=token_hash, expires_at=expires_at,
    )
    db.add(tok)
    db.flush()
    audit_svc.record(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, action="CREATE", entity_type="api_token",
        entity_id=tok.id, summary=f"Created API token '{tok.name}' ({prefix}…)",
    )
    db.commit()
    # The raw token is returned ONCE and never stored.
    return {**_serialize(tok), "token": raw}


@router.delete("/{token_id}")
def revoke_token(token_id: int, user: User = Depends(require_session_user), db: Session = Depends(get_db)):
    tok = db.query(ApiToken).filter(
        ApiToken.id == token_id, ApiToken.organization_id == user.organization_id,
    ).first()
    if tok is None:
        raise HTTPException(404, "Token not found")
    if user.role != "admin" and tok.user_id != user.id:
        raise HTTPException(403, "Cannot revoke another user's token")
    if tok.revoked_at is None:
        tok.revoked_at = datetime.now(timezone.utc)
        audit_svc.record(
            db, organization_id=user.organization_id, actor_id=user.id,
            actor_username=user.username, action="REVOKE", entity_type="api_token",
            entity_id=tok.id, summary=f"Revoked API token '{tok.name}' ({tok.token_prefix}…)",
        )
        db.commit()
    return {"ok": True}

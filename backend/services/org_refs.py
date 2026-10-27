"""Validation for ids a client supplies in a request body.

Every row is org-scoped, but a body field such as `system_id`, `owner_id` or
`assessor_id` is just an integer the client chose. Create/update paths must
check it points into the caller's organization (and, for systems, the caller's
system scope) before storing it — otherwise a row in one company can reference
another company's system or user, and reports that follow the reference render
the other company's data.
"""
from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy.orm import Session

from models.system import System
from models.user import User
from services.system_scope import system_scope_filter


def require_org_system(db: Session, user: User, system_id: int | None) -> System | None:
    """404 unless system_id is a system in the caller's org and system scope.
    None (org-level rows) passes."""
    if system_id is None:
        return None
    system = db.query(System).filter(
        System.id == system_id,
        System.organization_id == user.organization_id,
        *system_scope_filter(System.id, db, user),
    ).first()
    if system is None:
        raise HTTPException(404, "System not found")
    return system


def require_org_user(db: Session, user: User, user_id: int | None, field: str = "owner_id") -> None:
    """422 unless user_id is an active user in the caller's org. None
    (unassigned) passes."""
    if user_id is None:
        return
    ok = db.query(User.id).filter(
        User.id == user_id,
        User.organization_id == user.organization_id,
        User.is_active == True,  # noqa: E712
    ).first()
    if not ok:
        raise HTTPException(422, f"{field} must be an active user in your organization")

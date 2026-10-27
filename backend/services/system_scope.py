"""Per-system access scoping (SystemAssignment enforcement).

Assign a user to specific systems and they see ONLY those systems' data —
the "give the plant contractor access to SCADA and nothing else" feature.

Rules (deliberately back-compat safe):
  - admin, compliance_manager, and operators are NEVER scoped (org-wide roles).
  - Any other role (assessor, system_owner, evidence_contributor, auditor) with
    one or more SystemAssignment rows is limited to those systems.
  - A user with NO assignments keeps org-wide visibility — existing installs
    change behavior only when someone actually assigns systems.

Scoped surfaces: systems, findings, evidence, control implementations, ConMon,
IT/OT assets, risks, assessments, calendar, dashboard aggregates, CSV/binder
exports, SIEM + asset imports, global search, crosswalk suggestions, red team
reports, the audit log (and every feed built from it: dashboard activity,
import history) and threat-advisory asset matches. A scoped user sees only
audit entries tied to their systems — org-level entries (user admin, framework
activation, settings) are hidden from them. Threat advisories themselves are
org-level threat intel and stay visible; only their per-system asset matches
are filtered.
"""
from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy.orm import Session

from models.system import System
from models.system_assignment import SystemAssignment
from models.user import User

UNSCOPED_ROLES = ("admin", "compliance_manager")


def allowed_system_ids(db: Session, user: User) -> set[int] | None:
    """The systems this user may see, or None meaning unrestricted."""
    if user.role in UNSCOPED_ROLES or getattr(user, "is_operator", False):
        return None
    rows = (
        db.query(SystemAssignment.system_id)
        .join(System, SystemAssignment.system_id == System.id)
        .filter(
            SystemAssignment.user_id == user.id,
            # An assignment left over from another company (operator context or
            # stale data) must never widen visibility in this org.
            System.organization_id == user.organization_id,
        )
        .all()
    )
    ids = {sid for (sid,) in rows}
    return ids if ids else None


def scope_query(query, system_id_col, db: Session, user: User):
    """Apply the user's system restriction to a query (no-op if unrestricted)."""
    ids = allowed_system_ids(db, user)
    if ids is None:
        return query
    return query.filter(system_id_col.in_(ids))


def system_scope_filter(system_id_col, db: Session, user: User) -> tuple:
    """Splat-style variant for inline use in existing .filter(...) calls:
        .filter(Model.organization_id == ..., *system_scope_filter(Model.system_id, db, user))
    Returns no clauses when the user is unrestricted."""
    ids = allowed_system_ids(db, user)
    return () if ids is None else (system_id_col.in_(ids),)


def system_scope_filter_nullable(system_id_col, db: Session, user: User) -> tuple:
    """Like system_scope_filter, but rows with NULL system_id (org-level rows,
    e.g. calendar events not tied to a system) stay visible to scoped users."""
    from sqlalchemy import or_
    ids = allowed_system_ids(db, user)
    if ids is None:
        return ()
    return (or_(system_id_col.is_(None), system_id_col.in_(ids)),)


def audit_scope_filter(db: Session, user: User) -> tuple:
    """Splat-style filter for AuditEntry queries: a scoped user sees only
    entries recorded against one of their systems (system_id), plus the
    create/update/delete entries of those systems themselves (entity_type
    'system', which carry the system as entity_id rather than system_id).
    Org-level entries (system_id NULL) are hidden from scoped users."""
    from sqlalchemy import and_, or_
    from models.audit import AuditEntry
    ids = allowed_system_ids(db, user)
    if ids is None:
        return ()
    return (or_(
        AuditEntry.system_id.in_(ids),
        and_(AuditEntry.entity_type == "system", AuditEntry.entity_id.in_(ids)),
    ),)


def require_system_allowed(db: Session, user: User, system_id: int | None) -> None:
    """404 when a scoped user touches a system outside their assignments.
    (404, not 403 — mirrors the app's cross-org convention: don't reveal that
    the system exists.) None system_id (org-level rows) passes."""
    if system_id is None:
        return
    ids = allowed_system_ids(db, user)
    if ids is not None and system_id not in ids:
        raise HTTPException(404, "System not found")

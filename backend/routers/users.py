from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session
from database import get_db
from models.user import User
from models.session import UserSession
from schemas import UserCreate, UserUpdate, UserOut
from services.auth import hash_password
from services.password_policy import validate_password
from services import audit as audit_svc
from services import api_token as api_token_svc
from dependencies import get_current_user, require_role, ROLE_HIERARCHY

router = APIRouter()


def _require_unique_email(db: Session, organization_id: int, email: str | None, exclude_id: int | None = None) -> None:
    """Emails are unique per company, case-insensitively: SSO links a new
    identity to the one account holding its address (R2SEC-9). Existing
    duplicates are left alone — SSO refuses to link them."""
    if not email:
        return
    q = db.query(User.id).filter(User.organization_id == organization_id,
                                 func.lower(func.trim(User.email)) == email)
    if exclude_id is not None:
        q = q.filter(User.id != exclude_id)
    if q.first():
        raise HTTPException(409, "Another user in this company already has this email address")


def _end_access(db: Session, target: User) -> int:
    """Sign the user out everywhere and revoke their API tokens."""
    db.query(UserSession).filter(UserSession.user_id == target.id).delete()
    # API tokens act as the user; they must not outlive the credential or
    # privilege they were minted under (SECCODE-10).
    return api_token_svc.revoke_all_for_user(db, target.id)


def _unbind_sso(target: User) -> bool:
    was = bool(target.oidc_subject)
    target.oidc_issuer = None
    target.oidc_subject = None
    return was


@router.get("", response_model=list[UserOut])
def list_users(user: User = Depends(require_role("admin", "compliance_manager")), db: Session = Depends(get_db)):
    return db.query(User).filter(User.organization_id == user.organization_id).all()


# Fixed path — MUST stay registered before the /{user_id} param routes below.
@router.get("/assignable")
def assignable_users(
    finding_system_id: int | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Minimal teammate directory (id + name) so any role can populate an
    owner/assignee picker without the admin-only full user listing.

    With ``finding_system_id`` it lists only people who could actually work a
    finding on that system (R2USER-12): roles with work:own_finding (not the
    read-only auditor) whose system access includes it."""
    rows = db.query(User).filter(
        User.organization_id == user.organization_id,
        User.is_active == True,  # noqa: E712
    ).order_by(User.display_name, User.username).all()
    if finding_system_id is not None:
        from services.permissions import can
        from services.system_scope import allowed_system_ids
        from models.system import System
        # The filter reveals who can reach a system, so the caller must be able to
        # work findings and see that system: one in another org, outside the
        # caller's assignments, or nonexistent all answer the same 404.
        if not (can(user.role, "edit:finding") or can(user.role, "work:own_finding")):
            raise HTTPException(403, "Permission denied: work:own_finding")
        own = allowed_system_ids(db, user)
        exists = db.query(System.id).filter(
            System.id == finding_system_id, System.organization_id == user.organization_id,
        ).first()
        if not exists or (own is not None and finding_system_id not in own):
            raise HTTPException(404, "System not found")

        def can_work(u: User) -> bool:
            if not can(u.role, "work:own_finding"):
                return False
            ids = allowed_system_ids(db, u)
            return ids is None or finding_system_id in ids
        rows = [u for u in rows if can_work(u)]
    return [{"id": u.id, "display_name": u.display_name or u.username, "username": u.username} for u in rows]


@router.post("", response_model=UserOut)
def create_user(req: UserCreate, user: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    if req.role not in ROLE_HIERARCHY:
        raise HTTPException(422, f"Invalid role: {req.role}")
    pw_error = validate_password(req.password, username=req.username)
    if pw_error:
        raise HTTPException(422, pw_error)
    # Globally unique: sign-in looks usernames up across every company.
    existing = db.query(User.id).filter(User.username == req.username).first()
    if existing:
        raise HTTPException(409, "Username already exists")
    _require_unique_email(db, user.organization_id, req.email)

    new_user = User(
        organization_id=user.organization_id,
        username=req.username,
        password_hash=hash_password(req.password),
        email=req.email,
        display_name=req.display_name or req.username,
        role=req.role,
    )
    db.add(new_user)
    db.flush()
    audit_svc.record(db, organization_id=user.organization_id, actor_id=user.id,
                     actor_username=user.username, action="CREATE", entity_type="user",
                     entity_id=new_user.id,
                     summary=f"Created user {new_user.username} (role={new_user.role})")
    db.commit()
    db.refresh(new_user)
    return new_user


@router.patch("/{user_id}", response_model=UserOut)
def update_user(user_id: int, req: UserUpdate, user: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    target = db.query(User).filter(User.id == user_id, User.organization_id == user.organization_id).first()
    if not target:
        raise HTTPException(404, "User not found")

    changes = req.model_dump(exclude_unset=True)
    if "role" in changes and changes["role"] not in ROLE_HIERARCHY:
        raise HTTPException(422, f"Invalid role: {changes['role']}")
    if target.id == user.id and ("role" in changes or changes.get("is_active") is False):
        raise HTTPException(400, "Cannot change your own role or deactivate yourself")

    email_changed = "email" in changes and (changes["email"] or "") != (target.email or "").strip().lower()
    if email_changed:
        _require_unique_email(db, user.organization_id, changes["email"], exclude_id=target.id)
    active_changed = "is_active" in changes and changes["is_active"] != target.is_active

    new_password = changes.pop("password", None)
    if new_password:
        pw_error = validate_password(new_password, username=target.username)
        if pw_error:
            raise HTTPException(422, pw_error)
        target.password_hash = hash_password(new_password)

    for field, val in changes.items():
        setattr(target, field, val)

    # A changed email or a de/reactivation ends the SSO binding: the identity
    # links again (by the new address, inside the company) on the next SSO
    # sign-in, and everything issued under the old binding is revoked.
    unbound = _unbind_sso(target) if (email_changed or active_changed) else False
    revoked = 0
    if changes.get("is_active") is False or "role" in changes or new_password or email_changed or active_changed:
        revoked = _end_access(db, target)

    audit_svc.record(db, organization_id=user.organization_id, actor_id=user.id,
                     actor_username=user.username, action="UPDATE", entity_type="user",
                     entity_id=target.id,
                     summary=f"Updated user {target.username}: {', '.join(sorted(list(changes.keys()) + (['password reset'] if new_password else [])))}"
                             + (" (SSO link removed)" if unbound else "")
                             + (f" ({revoked} API token(s) revoked)" if revoked else ""))
    db.commit()
    db.refresh(target)
    return target


@router.delete("/{user_id}")
def deactivate_user(user_id: int, user: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    target = db.query(User).filter(User.id == user_id, User.organization_id == user.organization_id).first()
    if not target:
        raise HTTPException(404, "User not found")
    if target.id == user.id:
        raise HTTPException(400, "Cannot deactivate yourself")
    target.is_active = False
    _unbind_sso(target)
    revoked = _end_access(db, target)
    audit_svc.record(db, organization_id=user.organization_id, actor_id=user.id,
                     actor_username=user.username, action="DELETE", entity_type="user",
                     entity_id=target.id,
                     summary=f"Deactivated user {target.username}"
                             + (f" ({revoked} API token(s) revoked)" if revoked else ""))
    db.commit()
    return {"ok": True}


@router.delete("/{user_id}/sso")
def unlink_sso(user_id: int, user: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Remove the SSO identity bound to this account (wrong person linked, or
    the IdP account changed). The user is signed out and their API tokens are
    revoked; their next SSO sign-in links again by email."""
    target = db.query(User).filter(User.id == user_id, User.organization_id == user.organization_id).first()
    if not target:
        raise HTTPException(404, "User not found")
    if not target.oidc_subject:
        raise HTTPException(409, "This user has no SSO link")
    _unbind_sso(target)
    revoked = _end_access(db, target)
    audit_svc.record(db, organization_id=user.organization_id, actor_id=user.id,
                     actor_username=user.username, action="UPDATE", entity_type="user",
                     entity_id=target.id,
                     summary=f"Unlinked SSO identity from {target.username}"
                             + (f" ({revoked} API token(s) revoked)" if revoked else ""))
    db.commit()
    db.refresh(target)
    return {"ok": True}


@router.get("/{user_id}/systems")
def get_user_systems(user_id: int, user: User = Depends(require_role("admin", "compliance_manager")), db: Session = Depends(get_db)):
    """The system ids a user is assigned to (empty = org-wide visibility)."""
    from models.system_assignment import SystemAssignment

    target = db.query(User).filter(
        User.id == user_id, User.organization_id == user.organization_id
    ).first()
    if not target:
        raise HTTPException(404, "User not found")
    rows = db.query(SystemAssignment.system_id).filter(SystemAssignment.user_id == user_id).all()
    return {"user_id": user_id, "system_ids": [sid for (sid,) in rows]}


class SystemAssignmentUpdate(BaseModel):
    system_ids: list[int]


@router.put("/{user_id}/systems")
def set_user_systems(
    user_id: int,
    req: SystemAssignmentUpdate,
    user: User = Depends(require_role("admin", "compliance_manager")),
    db: Session = Depends(get_db),
):
    """Replace a user's system assignments. Empty list = unrestricted (org-wide).
    Admins/compliance managers are org-wide by role; assignments on them are
    stored but have no effect."""
    from models.system import System
    from models.system_assignment import SystemAssignment
    from services import audit as audit_svc

    target = db.query(User).filter(
        User.id == user_id, User.organization_id == user.organization_id
    ).first()
    if not target:
        raise HTTPException(404, "User not found")

    wanted = set(req.system_ids)
    if wanted:
        valid = {
            s.id for s in db.query(System).filter(
                System.organization_id == user.organization_id,
                System.id.in_(wanted),
            ).all()
        }
        if valid != wanted:
            raise HTTPException(422, "One or more systems do not exist in your organization")

    db.query(SystemAssignment).filter(SystemAssignment.user_id == user_id).delete()
    for sid in sorted(wanted):
        db.add(SystemAssignment(user_id=user_id, system_id=sid))
    audit_svc.record(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, action="UPDATE", entity_type="user",
        entity_id=user_id,
        summary=(f"System assignments for {target.username}: "
                 + (f"{len(wanted)} system(s)" if wanted else "unrestricted (org-wide)")),
    )
    db.commit()
    return {"user_id": user_id, "system_ids": sorted(wanted)}

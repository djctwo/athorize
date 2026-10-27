from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from services.natural_sort import control_sort_key
from database import get_db
from models.user import User
from models.control import Control
from models.control_implementation import ControlImplementation
from models.system import System
from schemas import ControlImplementationUpsert
from dependencies import get_current_user, require_can, require_min_role
from services import audit as audit_svc
from services.payload import safe_commit
from services.system_scope import system_scope_filter, system_scope_filter_nullable, require_system_allowed

router = APIRouter()

VALID_IMPL_STATUSES = {
    "IMPLEMENTED", "PARTIALLY", "NOT_IMPLEMENTED", "NOT_APPLICABLE",
    "INHERITED", "PLANNED", "NOT_ASSESSED",
}


@router.get("")
def list_controls(
    framework_id: str | None = None,
    family: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from routers.frameworks import hidden_framework_ids
    q = db.query(Control)
    hidden = hidden_framework_ids(user)
    if hidden:
        q = q.filter(Control.framework_id.notin_(hidden))
    if framework_id:
        q = q.filter(Control.framework_id == framework_id)
    if family:
        q = q.filter(Control.family == family)
    return sorted(q.all(), key=lambda c: (c.framework_id, control_sort_key(c.control_id)))


class BulkImplementationTarget(BaseModel):
    system_id: int
    framework_id: str
    control_id: str


class BulkImplementationsUpdate(BaseModel):
    targets: list[BulkImplementationTarget]
    implementation_status: str | None = None
    owner_id: int | None = None


# Registered EARLY on purpose: fixed-path routes must come before the
# parameterized catch-alls further down this router (route ordering has
# bitten this repo 3x — see CLAUDE.md "FastAPI route shadowing").
@router.post("/bulk")
def bulk_update_implementations(
    req: BulkImplementationsUpdate,
    user: User = Depends(require_can("assess:control")),
    db: Session = Depends(get_db),
):
    """Set implementation status and/or owner on many controls — across any
    mix of systems and frameworks — in one call (mirrors POST /findings/bulk).
    Targets whose system is outside the caller's org or system scope are
    skipped and reported, not failed, so one bad target doesn't abort the
    batch. Rows are created for controls not yet assessed; narratives and
    other assessed fields are preserved."""
    if not req.targets:
        raise HTTPException(422, "No controls selected")
    if req.implementation_status is not None and req.implementation_status not in VALID_IMPL_STATUSES:
        raise HTTPException(422, f"Invalid implementation_status: {req.implementation_status}")
    if req.implementation_status is None and req.owner_id is None:
        raise HTTPException(422, "Nothing to change: provide implementation_status and/or owner_id")
    _verify_owner_in_org(req.owner_id, user, db)
    from routers.frameworks import hidden_framework_ids
    hidden = hidden_framework_ids(user)

    # One visibility query for the whole batch: org-scope + system-scope.
    requested_systems = {t.system_id for t in req.targets}
    visible_systems = {
        sid for (sid,) in db.query(System.id).filter(
            System.id.in_(requested_systems),
            System.organization_id == user.organization_id,
            *system_scope_filter(System.id, db, user),
        ).all()
    }

    # Dedupe targets — a repeated triple would otherwise insert twice.
    seen: set[tuple[int, str, str]] = set()
    targets: list[BulkImplementationTarget] = []
    for t in req.targets:
        key = (t.system_id, t.framework_id, t.control_id)
        if key not in seen:
            seen.add(key)
            targets.append(t)

    existing = {
        (i.system_id, i.framework_id, i.control_id): i
        for i in db.query(ControlImplementation).filter(
            ControlImplementation.system_id.in_(visible_systems),
            ControlImplementation.framework_id.in_({t.framework_id for t in targets}),
            ControlImplementation.control_id.in_({t.control_id for t in targets}),
        ).all()
    } if visible_systems else {}

    updated: list[tuple[int, str, str]] = []
    skipped: list[dict] = []
    for t in targets:
        if t.system_id not in visible_systems:
            # Same reason for cross-org and out-of-scope: never confirm to a
            # caller that a system they can't see exists.
            skipped.append({
                "system_id": t.system_id, "framework_id": t.framework_id,
                "control_id": t.control_id, "reason": "system not found",
            })
            continue
        if t.framework_id in hidden:
            # Another company's private custom framework (R2SEC-2).
            skipped.append({
                "system_id": t.system_id, "framework_id": t.framework_id,
                "control_id": t.control_id, "reason": "framework not found",
            })
            continue
        key = (t.system_id, t.framework_id, t.control_id)
        impl = existing.get(key)
        if impl is None:
            impl = ControlImplementation(
                system_id=t.system_id, framework_id=t.framework_id, control_id=t.control_id,
            )
            db.add(impl)
            existing[key] = impl
        if req.implementation_status is not None:
            impl.implementation_status = req.implementation_status
        if req.owner_id is not None:
            impl.owner_id = req.owner_id
        updated.append(key)

    if updated:
        changes = []
        if req.implementation_status is not None:
            changes.append(f"status → {req.implementation_status}")
        if req.owner_id is not None:
            changes.append("owner assigned")
        updated_systems = {k[0] for k in updated}
        audit_svc.record(
            db, organization_id=user.organization_id, actor_id=user.id,
            actor_username=user.username, action="BULK_UPDATE",
            entity_type="control_implementation",
            system_id=next(iter(updated_systems)) if len(updated_systems) == 1 else None,
            summary=(f"Bulk-updated {len(updated)} control implementation(s) "
                     f"across {len(updated_systems)} system(s): {', '.join(changes)}"),
        )
    safe_commit(db)
    return {"updated": len(updated), "skipped": skipped}


@router.get("/baselines")
def list_baselines(
    framework_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Distinct baseline/level tags present in a framework's catalog (e.g.
    SL1-SL4, OT_LOW/MODERATE/HIGH). Empty list = framework has no baselines."""
    from routers.frameworks import require_framework_visible
    require_framework_visible(framework_id, user)
    rows = db.query(Control.baselines).filter(Control.framework_id == framework_id).all()
    seen: set[str] = set()
    for (baselines,) in rows:
        seen.update(baselines or [])
    return sorted(seen)


class ScopeRequest(BaseModel):
    framework_id: str
    baseline: str


@router.post("/systems/{system_id}/scope")
def scope_to_baseline(
    system_id: int,
    req: ScopeRequest,
    user: User = Depends(require_can("assess:control")),
    db: Session = Depends(get_db),
):
    """Scoping wizard: mark every control OUTSIDE the chosen baseline as
    NOT_APPLICABLE for this system — without clobbering assessed work. Only
    missing rows are created and only NOT_ASSESSED rows are updated; anything a
    human already touched is left alone (and reported as skipped)."""
    _verify_system_ownership(system_id, user, db)
    from routers.frameworks import require_framework_visible
    require_framework_visible(req.framework_id, user)
    controls = db.query(Control).filter(Control.framework_id == req.framework_id).all()
    if not controls:
        raise HTTPException(404, "Framework has no controls loaded (activate it first)")
    valid = set()
    for c in controls:
        valid.update(c.baselines or [])
    if req.baseline not in valid:
        raise HTTPException(422, f"Unknown baseline for {req.framework_id}: {req.baseline}")

    out_of_scope = [c.control_id for c in controls if req.baseline not in (c.baselines or [])]
    existing = {
        i.control_id: i
        for i in db.query(ControlImplementation).filter(
            ControlImplementation.system_id == system_id,
            ControlImplementation.framework_id == req.framework_id,
            ControlImplementation.control_id.in_(out_of_scope),
        ).all()
    } if out_of_scope else {}

    marked = 0
    skipped = 0
    note = f"Out of scope: not in the {req.baseline} baseline."
    for cid in out_of_scope:
        impl = existing.get(cid)
        if impl is None:
            db.add(ControlImplementation(
                system_id=system_id, framework_id=req.framework_id, control_id=cid,
                implementation_status="NOT_APPLICABLE", narrative=note,
            ))
            marked += 1
        elif impl.implementation_status == "NOT_ASSESSED":
            impl.implementation_status = "NOT_APPLICABLE"
            impl.narrative = impl.narrative or note
            marked += 1
        else:
            skipped += 1  # a human already recorded something — never overwrite

    audit_svc.record(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, action="SCOPE", entity_type="control_implementation",
        system_id=system_id,
        summary=(f"Scoped {req.framework_id} to baseline {req.baseline}: "
                 f"{marked} control(s) marked N/A, {skipped} skipped (already assessed)"),
    )
    safe_commit(db)
    return {
        "in_scope": len(controls) - len(out_of_scope),
        "marked_na": marked,
        "skipped_assessed": skipped,
    }


def _verify_system_ownership(system_id: int, user: User, db: Session) -> System:
    system = db.query(System).filter(
        System.id == system_id, System.organization_id == user.organization_id, *system_scope_filter(System.id, db, user)
    ).first()
    if not system:
        raise HTTPException(404, "System not found")
    return system


def _verify_owner_in_org(owner_id: int | None, user: User, db: Session) -> None:
    """An assigned owner must be an active user in the caller's organization."""
    if owner_id is None:
        return
    ok = db.query(User).filter(
        User.id == owner_id,
        User.organization_id == user.organization_id,
        User.is_active == True,  # noqa: E712
    ).first()
    if not ok:
        raise HTTPException(422, "owner_id is not an active user in your organization")


def _verify_controls_in_catalog(framework_id: str, control_ids: list[str], db: Session) -> None:
    """Implementations may only be recorded for controls in the framework's
    catalog — an orphan row would otherwise count toward nothing the user can
    see (and, before INTEGRITY-1, inflated the score past 100%). Only
    enforced when the framework's catalog is loaded; rows for a framework
    with no catalog are never scored (services.compliance_score joins the
    catalog)."""
    if db.query(Control.control_id).filter(Control.framework_id == framework_id).first() is None:
        return
    known = {cid for (cid,) in db.query(Control.control_id).filter(
        Control.framework_id == framework_id, Control.control_id.in_(set(control_ids)))}
    unknown = sorted(set(control_ids) - known)
    if unknown:
        if len(control_ids) == 1:
            raise HTTPException(404, f"Control {unknown[0]} is not in the {framework_id} catalog")
        raise HTTPException(422, f"Not in the {framework_id} catalog: {', '.join(unknown[:10])}")


@router.get("/systems/{system_id}")
def get_system_controls(
    system_id: int,
    framework_id: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _verify_system_ownership(system_id, user, db)
    q = db.query(ControlImplementation).filter(ControlImplementation.system_id == system_id)
    if framework_id:
        q = q.filter(ControlImplementation.framework_id == framework_id)
    return q.all()


def _find_impl(db: Session, system_id: int, framework_id: str, control_id: str) -> ControlImplementation | None:
    return db.query(ControlImplementation).filter(
        ControlImplementation.system_id == system_id,
        ControlImplementation.framework_id == framework_id,
        ControlImplementation.control_id == control_id,
    ).first()


_CONFLICT_MSG = ("This control was changed by someone else after you opened it. "
                 "Load the latest version, then re-apply your edit.")


def _claim_version(db: Session, impl: ControlImplementation, expected) -> None:
    """Optimistic concurrency for control edits (R2DATA-12), done atomically:
    a conditional UPDATE bumps updated_at only if it still equals the version
    the editor loaded. That statement takes SQLite's write lock, so of two saves
    holding the same version exactly one matches; the other gets 409 instead of
    silently reverting the first."""
    if expected is None:
        return  # API clients that don't send a version keep last-write-wins
    from datetime import datetime, timezone
    from sqlalchemy import update
    if expected.tzinfo is None:
        expected = expected.replace(tzinfo=timezone.utc)
    current = impl.updated_at
    if current is not None and current.astimezone(timezone.utc) != expected.astimezone(timezone.utc):
        raise HTTPException(409, _CONFLICT_MSG)
    cond = ControlImplementation.updated_at.is_(None) if current is None else ControlImplementation.updated_at == expected
    res = db.execute(
        update(ControlImplementation)
        .where(ControlImplementation.id == impl.id, cond)
        .values(updated_at=datetime.now(timezone.utc))
        .execution_options(synchronize_session=False)
    )
    if res.rowcount != 1:
        db.rollback()
        raise HTTPException(409, _CONFLICT_MSG)


@router.put("/systems/{system_id}/{framework_id}/{control_id}")
def upsert_implementation(
    system_id: int,
    framework_id: str,
    control_id: str,
    req: ControlImplementationUpsert,
    user: User = Depends(require_can("assess:control")),
    db: Session = Depends(get_db),
):
    _verify_system_ownership(system_id, user, db)
    _verify_owner_in_org(req.owner_id, user, db)
    if req.implementation_status not in VALID_IMPL_STATUSES:
        raise HTTPException(422, f"Invalid implementation_status: {req.implementation_status}")
    from routers.frameworks import require_framework_visible
    require_framework_visible(framework_id, user)
    _verify_controls_in_catalog(framework_id, [control_id], db)
    impl = _find_impl(db, system_id, framework_id, control_id)
    changes = req.model_dump(exclude_unset=True)
    # An explicit null means "I opened this control before it had any saved
    # implementation" — someone creating it meanwhile is a conflict too.
    version_sent = "expected_updated_at" in changes
    expected = changes.pop("expected_updated_at", None)

    action = "UPDATE"
    if impl:
        if version_sent and expected is None:
            raise HTTPException(409, _CONFLICT_MSG)
        _claim_version(db, impl, expected)
        for field, val in changes.items():
            setattr(impl, field, val)
        db.flush()
    else:
        action = "CREATE"
        impl = ControlImplementation(
            system_id=system_id,
            framework_id=framework_id,
            control_id=control_id,
            **req.model_dump(exclude={"expected_updated_at"}),
        )
        db.add(impl)
        try:
            db.flush()
        except IntegrityError:
            # Another request created the row between our read and insert (two
            # tabs/users assessing the same control for the first time): apply
            # this edit as an update instead of failing with a 500 — unless the
            # editor said which version it saw, which the new row is not.
            db.rollback()
            impl = _find_impl(db, system_id, framework_id, control_id)
            if impl is None:
                raise HTTPException(409, "This control was being saved by someone else — try again")
            if version_sent:
                raise HTTPException(409, _CONFLICT_MSG)
            action = "UPDATE"
            for field, val in changes.items():
                setattr(impl, field, val)
            db.flush()
    audit_svc.record(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, action=action, entity_type="control_implementation",
        system_id=system_id, summary=f"{framework_id}/{control_id}: {req.implementation_status}",
    )
    safe_commit(db)
    db.refresh(impl)
    return impl


class BulkImplementationUpdate(BaseModel):
    framework_id: str
    control_ids: list[str]
    implementation_status: str | None = None
    owner_id: int | None = None
    assign_owner: bool = False  # distinguishes "assign to owner_id (incl. None=unassign)" from "leave owner alone"


@router.post("/systems/{system_id}/bulk")
def bulk_upsert_implementations(
    system_id: int,
    req: BulkImplementationUpdate,
    user: User = Depends(require_can("assess:control")),
    db: Session = Depends(get_db),
):
    """Set status and/or owner on many controls for one system at once
    (creating rows for controls not yet assessed). Narratives are preserved."""
    _verify_system_ownership(system_id, user, db)
    if req.implementation_status is not None and req.implementation_status not in VALID_IMPL_STATUSES:
        raise HTTPException(422, f"Invalid implementation_status: {req.implementation_status}")
    if req.implementation_status is None and not req.assign_owner:
        raise HTTPException(422, "Nothing to change: provide implementation_status and/or assign_owner")
    if req.assign_owner:
        _verify_owner_in_org(req.owner_id, user, db)
    # A repeated id (double-click, merged selections) must not insert the row
    # twice — that was a UNIQUE violation and an HTTP 500 (INTEGRITY-4).
    control_ids = list(dict.fromkeys(req.control_ids))
    if not control_ids:
        raise HTTPException(422, "No controls selected")
    from routers.frameworks import require_framework_visible
    require_framework_visible(req.framework_id, user)
    _verify_controls_in_catalog(req.framework_id, req.control_ids, db)

    existing = {
        i.control_id: i
        for i in db.query(ControlImplementation).filter(
            ControlImplementation.system_id == system_id,
            ControlImplementation.framework_id == req.framework_id,
            ControlImplementation.control_id.in_(control_ids),
        ).all()
    }
    for cid in control_ids:
        impl = existing.get(cid)
        if impl is None:
            impl = ControlImplementation(
                system_id=system_id, framework_id=req.framework_id, control_id=cid,
            )
            db.add(impl)
        if req.implementation_status is not None:
            impl.implementation_status = req.implementation_status
        if req.assign_owner:
            impl.owner_id = req.owner_id

    changes = []
    if req.implementation_status is not None:
        changes.append(f"status → {req.implementation_status}")
    if req.assign_owner:
        changes.append("owner assigned" if req.owner_id else "owner cleared")
    audit_svc.record(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, action="BULK_UPDATE", entity_type="control_implementation",
        system_id=system_id,
        summary=f"Bulk-updated {len(control_ids)} {req.framework_id} control(s): {', '.join(changes)}",
    )
    safe_commit(db)
    return {"updated": len(control_ids)}


# NOTE: this catch-all param route MUST stay LAST — registered before the
# fixed-prefix "/systems/..." routes it would shadow them (e.g. GET
# /controls/systems/4 would match framework_id="systems", control_id="4").
@router.get("/{framework_id}/{control_id}")
def get_control(framework_id: str, control_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    from routers.frameworks import hidden_framework_ids
    if framework_id in hidden_framework_ids(user):
        raise HTTPException(404, "Control not found")
    control = db.query(Control).filter(
        Control.framework_id == framework_id,
        Control.control_id == control_id,
    ).first()
    if not control:
        raise HTTPException(404, "Control not found")
    return control

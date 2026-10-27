from datetime import date, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from models.user import User
from models.conmon import ConMonEntry
from models.system import System
from models.framework_activation import FrameworkActivation
from models.evidence import EvidenceArtifact
from schemas import ConMonCreate, ConMonUpdate
from dependencies import get_current_user, require_can
from services import audit as audit_svc
from services.payload import safe_commit
from services import conmon_cadence as cadence_svc
from pydantic import BaseModel
from services.system_scope import system_scope_filter, system_scope_filter_nullable, require_system_allowed

_MAX_BACKDATE_DAYS = 90

router = APIRouter()


class CadenceUpsert(BaseModel):
    framework_id: str = ""
    activity_type: str
    interval_days: int
    enabled: bool = True


@router.get("/cadences")
def list_cadences(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Resolved cadence requirements + computed status (last done / next due /
    overdue) for the org's active frameworks."""
    return cadence_svc.list_cadences(db, user.organization_id)


@router.put("/cadences", dependencies=[Depends(require_can("edit:conmon"))])
def upsert_cadence(req: CadenceUpsert, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if req.interval_days < 1 or req.interval_days > 3650:
        raise HTTPException(422, "interval_days must be between 1 and 3650")
    cadence_svc.set_cadence(
        db, user.organization_id, req.framework_id, req.activity_type,
        req.interval_days, req.enabled,
    )
    audit_svc.record(db, organization_id=user.organization_id, actor_id=user.id,
                     actor_username=user.username, action="UPDATE", entity_type="conmon_cadence",
                     summary=f"Set cadence {req.framework_id or 'org-wide'}/{req.activity_type} = {req.interval_days}d"
                             + ("" if req.enabled else " (disabled)"))
    safe_commit(db)
    return {"ok": True}


def _summary(e: ConMonEntry) -> str:
    label = (e.activity_type or "ACTIVITY").replace("_", " ")
    when = e.entry_date.isoformat() if e.entry_date else ""
    return f"{label} on {when}" if when else label


@router.get("")
def list_entries(
    system_id: int | None = None,
    framework_id: str | None = None,
    activity_type: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(ConMonEntry).filter(ConMonEntry.organization_id == user.organization_id, *system_scope_filter(ConMonEntry.system_id, db, user))
    if system_id:
        q = q.filter(ConMonEntry.system_id == system_id)
    if framework_id:
        q = q.filter(ConMonEntry.framework_id == framework_id)
    if activity_type:
        q = q.filter(ConMonEntry.activity_type == activity_type)
    return q.order_by(ConMonEntry.entry_date.desc()).all()


@router.get("/{entry_id}")
def get_entry(entry_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    e = db.query(ConMonEntry).filter(
        ConMonEntry.id == entry_id, ConMonEntry.organization_id == user.organization_id, *system_scope_filter(ConMonEntry.system_id, db, user)
    ).first()
    if not e:
        raise HTTPException(404, "ConMon entry not found")
    return e


def _require_evidence_visible(db: Session, user: User, evidence_id: int | None) -> None:
    """A linked evidence artifact must belong to the caller's company and lie
    within their system scope — otherwise 404 (don't reveal it exists), so an
    entry can never point at another tenant's or another system's evidence."""
    if evidence_id is None:
        return
    ok = db.query(EvidenceArtifact.id).filter(
        EvidenceArtifact.id == evidence_id,
        EvidenceArtifact.organization_id == user.organization_id,
        *system_scope_filter(EvidenceArtifact.system_id, db, user),
    ).first()
    if not ok:
        raise HTTPException(404, "Evidence not found")


@router.post("")
def create_entry(
    payload: ConMonCreate,
    user: User = Depends(require_can("edit:conmon")),
    db: Session = Depends(get_db),
):
    system = db.query(System).filter(
        System.id == payload.system_id, System.organization_id == user.organization_id, *system_scope_filter(System.id, db, user)
    ).first()
    if not system:
        raise HTTPException(404, "System not found")

    data = payload.model_dump()
    entry_date = data.get("entry_date")
    if entry_date:
        today = date.today()
        earliest = today - timedelta(days=_MAX_BACKDATE_DAYS)
        # +1 day of slack: the browser sends the user's LOCAL date, which east of
        # the server's zone is already "tomorrow" for part of the day.
        latest = today + timedelta(days=1)
        if entry_date < earliest or entry_date > latest:
            raise HTTPException(422, f"entry_date must be between {earliest} and {today}")

    _require_evidence_visible(db, user, data.get("evidence_artifact_id"))

    # A framework-specific entry must name a framework active for this org —
    # it is what satisfies that framework's cadence (E2E-8).
    if data.get("framework_id"):
        active = db.query(FrameworkActivation).filter(
            FrameworkActivation.organization_id == user.organization_id,
            FrameworkActivation.framework_id == data["framework_id"],
            FrameworkActivation.is_active == True,  # noqa: E712
        ).first()
        if not active:
            raise HTTPException(422, "framework_id is not an active framework for your organization")

    e = ConMonEntry(organization_id=user.organization_id, **data)
    db.add(e)
    db.flush()
    audit_svc.record(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, action="CREATE", entity_type="conmon",
        entity_id=e.id, system_id=e.system_id, summary=_summary(e),
    )
    safe_commit(db)
    db.refresh(e)
    return e


@router.patch("/{entry_id}")
def update_entry(
    entry_id: int, payload: ConMonUpdate,
    user: User = Depends(require_can("edit:conmon")),
    db: Session = Depends(get_db),
):
    e = db.query(ConMonEntry).filter(
        ConMonEntry.id == entry_id, ConMonEntry.organization_id == user.organization_id, *system_scope_filter(ConMonEntry.system_id, db, user)
    ).first()
    if not e:
        raise HTTPException(404, "ConMon entry not found")

    updates = payload.model_dump(exclude_unset=True)
    if "evidence_artifact_id" in updates:
        _require_evidence_visible(db, user, updates["evidence_artifact_id"])
    if "entry_date" in updates and updates["entry_date"] is not None:
        entry_date = updates["entry_date"]
        today = date.today()
        earliest = today - timedelta(days=_MAX_BACKDATE_DAYS)
        if entry_date < earliest or entry_date > today:
            raise HTTPException(422, f"entry_date must be between {earliest} and {today}")

    for k, v in updates.items():
        setattr(e, k, v)
    audit_svc.record(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, action="UPDATE", entity_type="conmon",
        entity_id=e.id, system_id=e.system_id, summary=_summary(e),
    )
    safe_commit(db)
    db.refresh(e)
    return e


@router.delete("/{entry_id}")
def delete_entry(
    entry_id: int,
    user: User = Depends(require_can("edit:conmon")),
    db: Session = Depends(get_db),
):
    e = db.query(ConMonEntry).filter(
        ConMonEntry.id == entry_id, ConMonEntry.organization_id == user.organization_id, *system_scope_filter(ConMonEntry.system_id, db, user)
    ).first()
    if not e:
        raise HTTPException(404, "ConMon entry not found")
    audit_svc.record(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, action="DELETE", entity_type="conmon",
        entity_id=e.id, system_id=e.system_id, summary=_summary(e),
    )
    db.delete(e)
    safe_commit(db)
    return {"deleted": entry_id}

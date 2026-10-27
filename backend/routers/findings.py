from datetime import date, datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session
from database import get_db
from models.user import User
from models.finding import Finding
from models.system import System
from schemas import FindingCreate, FindingUpdate, BulkImportPayload
from dependencies import get_current_user, require_min_role, require_can
from services import audit as audit_svc
from services.aging import compute_aging
from services.payload import safe_commit, coerce_dates
from services.bulk_import import run_bulk_import
from services.control_catalog import CatalogIndex, active_framework_ids, require_active_framework, require_known_control
from services.system_scope import system_scope_filter, system_scope_filter_nullable, require_system_allowed
from services.permissions import can

router = APIRouter()

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
VALID_STATUSES = {"OPEN", "IN_PROGRESS", "CLOSED", "RISK_ACCEPTED", "FALSE_POSITIVE", "DELAYED"}

_FINDING_TRANSITIONS: dict[str, set[str]] = {
    "OPEN": {"IN_PROGRESS", "CLOSED", "RISK_ACCEPTED", "FALSE_POSITIVE"},
    "IN_PROGRESS": {"CLOSED", "RISK_ACCEPTED", "DELAYED", "OPEN"},
    "DELAYED": {"OPEN", "IN_PROGRESS", "CLOSED", "RISK_ACCEPTED"},
    "CLOSED": set(),
    "RISK_ACCEPTED": set(),
    "FALSE_POSITIVE": set(),
}

_TERMINAL_STATUSES = {"CLOSED", "RISK_ACCEPTED", "FALSE_POSITIVE"}

def _require_close_approval(user: User, new_status: str | None) -> None:
    """Moving a finding to a terminal status (closed, risk-accepted, false
    positive) is an approval decision, checked separately from editing
    (KNOWN-5): today approve:finding_close and edit:finding grant the same
    roles, but narrowing the approver set in services/permissions.py now
    takes effect on every close path."""
    if new_status in _TERMINAL_STATUSES and not can(user.role, "approve:finding_close"):
        raise HTTPException(403, "Permission denied: approve:finding_close")


_STATUS_REQUIRED_FIELDS: dict[str, str] = {
    "CLOSED": "actual_completion",
    "RISK_ACCEPTED": "risk_rationale",
}

DATE_FIELDS = {"scheduled_completion", "actual_completion", "due_date", "closed_date"}
IMPORT_FIELDS = {
    "title", "description", "weakness_description", "control_id", "severity",
    "status", "scheduled_completion", "owner_name", "owner_email", "remediation_plan",
    "framework_id",
}


def _serialize(f: Finding) -> dict:
    data = {c.name: getattr(f, c.name) for c in f.__table__.columns}
    data.update(compute_aging(f.due_date or f.scheduled_completion, f.created_at, f.status))
    return data


@router.get("")
def list_findings(
    system_id: int | None = None,
    framework_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    owner_id: int | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(Finding).filter(Finding.organization_id == user.organization_id, *system_scope_filter(Finding.system_id, db, user))
    if system_id:
        q = q.filter(Finding.system_id == system_id)
    if framework_id:
        q = q.filter(Finding.framework_id == framework_id)
    if severity:
        q = q.filter(Finding.severity == severity)
    if status:
        q = q.filter(Finding.status == status)
    if owner_id:
        q = q.filter(Finding.owner_id == owner_id)
    return [_serialize(f) for f in q.order_by(Finding.created_at.desc()).all()]


@router.post("")
def create_finding(req: FindingCreate, user: User = Depends(require_can("edit:finding")), db: Session = Depends(get_db)):
    if not db.query(System).filter(System.id == req.system_id, System.organization_id == user.organization_id, *system_scope_filter(System.id, db, user)).first():
        raise HTTPException(404, "System not found")

    _validate_owner(req.owner_id, user, db)
    data = req.model_dump()
    require_active_framework(db, user.organization_id, data["framework_id"])
    data["control_id"] = require_known_control(db, data.get("control_id"), data["framework_id"])
    _owner_contact(data, _validate_owner(data.get("owner_id"), user, db))
    if data.get("severity") and data["severity"] not in VALID_SEVERITIES:
        raise HTTPException(422, f"Invalid severity. Must be one of {sorted(VALID_SEVERITIES)}")
    data["status"] = "OPEN"
    finding = Finding(organization_id=user.organization_id, **data)
    db.add(finding)
    db.flush()
    audit_svc.record(db, organization_id=user.organization_id, actor_id=user.id,
                     actor_username=user.username, action="CREATE", entity_type="finding",
                     entity_id=finding.id, system_id=finding.system_id,
                     summary=f"Created finding: {finding.title}")
    safe_commit(db)
    db.refresh(finding)
    return _serialize(finding)


@router.get("/{finding_id}")
def get_finding(finding_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id, Finding.organization_id == user.organization_id, *system_scope_filter(Finding.system_id, db, user)).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    return _serialize(finding)


def _validate_owner(owner_id: int | None, user: User, db: Session) -> User | None:
    """An assigned owner must be a real user in the caller's org — never a
    cross-org user id (which would create a dangling FK no one in either org
    can see). owner_id None means "unassign", which is always allowed.
    Returns the owner (None when unassigning)."""
    if owner_id is None:
        return None
    owner = db.query(User).filter(
        User.id == owner_id, User.organization_id == user.organization_id
    ).first()
    if not owner:
        raise HTTPException(422, "owner_id must be a user in your organization")
    return owner


def _owner_contact(data: dict, owner: User | None) -> None:
    """When an owner is assigned by id, keep the denormalised owner_name /
    owner_email (POA&M exports, CSVs) in step unless the caller set them."""
    if owner is None:
        return
    if not data.get("owner_name"):
        data["owner_name"] = owner.display_name or owner.username
    if not data.get("owner_email"):
        data["owner_email"] = owner.email or ""


_CONFLICT = ("This finding was changed by someone else after you opened it. "
             "Reopen it to see the latest version, then re-apply your edit.")


def _same_instant(a: datetime | None, b: datetime | None) -> bool:
    if a is None or b is None:
        return True  # legacy row without updated_at: nothing to compare
    if a.tzinfo is None:
        a = a.replace(tzinfo=timezone.utc)
    if b.tzinfo is None:
        b = b.replace(tzinfo=timezone.utc)
    return a == b


# What the assigned owner may change without edit:finding (R2USER-12).
_OWNER_FIELDS = {"status", "milestones", "expected_updated_at"}
_OWNER_STATUSES = {"OPEN", "IN_PROGRESS", "DELAYED"}


def _require_edit_or_own_work(user: User, finding: Finding, changes: dict) -> None:
    if can(user.role, "edit:finding"):
        return
    if finding.owner_id != user.id:
        raise HTTPException(403, "Permission denied: edit:finding")
    if set(changes) - _OWNER_FIELDS:
        raise HTTPException(403, "As the finding's owner you can update its status and milestones; "
                                 "other fields need a compliance manager or admin")
    if "status" in changes and changes["status"] != finding.status and changes["status"] not in _OWNER_STATUSES:
        raise HTTPException(403, "Closing, accepting the risk or marking a false positive needs a "
                                 "compliance manager or admin")


@router.patch("/{finding_id}")
def update_finding(finding_id: int, req: FindingUpdate, user: User = Depends(require_can("work:own_finding")), db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id, Finding.organization_id == user.organization_id, *system_scope_filter(Finding.system_id, db, user)).first()
    if not finding:
        raise HTTPException(404, "Finding not found")

    changes = req.model_dump(exclude_unset=True)
    _require_edit_or_own_work(user, finding, changes)
    expected = changes.pop("expected_updated_at", None)
    if expected is not None and not _same_instant(expected, finding.updated_at):
        raise HTTPException(409, _CONFLICT)

    if "owner_id" in changes:
        owner = _validate_owner(changes["owner_id"], user, db)
        if changes["owner_id"] != finding.owner_id:
            prev = db.get(User, finding.owner_id) if finding.owner_id else None
            if prev is not None:
                # Drop contact details that were only the previous owner's.
                if "owner_name" not in changes and finding.owner_name in (prev.display_name, prev.username):
                    changes["owner_name"] = ""
                if "owner_email" not in changes and finding.owner_email and finding.owner_email == prev.email:
                    changes["owner_email"] = ""
            _owner_contact(changes, owner)

    if "severity" in changes and changes["severity"] not in VALID_SEVERITIES:
        raise HTTPException(422, f"Invalid severity: {changes['severity']}. Must be one of {sorted(VALID_SEVERITIES)}")
    if "control_id" in changes and (changes["control_id"] or "") != (finding.control_id or ""):
        changes["control_id"] = require_known_control(db, changes["control_id"], finding.framework_id)

    new_status = changes.get("status")
    if new_status and new_status != finding.status:
        _require_close_approval(user, new_status)
        current = finding.status or "OPEN"
        allowed = _FINDING_TRANSITIONS.get(current, set())

        if new_status != "OPEN" and new_status not in allowed:
            raise HTTPException(422, f"Invalid status transition from {current} to {new_status}")

        if new_status == "OPEN" and current in _TERMINAL_STATUSES:
            if not (changes.get("reopen_reason") or "").strip():
                raise HTTPException(422, f"Reopening from {current} requires a non-empty 'reopen_reason'")

        required_field = _STATUS_REQUIRED_FIELDS.get(new_status)
        if required_field:
            has_value = changes.get(required_field) or getattr(finding, required_field, None)
            if not has_value:
                raise HTTPException(422, f"Transition to {new_status} requires '{required_field}'")

    # The audit append takes the write lock (held until commit), so the version
    # re-read after it is the committed one: two saves holding the same version
    # can't both pass the check above and both win (R2DATA-4).
    audit_svc.record(db, organization_id=user.organization_id, actor_id=user.id,
                     actor_username=user.username, action="UPDATE", entity_type="finding",
                     entity_id=finding.id, system_id=finding.system_id,
                     summary=f"Updated finding: {changes.get('title') or finding.title}")
    if expected is not None:
        current = db.execute(select(Finding.updated_at).where(Finding.id == finding.id)).scalar_one()
        if not _same_instant(expected, current):
            db.rollback()
            raise HTTPException(409, _CONFLICT)

    for field, val in changes.items():
        setattr(finding, field, val)
    safe_commit(db)
    db.refresh(finding)
    return _serialize(finding)


class BulkFindingUpdate(BaseModel):
    ids: list[int]
    status: str | None = None
    owner_id: int | None = None
    owner_name: str | None = None
    owner_email: str | None = None


@router.post("/bulk")
def bulk_update_findings(req: BulkFindingUpdate, user: User = Depends(require_can("edit:finding")), db: Session = Depends(get_db)):
    """Apply a status change and/or owner assignment to many findings at once.
    Invalid status transitions are skipped (reported), not failed — so one bad
    finding doesn't abort the batch."""
    if not req.ids:
        raise HTTPException(422, "No findings selected")
    if req.status and req.status not in VALID_STATUSES:
        raise HTTPException(422, f"Invalid status: {req.status}")
    _require_close_approval(user, req.status)
    _validate_owner(req.owner_id, user, db)

    findings = db.query(Finding).filter(
        Finding.id.in_(req.ids), Finding.organization_id == user.organization_id, *system_scope_filter(Finding.system_id, db, user),
    ).all()

    updated, skipped = [], []
    for f in findings:
        if req.status and req.status != f.status:
            current = f.status or "OPEN"
            if req.status != "OPEN" and req.status not in _FINDING_TRANSITIONS.get(current, set()):
                skipped.append({"id": f.id, "reason": f"can't move {current} → {req.status}"})
                continue
            # Auto-fill the field a terminal status requires so bulk-close works.
            if req.status == "CLOSED" and not f.actual_completion:
                f.actual_completion = date.today()
            required = _STATUS_REQUIRED_FIELDS.get(req.status)
            if required and not getattr(f, required, None):
                skipped.append({"id": f.id, "reason": f"{req.status} needs {required} — set it on the finding first"})
                continue
            f.status = req.status
        if req.owner_id is not None:
            f.owner_id = req.owner_id
        if req.owner_name is not None:
            f.owner_name = req.owner_name
        if req.owner_email is not None:
            f.owner_email = req.owner_email
        updated.append(f.id)

    if updated:
        bits = []
        if req.status:
            bits.append(f"status→{req.status}")
        if req.owner_id is not None or req.owner_name is not None:
            bits.append("reassigned owner")
        audit_svc.record(db, organization_id=user.organization_id, actor_id=user.id,
                         actor_username=user.username, action="BULK_UPDATE", entity_type="finding",
                         summary=f"Bulk-updated {len(updated)} finding(s): {', '.join(bits) or 'no-op'}")
    safe_commit(db)
    return {"updated": len(updated), "skipped": skipped}


@router.delete("/{finding_id}")
def delete_finding(finding_id: int, user: User = Depends(require_can("edit:finding")), db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id, Finding.organization_id == user.organization_id, *system_scope_filter(Finding.system_id, db, user)).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    audit_svc.record(db, organization_id=user.organization_id, actor_id=user.id,
                     actor_username=user.username, action="DELETE", entity_type="finding",
                     entity_id=finding.id, system_id=finding.system_id,
                     summary=f"Deleted finding: {finding.title}")
    db.delete(finding)
    safe_commit(db)
    return {"ok": True}


def _validate_import_row(idx: int, row: dict) -> tuple[dict | None, list[dict]]:
    errors: list[dict] = []
    clean = {k: v for k, v in row.items() if k in IMPORT_FIELDS and v not in (None, "")}
    if not clean.get("title"):
        errors.append({"row": idx, "field": "title", "message": "title is required"})
    if not clean.get("framework_id"):
        errors.append({"row": idx, "field": "framework_id", "message": "framework_id is required"})
    sev = clean.get("severity")
    if sev and sev not in VALID_SEVERITIES:
        errors.append({"row": idx, "field": "severity", "message": f"'{sev}' not one of {sorted(VALID_SEVERITIES)}"})
    status = clean.get("status")
    if status and status != "OPEN":
        errors.append({"row": idx, "field": "status", "message": f"Imported findings must start as OPEN; got '{status}'"})
    if errors:
        return None, errors
    clean.setdefault("severity", "MEDIUM")
    clean.setdefault("status", "OPEN")
    return coerce_dates(clean, DATE_FIELDS), []


@router.post("/bulk-import/{system_id}")
def bulk_import(
    system_id: int, payload: BulkImportPayload,
    user: User = Depends(require_can("edit:finding")),
    db: Session = Depends(get_db),
):
    active = set(active_framework_ids(db, user.organization_id))
    catalogs = CatalogIndex(db, active)

    def validate_row(idx: int, row: dict) -> tuple[dict | None, list[dict]]:
        # Same catalog rules as a manual finding (R2DATA-6, R2USER-7), reported per row.
        clean, errors = _validate_import_row(idx, row)
        if clean is None:
            return None, errors
        fw = clean["framework_id"]
        if fw not in active:
            return None, [{"row": idx, "field": "framework_id",
                           "message": f"'{fw}' is not an active framework for this company"}]
        if clean.get("control_id"):
            hit = catalogs.canonical(clean["control_id"], fw)
            if hit is None:
                return None, [{"row": idx, "field": "control_id",
                               "message": f"'{clean['control_id']}' is not in the {fw} catalog"}]
            clean["control_id"] = hit
        return clean, []

    result = run_bulk_import(
        db,
        organization_id=user.organization_id,
        system_id=system_id,
        rows=payload.rows,
        commit=payload.commit,
        system_model=System,
        record_model=Finding,
        validate_row=validate_row,
    )
    if payload.commit and result.get("committed"):
        audit_svc.record(db, organization_id=user.organization_id, actor_id=user.id,
                         actor_username=user.username, action="BULK_IMPORT", entity_type="finding",
                         system_id=system_id,
                         summary=f"Imported {result['committed']} findings")
        db.commit()
    return result

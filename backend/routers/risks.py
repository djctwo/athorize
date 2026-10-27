from datetime import date, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from dependencies import get_current_user, require_can
from models import AuditEntry, Finding, System
from models.risk import RiskRegisterEntry
from models.user import User
from schemas import RiskCreate, RiskUpdate
from services import audit as audit_svc
from services.payload import safe_commit
from services.system_scope import system_scope_filter, system_scope_filter_nullable, require_system_allowed

router = APIRouter()

ENTITY = "RISK"
FINDING_SPAWN_LIMIT = 3

RISK_TO_SEVERITY = {
    "VERY_HIGH": "CRITICAL",
    "HIGH": "CRITICAL",
    "MODERATE": "HIGH",
    "LOW": "MEDIUM",
}

LIKELIHOOD_IMPACT = {"LOW", "MODERATE", "HIGH"}
RISK_LEVEL_MATRIX: dict[tuple[str, str], str] = {
    ("LOW", "LOW"): "LOW",
    ("LOW", "MODERATE"): "LOW",
    ("MODERATE", "LOW"): "LOW",
    ("LOW", "HIGH"): "MODERATE",
    ("HIGH", "LOW"): "MODERATE",
    ("MODERATE", "MODERATE"): "MODERATE",
    ("MODERATE", "HIGH"): "HIGH",
    ("HIGH", "MODERATE"): "HIGH",
    ("HIGH", "HIGH"): "VERY_HIGH",
}


def _risk_level(likelihood: str | None, impact: str | None) -> str | None:
    if likelihood in LIKELIHOOD_IMPACT and impact in LIKELIHOOD_IMPACT:
        return RISK_LEVEL_MATRIX[(likelihood, impact)]
    return None


def _serialize(r: RiskRegisterEntry) -> dict:
    data = {c.name: getattr(r, c.name) for c in r.__table__.columns}
    data["risk_level"] = _risk_level(r.likelihood, r.impact)
    return data


@router.get("")
def list_risks(
    system_id: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    q = db.query(RiskRegisterEntry).filter(RiskRegisterEntry.organization_id == user.organization_id, *system_scope_filter(RiskRegisterEntry.system_id, db, user))
    if system_id is not None:
        q = q.filter(RiskRegisterEntry.system_id == system_id)
    return [_serialize(r) for r in q.all()]


@router.get("/{risk_id}")
def get_risk(risk_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    r = (
        db.query(RiskRegisterEntry)
        .filter(RiskRegisterEntry.id == risk_id, RiskRegisterEntry.organization_id == user.organization_id, *system_scope_filter(RiskRegisterEntry.system_id, db, user))
        .first()
    )
    if not r:
        raise HTTPException(404, "Risk not found")
    return _serialize(r)


@router.post("", dependencies=[Depends(require_can("edit:risk"))])
def create_risk(
    payload: RiskCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    system = db.query(System).filter(
        System.id == payload.system_id, System.organization_id == user.organization_id, *system_scope_filter(System.id, db, user)
    ).first()
    if not system:
        raise HTTPException(404, "System not found")
    r = RiskRegisterEntry(**payload.model_dump(), organization_id=user.organization_id)
    db.add(r)
    db.flush()
    audit_svc.record(
        db,
        organization_id=user.organization_id,
        actor_id=user.id,
        actor_username=user.username,
        action="CREATE",
        entity_type=ENTITY,
        entity_id=r.id,
        system_id=r.system_id,
        summary=r.title,
    )
    safe_commit(db)
    db.refresh(r)
    return _serialize(r)


@router.patch("/{risk_id}", dependencies=[Depends(require_can("edit:risk"))])
def update_risk(
    risk_id: int,
    payload: RiskUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    r = (
        db.query(RiskRegisterEntry)
        .filter(RiskRegisterEntry.id == risk_id, RiskRegisterEntry.organization_id == user.organization_id, *system_scope_filter(RiskRegisterEntry.system_id, db, user))
        .first()
    )
    if not r:
        raise HTTPException(404, "Risk not found")
    for k, v in payload.model_dump(exclude_unset=True).items():
        setattr(r, k, v)
    audit_svc.record(
        db,
        organization_id=user.organization_id,
        actor_id=user.id,
        actor_username=user.username,
        action="UPDATE",
        entity_type=ENTITY,
        entity_id=r.id,
        system_id=r.system_id,
        summary=r.title,
    )
    safe_commit(db)
    db.refresh(r)
    return _serialize(r)


@router.delete("/{risk_id}", dependencies=[Depends(require_can("edit:risk"))])
def delete_risk(
    risk_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    r = (
        db.query(RiskRegisterEntry)
        .filter(RiskRegisterEntry.id == risk_id, RiskRegisterEntry.organization_id == user.organization_id, *system_scope_filter(RiskRegisterEntry.system_id, db, user))
        .first()
    )
    if not r:
        raise HTTPException(404, "Risk not found")
    audit_svc.record(
        db,
        organization_id=user.organization_id,
        actor_id=user.id,
        actor_username=user.username,
        action="DELETE",
        entity_type=ENTITY,
        entity_id=r.id,
        system_id=r.system_id,
        summary=r.title,
    )
    db.delete(r)
    safe_commit(db)
    return {"deleted": risk_id}


@router.post("/{risk_id}/spawn-finding", dependencies=[Depends(require_can("edit:risk")), Depends(require_can("edit:finding"))])
def spawn_finding_from_risk(
    risk_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    r = (
        db.query(RiskRegisterEntry)
        .filter(RiskRegisterEntry.id == risk_id, RiskRegisterEntry.organization_id == user.organization_id, *system_scope_filter(RiskRegisterEntry.system_id, db, user))
        .first()
    )
    if not r:
        raise HTTPException(404, "Risk not found")
    if r.linked_finding_id:
        existing = db.query(Finding).filter(Finding.id == r.linked_finding_id).first()
        if existing:
            raise HTTPException(409, f"Risk already linked to Finding {r.linked_finding_id}")

    prior_spawns = (
        db.query(AuditEntry)
        .filter(
            AuditEntry.action == "SPAWN_FINDING",
            AuditEntry.entity_type == ENTITY,
            AuditEntry.entity_id == risk_id,
        )
        .count()
    )
    if prior_spawns >= FINDING_SPAWN_LIMIT:
        raise HTTPException(
            422,
            f"Risk {risk_id} has already spawned {prior_spawns} finding(s); "
            f"maximum of {FINDING_SPAWN_LIMIT} is allowed",
        )

    level = _risk_level(r.likelihood, r.impact) or "MODERATE"
    severity = RISK_TO_SEVERITY.get(level, "HIGH")
    due = r.review_date or (date.today() + timedelta(days=90))

    finding = Finding(
        organization_id=user.organization_id,
        system_id=r.system_id,
        framework_id="",
        title=f"Remediate: {r.title}",
        weakness_description=r.description or "",
        control_id=r.control_id or "",
        severity=severity,
        status="OPEN",
        remediation_plan=r.mitigation or "",
        due_date=due,
        scheduled_completion=due,
        owner_name=r.owner_name or "",
        owner_email=r.owner_email or "",
    )
    db.add(finding)
    db.flush()
    r.linked_finding_id = finding.id
    audit_svc.record(
        db,
        organization_id=user.organization_id,
        actor_id=user.id,
        actor_username=user.username,
        action="SPAWN_FINDING",
        entity_type=ENTITY,
        entity_id=r.id,
        system_id=r.system_id,
        summary=f"Spawned Finding {finding.id} from risk: {r.title}",
    )
    audit_svc.record(
        db,
        organization_id=user.organization_id,
        actor_id=user.id,
        actor_username=user.username,
        action="CREATE",
        entity_type="FINDING",
        entity_id=finding.id,
        system_id=finding.system_id,
        summary=f"{finding.title} (from risk {r.id})",
    )
    safe_commit(db)
    db.refresh(finding)
    db.refresh(r)
    return {"risk": _serialize(r), "finding_id": finding.id}

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from models.user import User
from models.calendar_event import CalendarEvent
from schemas import CalendarEventCreate, CalendarEventUpdate
from dependencies import get_current_user, require_min_role
from services import audit as audit_svc
from services.system_scope import system_scope_filter, system_scope_filter_nullable, require_system_allowed  # noqa: F401

router = APIRouter()


_ACTIVE_FINDING = ("OPEN", "IN_PROGRESS", "DELAYED")
DERIVED_PAST_DAYS = 90     # overdue items stay visible for a quarter
DERIVED_FUTURE_DAYS = 365


def _derived_events(db: Session, user: User, framework_id: str | None, system_id: int | None) -> list[dict]:
    """Read-only deadlines computed from the records themselves (R2USER-4): open
    findings' due dates and milestones, evidence expiries, assessment dates and
    ConMon cadence due dates. Same org + system scoping as the records' own
    pages; never stored, so they can't drift from the source."""
    from datetime import date, timedelta
    from models.assessment import Assessment
    from models.evidence import EvidenceArtifact
    from models.finding import Finding
    from services import conmon_cadence

    today = date.today()
    lo, hi = today - timedelta(days=DERIVED_PAST_DAYS), today + timedelta(days=DERIVED_FUTURE_DAYS)
    out: list[dict] = []

    def add(key, event_type, title, when, *, sys_id=None, fw=None, entity=None, entity_id=None, link=None, description=""):
        if when is None or not (lo <= when <= hi):
            return
        out.append({
            "id": None, "derived_key": key, "source": "derived", "event_type": event_type, "title": title,
            "event_date": when.isoformat(), "system_id": sys_id, "framework_id": fw, "description": description,
            "related_entity_type": entity, "related_entity_id": entity_id, "link": link,
        })

    def scoped(q, model):
        q = q.filter(model.organization_id == user.organization_id, *system_scope_filter(model.system_id, db, user))
        if system_id:
            q = q.filter(model.system_id == system_id)
        return q

    fq = scoped(db.query(Finding), Finding).filter(Finding.status.in_(_ACTIVE_FINDING))
    if framework_id:
        fq = fq.filter(Finding.framework_id == framework_id)
    for f in fq.all():
        add(f"finding-due:{f.id}", "FINDING_DUE", f"Finding due: {f.title}", f.due_date or f.scheduled_completion,
            sys_id=f.system_id, fw=f.framework_id, entity="finding", entity_id=f.id, link=f"/findings?focus={f.id}",
            description=f"{f.severity} · {f.status.replace('_', ' ').title()}")
        for i, m in enumerate(f.milestones or []):
            if not isinstance(m, dict) or m.get("complete"):
                continue
            try:
                due = date.fromisoformat(str(m.get("due") or "")[:10])
            except ValueError:
                continue
            add(f"milestone:{f.id}:{i}", "MILESTONE", f"Milestone: {m.get('title') or 'untitled'}", due,
                sys_id=f.system_id, fw=f.framework_id, entity="finding", entity_id=f.id,
                link=f"/findings?focus={f.id}", description=f"Finding: {f.title}")

    eq = scoped(db.query(EvidenceArtifact), EvidenceArtifact)
    for e in eq.all():
        if framework_id and framework_id not in (e.framework_ids or []):
            continue
        add(f"evidence-expiry:{e.id}", "EVIDENCE_EXPIRY", f"Evidence expires: {e.filename}", e.expiration_date,
            sys_id=e.system_id, entity="evidence", entity_id=e.id, link="/evidence")

    aq = scoped(db.query(Assessment), Assessment)
    if framework_id:
        aq = aq.filter(Assessment.framework_id == framework_id)
    for a in aq.all():
        label = (a.assessment_type or "Assessment").replace("_", " ").title()
        common = dict(sys_id=a.system_id, fw=a.framework_id, entity="assessment", entity_id=a.id, link="/assessments")
        if a.completed_at:
            add(f"assessment-done:{a.id}", "ASSESSMENT", f"Assessment completed: {label}", a.completed_at.date(), **common)
        elif a.started_at:
            add(f"assessment-start:{a.id}", "ASSESSMENT", f"Assessment started: {label}", a.started_at.date(), **common)
        elif a.created_at:
            add(f"assessment-planned:{a.id}", "ASSESSMENT", f"Assessment planned: {label}", a.created_at.date(), **common)

    if not system_id:  # cadences are org-level, not per system
        for c in conmon_cadence.list_cadences(db, user.organization_id):
            if not c["next_due"] or (framework_id and c["framework_id"] not in ("", framework_id)):
                continue
            activity = c["activity_type"].replace("_", " ").capitalize()
            add(f"conmon:{c['framework_id']}:{c['activity_type']}", "CONMON_DUE", f"ConMon due: {activity}",
                date.fromisoformat(c["next_due"]), fw=c["framework_id"] or None, link="/conmon",
                description=f"Every {c['interval_days']} days" + (" — overdue" if c["status"] == "OVERDUE" else ""))
    return out


@router.get("")
def list_events(
    framework_id: str | None = None,
    system_id: int | None = None,
    derived: bool = True,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Manual events plus (unless derived=false) read-only deadlines derived
    from findings, milestones, evidence, assessments and ConMon cadences.
    Each item carries source = "manual" | "derived"; derived items have id null
    and a stable derived_key, and can't be edited or deleted here."""
    q = db.query(CalendarEvent).filter(CalendarEvent.organization_id == user.organization_id, *system_scope_filter_nullable(CalendarEvent.system_id, db, user))
    if framework_id:
        q = q.filter(CalendarEvent.framework_id == framework_id)
    if system_id:
        q = q.filter(CalendarEvent.system_id == system_id)
    events = [{**{c.name: getattr(e, c.name) for c in CalendarEvent.__table__.columns}, "source": "manual"}
              for e in q.all()]
    if derived:
        events += _derived_events(db, user, framework_id, system_id)
    return sorted(events, key=lambda e: (str(e["event_date"]), e["source"] != "manual", e["title"]))


@router.post("")
def create_event(req: CalendarEventCreate, user: User = Depends(require_min_role("assessor")), db: Session = Depends(get_db)):
    from services.org_refs import require_org_system
    require_org_system(db, user, req.system_id)
    event = CalendarEvent(organization_id=user.organization_id, **req.model_dump())
    db.add(event)
    db.flush()
    audit_svc.record(db, organization_id=user.organization_id, actor_id=user.id,
                     actor_username=user.username, action="CREATE", entity_type="calendar_event",
                     entity_id=event.id, system_id=event.system_id,
                     summary=f"Created event: {event.title}")
    db.commit()
    db.refresh(event)
    return event


@router.patch("/{event_id}")
def update_event(event_id: int, req: CalendarEventUpdate, user: User = Depends(require_min_role("assessor")), db: Session = Depends(get_db)):
    event = db.query(CalendarEvent).filter(
        CalendarEvent.id == event_id,
        CalendarEvent.organization_id == user.organization_id, *system_scope_filter_nullable(CalendarEvent.system_id, db, user),
    ).first()
    if not event:
        raise HTTPException(404, "Event not found")

    for field, val in req.model_dump(exclude_unset=True).items():
        setattr(event, field, val)

    audit_svc.record(db, organization_id=user.organization_id, actor_id=user.id,
                     actor_username=user.username, action="UPDATE", entity_type="calendar_event",
                     entity_id=event.id, system_id=event.system_id,
                     summary=f"Updated event: {event.title}")
    db.commit()
    db.refresh(event)
    return event


@router.delete("/{event_id}")
def delete_event(event_id: int, user: User = Depends(require_min_role("compliance_manager")), db: Session = Depends(get_db)):
    event = db.query(CalendarEvent).filter(
        CalendarEvent.id == event_id,
        CalendarEvent.organization_id == user.organization_id, *system_scope_filter_nullable(CalendarEvent.system_id, db, user),
    ).first()
    if not event:
        raise HTTPException(404, "Event not found")
    audit_svc.record(db, organization_id=user.organization_id, actor_id=user.id,
                     actor_username=user.username, action="DELETE", entity_type="calendar_event",
                     entity_id=event.id, system_id=event.system_id,
                     summary=f"Deleted event: {event.title}")
    db.delete(event)
    db.commit()
    return {"ok": True}

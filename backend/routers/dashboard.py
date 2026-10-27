from datetime import date, timedelta
from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session
from database import get_db
from models.organization import Organization
from models.user import User
from models.system import System
from models.finding import Finding
from models.evidence import EvidenceArtifact
from models.framework_activation import FrameworkActivation
from models.control_implementation import ControlImplementation
from models.audit import AuditEntry
from models.conmon import ConMonEntry
from models.risk import RiskRegisterEntry
from dependencies import get_current_user
from services.compliance_score import score_system
from services.metrics import counted_framework_clause, finding_counts, open_finding_clause
from services import conmon_cadence as cadence_svc
from services.system_scope import system_scope_filter, system_scope_filter_nullable, require_system_allowed, allowed_system_ids

router = APIRouter()


def _sys(query, model, system_id):
    return query.filter(model.system_id == system_id) if system_id else query


@router.get("/onboarding")
def onboarding_status(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """First-run setup progress, for the Dashboard onboarding checklist."""
    org_id = user.organization_id

    def exists(q) -> bool:
        return db.query(q.exists()).scalar()

    framework = exists(db.query(FrameworkActivation).filter(
        FrameworkActivation.organization_id == org_id, FrameworkActivation.is_active == True))  # noqa: E712
    system = exists(db.query(System).filter(System.organization_id == org_id, *system_scope_filter(System.id, db, user)))
    team = db.query(User).filter(User.organization_id == org_id).count() > 1
    implementation = exists(
        db.query(ControlImplementation).join(System, ControlImplementation.system_id == System.id)
        .filter(System.organization_id == org_id, *system_scope_filter(System.id, db, user)))
    evidence = exists(db.query(EvidenceArtifact).filter(EvidenceArtifact.organization_id == org_id, *system_scope_filter(EvidenceArtifact.system_id, db, user)))

    from models.conmon import ConMonEntry
    conmon = exists(db.query(ConMonEntry).filter(ConMonEntry.organization_id == org_id))

    steps = [
        {"key": "framework", "label": "Activate a compliance framework", "to": "/marketplace", "done": framework},
        {"key": "system", "label": "Register your first system", "to": "/systems", "done": system},
        {"key": "team", "label": "Add a team member", "to": "/users", "done": team},
        {"key": "implementation", "label": "Record a control implementation", "to": "/controls", "done": implementation},
        {"key": "evidence", "label": "Upload your first evidence", "to": "/evidence", "done": evidence},
        # R2USER-18: cadences start counting once a system exists — say where to log them.
        {"key": "conmon", "label": "Log a continuous-monitoring activity (scans, reviews)", "to": "/conmon", "done": conmon},
    ]
    return {"steps": steps, "complete": all(s["done"] for s in steps),
            "done_count": sum(s["done"] for s in steps), "total": len(steps)}


@router.get("/snapshot")
def dashboard_snapshot(system_id: int | None = None, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    org_id = user.organization_id

    total_systems = db.query(System).filter(System.organization_id == org_id, *system_scope_filter(System.id, db, user)).count()
    counts = finding_counts(_sys(db.query(Finding).filter(
        Finding.organization_id == org_id, *system_scope_filter(Finding.system_id, db, user),
        counted_framework_clause(org_id),
    ), Finding, system_id))
    open_findings = counts["open"]
    critical_findings = counts["critical"]
    overdue_findings = counts["overdue"]

    expiring_evidence = _sys(db.query(EvidenceArtifact).filter(
        EvidenceArtifact.organization_id == org_id, *system_scope_filter(EvidenceArtifact.system_id, db, user),
        EvidenceArtifact.expiration_date <= date.today() + timedelta(days=30),
        EvidenceArtifact.expiration_date >= date.today(),
    ), EvidenceArtifact, system_id).count()
    expired_evidence = _sys(db.query(EvidenceArtifact).filter(
        EvidenceArtifact.organization_id == org_id, *system_scope_filter(EvidenceArtifact.system_id, db, user),
        EvidenceArtifact.expiration_date < date.today(),
    ), EvidenceArtifact, system_id).count()

    active_frameworks = db.query(FrameworkActivation).filter(
        FrameworkActivation.organization_id == org_id,
        FrameworkActivation.is_active == True,
    ).count()

    total_evidence = _sys(db.query(EvidenceArtifact).filter(
        EvidenceArtifact.organization_id == org_id, *system_scope_filter(EvidenceArtifact.system_id, db, user),
    ), EvidenceArtifact, system_id).count()
    fresh_evidence = total_evidence - expiring_evidence - expired_evidence

    open_risks = _sys(db.query(RiskRegisterEntry).filter(
        RiskRegisterEntry.organization_id == org_id, *system_scope_filter(RiskRegisterEntry.system_id, db, user),
        RiskRegisterEntry.status.in_(["OPEN", "MITIGATING"]),
    ), RiskRegisterEntry, system_id).count()

    # Cadence is org-wide (not per-system); only computed for the all-systems view
    cadence_overdue = 0 if system_id else cadence_svc.overdue_count(db, org_id)

    org = db.query(Organization).filter(Organization.id == org_id).first()
    return {
        "organization_name": org.name if org else "",
        "total_systems": total_systems,
        "open_findings": open_findings,
        "critical_findings": critical_findings,
        "overdue_findings": overdue_findings,
        "expiring_evidence": expiring_evidence,
        "expired_evidence": expired_evidence,
        "fresh_evidence": fresh_evidence,
        "total_evidence": total_evidence,
        "active_frameworks": active_frameworks,
        "open_risks": open_risks,
        "cadence_overdue": cadence_overdue,
    }


@router.get("/finding-aging")
def finding_aging(system_id: int | None = None, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    org_id = user.organization_id
    today = date.today()
    open_q = _sys(db.query(Finding).filter(
        Finding.organization_id == org_id, *system_scope_filter(Finding.system_id, db, user),
        open_finding_clause(), counted_framework_clause(org_id),
    ), Finding, system_id)
    overdue = open_q.filter(Finding.due_date < today).count()
    due_7 = open_q.filter(Finding.due_date >= today, Finding.due_date <= today + timedelta(days=7)).count()
    due_30 = open_q.filter(Finding.due_date > today + timedelta(days=7), Finding.due_date <= today + timedelta(days=30)).count()
    on_track = open_q.filter((Finding.due_date > today + timedelta(days=30)) | (Finding.due_date == None)).count()
    return {"overdue": overdue, "due_7": due_7, "due_30": due_30, "on_track": on_track}


@router.get("/finding-severity")
def finding_severity_breakdown(system_id: int | None = None, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    org_id = user.organization_id
    q = db.query(Finding.severity, func.count(Finding.id)).filter(
        Finding.organization_id == org_id, *system_scope_filter(Finding.system_id, db, user),
        open_finding_clause(), counted_framework_clause(org_id),
    )
    if system_id:
        q = q.filter(Finding.system_id == system_id)
    rows = q.group_by(Finding.severity).all()
    return {sev: cnt for sev, cnt in rows}


@router.get("/evidence-freshness")
def evidence_freshness(system_id: int | None = None, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    org_id = user.organization_id
    today = date.today()
    total = _sys(db.query(EvidenceArtifact).filter(EvidenceArtifact.organization_id == org_id, *system_scope_filter(EvidenceArtifact.system_id, db, user)), EvidenceArtifact, system_id).count()
    expired = _sys(db.query(EvidenceArtifact).filter(
        EvidenceArtifact.organization_id == org_id, *system_scope_filter(EvidenceArtifact.system_id, db, user),
        EvidenceArtifact.expiration_date < today,
    ), EvidenceArtifact, system_id).count()
    expiring = _sys(db.query(EvidenceArtifact).filter(
        EvidenceArtifact.organization_id == org_id, *system_scope_filter(EvidenceArtifact.system_id, db, user),
        EvidenceArtifact.expiration_date >= today,
        EvidenceArtifact.expiration_date <= today + timedelta(days=30),
    ), EvidenceArtifact, system_id).count()
    fresh = total - expired - expiring
    return {"fresh": fresh, "expiring": expiring, "expired": expired, "total": total}


@router.get("/activity")
def recent_activity(system_id: int | None = None, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    org_id = user.organization_id
    from services.system_scope import audit_scope_filter
    q = db.query(AuditEntry).filter(AuditEntry.organization_id == org_id, *audit_scope_filter(db, user))
    if system_id:
        q = q.filter(AuditEntry.system_id == system_id)
    entries = q.order_by(AuditEntry.timestamp.desc()).limit(20).all()
    return [
        {
            "id": e.id,
            "action": e.action,
            "entity_type": e.entity_type,
            "entity_id": e.entity_id,
            "actor": e.actor_username,
            "summary": e.summary,
            "created_at": e.timestamp.isoformat() if e.timestamp else None,
        }
        for e in entries
    ]


@router.get("/compliance")
def compliance_overview(system_id: int | None = None, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    org_id = user.organization_id

    activations = db.query(FrameworkActivation).filter(
        FrameworkActivation.organization_id == org_id,
        FrameworkActivation.is_active == True,
    ).all()

    sys_q = db.query(System).filter(System.organization_id == org_id, *system_scope_filter(System.id, db, user))
    if system_id:
        sys_q = sys_q.filter(System.id == system_id)
    systems = sys_q.all()

    scores = []
    for activation in activations:
        for system in systems:
            s = score_system(system.id, activation.framework_id, db)
            scores.append({
                "system_id": system.id,
                "system_name": system.name,
                "framework_id": activation.framework_id,
                "score_percentage": s.score_percentage,
                "total_controls": s.total_controls,
                "implemented": s.implemented,
                "open_findings": s.open_findings,
                "critical_findings": s.critical_findings,
            })

    return scores


@router.get("/history")
def compliance_history(
    system_id: int | None = None,
    framework_id: str | None = None,
    days: int = 180,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Per-day compliance trend: average score + finding counts, from the daily
    snapshots. Optional system/framework filters narrow the aggregate.
    Today's point is always computed live (the same computation the snapshot
    job stores), so the trend's last point matches the live Dashboard and
    Portfolio instead of lagging up to a day behind."""
    from models.compliance_snapshot import ComplianceSnapshot
    from services.history import live_pair_scores, live_trend_point

    days = max(1, min(days, 730))
    today = date.today()
    since = today - timedelta(days=days)
    q = db.query(
        ComplianceSnapshot.snapshot_date,
        func.avg(ComplianceSnapshot.score_percentage),
        func.sum(ComplianceSnapshot.open_findings),
        func.sum(ComplianceSnapshot.overdue_findings),
        func.sum(ComplianceSnapshot.critical_findings),
    ).filter(
        ComplianceSnapshot.organization_id == user.organization_id, *system_scope_filter(ComplianceSnapshot.system_id, db, user),
        ComplianceSnapshot.snapshot_date >= since,
        ComplianceSnapshot.snapshot_date < today,
    )
    if system_id:
        q = q.filter(ComplianceSnapshot.system_id == system_id)
    if framework_id:
        q = q.filter(ComplianceSnapshot.framework_id == framework_id)
    rows = q.group_by(ComplianceSnapshot.snapshot_date).order_by(ComplianceSnapshot.snapshot_date).all()

    scope = allowed_system_ids(db, user)
    if system_id:
        scope = {system_id} if scope is None or system_id in scope else set()
    live = live_pair_scores(db, user.organization_id, system_ids=scope, framework_id=framework_id, on=today)
    today_point = [live_trend_point(live, today)] if live else []
    return [
        {
            "date": d.isoformat(),
            "avg_score": round(float(score or 0), 1),
            "open_findings": int(open_f or 0),
            "overdue_findings": int(over_f or 0),
            "critical_findings": int(crit_f or 0),
        }
        for d, score, open_f, over_f, crit_f in rows
    ] + today_point


@router.get("/my-work")
def my_work(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Everything assigned to the current user that still needs action:
    open findings, unimplemented controls, and evidence nearing expiry."""
    from services.aging import TERMINAL_STATUSES

    findings = db.query(Finding).filter(
        Finding.organization_id == user.organization_id, *system_scope_filter(Finding.system_id, db, user),
        Finding.owner_id == user.id,
        ~Finding.status.in_(TERMINAL_STATUSES),
    ).all()

    ACTIONABLE_IMPL = ("NOT_ASSESSED", "PLANNED", "PARTIALLY", "NOT_IMPLEMENTED")
    controls = (
        db.query(ControlImplementation, System.name, System.acronym)
        .join(System, ControlImplementation.system_id == System.id)
        .filter(
            System.organization_id == user.organization_id, *system_scope_filter(System.id, db, user),
            ControlImplementation.owner_id == user.id,
            ControlImplementation.implementation_status.in_(ACTIONABLE_IMPL),
        )
        .all()
    )

    horizon = date.today() + timedelta(days=14)
    evidence = db.query(EvidenceArtifact).filter(
        EvidenceArtifact.organization_id == user.organization_id, *system_scope_filter(EvidenceArtifact.system_id, db, user),
        EvidenceArtifact.owner_id == user.id,
        EvidenceArtifact.expiration_date.isnot(None),
        EvidenceArtifact.expiration_date <= horizon,
    ).all()

    today = date.today()
    return {
        "findings": [
            {
                "id": f.id, "title": f.title, "severity": f.severity,
                "status": f.status,
                "due_date": f.due_date.isoformat() if f.due_date else None,
                "overdue": bool(f.due_date and f.due_date < today),
            }
            for f in findings
        ],
        "controls": [
            {
                "system_id": impl.system_id, "system": acronym or name,
                "framework_id": impl.framework_id, "control_id": impl.control_id,
                "implementation_status": impl.implementation_status,
            }
            for impl, name, acronym in controls
        ],
        "evidence": [
            {
                "id": e.id, "filename": e.filename,
                "expiration_date": e.expiration_date.isoformat(),
                "days": (e.expiration_date - today).days,
                "expired": e.expiration_date < today,
            }
            for e in evidence
        ],
    }

import csv
import io
from datetime import date
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from sqlalchemy.orm import Session
from database import get_db
from models.user import User
from models.assessment import Assessment
from models.system import System
from models.finding import Finding
from models.evidence import EvidenceArtifact
from models.conmon import ConMonEntry
from models.risk import RiskRegisterEntry
from models.framework_activation import FrameworkActivation
from dependencies import get_current_user
from routers.risks import _risk_level
from services.compliance_score import score_system
from services.csv_safety import safe_csv_cell
from services.system_scope import system_scope_filter, system_scope_filter_nullable, require_system_allowed

router = APIRouter()


_safe_csv = safe_csv_cell  # shared with every other CSV export (services/csv_safety.py)


def _csv_response(rows: list[dict], filename: str) -> StreamingResponse:
    if not rows:
        return StreamingResponse(
            iter(["No data\n"]),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    sanitized = [{k: _safe_csv(v) for k, v in r.items()} for r in rows]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(sanitized[0].keys()))
    writer.writeheader()
    writer.writerows(sanitized)
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/findings")
def export_findings(
    system_id: int | None = None,
    framework_id: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(Finding).filter(Finding.organization_id == user.organization_id, *system_scope_filter(Finding.system_id, db, user))
    if system_id:
        q = q.filter(Finding.system_id == system_id)
    if framework_id:
        q = q.filter(Finding.framework_id == framework_id)
    rows = []
    for f in q.order_by(Finding.created_at.desc()).all():
        rows.append({
            "id": f.id, "title": f.title, "framework_id": f.framework_id,
            "control_id": f.control_id or "", "severity": f.severity,
            "status": f.status, "description": (f.description or "")[:500],
            "owner_name": f.owner_name or "", "owner_email": f.owner_email or "",
            "due_date": str(f.due_date) if f.due_date else "",
            "scheduled_completion": str(f.scheduled_completion) if f.scheduled_completion else "",
            "created_at": f.created_at.isoformat() if f.created_at else "",
        })
    return _csv_response(rows, f"findings-{date.today()}.csv")


@router.get("/evidence")
def export_evidence(
    system_id: int | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(EvidenceArtifact).filter(EvidenceArtifact.organization_id == user.organization_id, *system_scope_filter(EvidenceArtifact.system_id, db, user))
    if system_id:
        q = q.filter(EvidenceArtifact.system_id == system_id)
    rows = []
    for e in q.order_by(EvidenceArtifact.created_at.desc()).all():
        rows.append({
            "id": e.id, "filename": e.filename, "description": (e.description or "")[:300],
            "artifact_type": e.artifact_type or "", "system_id": e.system_id,
            "date_collected": str(e.date_collected) if e.date_collected else "",
            "expiration_date": str(e.expiration_date) if e.expiration_date else "",
            "control_ids": ",".join(e.control_ids) if e.control_ids else "",
            "framework_ids": ",".join(e.framework_ids) if e.framework_ids else "",
        })
    return _csv_response(rows, f"evidence-{date.today()}.csv")


@router.get("/risks")
def export_risks(
    system_id: int | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(RiskRegisterEntry).filter(RiskRegisterEntry.organization_id == user.organization_id, *system_scope_filter(RiskRegisterEntry.system_id, db, user))
    if system_id:
        q = q.filter(RiskRegisterEntry.system_id == system_id)
    rows = []
    for r in q.order_by(RiskRegisterEntry.created_at.desc()).all():
        rows.append({
            "id": r.id, "title": r.title, "category": r.category or "",
            "likelihood": r.likelihood or "", "impact": r.impact or "",
            "risk_level": _risk_level(r.likelihood, r.impact) or "", "residual_risk": r.residual_risk or "",
            "status": r.status, "treatment": r.treatment or "",
            "mitigation": (r.mitigation or "")[:300],
            "owner_name": r.owner_name or "", "review_date": str(r.review_date) if r.review_date else "",
        })
    return _csv_response(rows, f"risk-register-{date.today()}.csv")


@router.get("/compliance-summary")
def compliance_summary(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org_id = user.organization_id
    activations = db.query(FrameworkActivation).filter(
        FrameworkActivation.organization_id == org_id,
        FrameworkActivation.is_active == True,
    ).all()
    systems = db.query(System).filter(
        System.organization_id == org_id, *system_scope_filter(System.id, db, user),
    ).all()

    rows = []
    for act in activations:
        for sys in systems:
            s = score_system(sys.id, act.framework_id, db)
            rows.append({
                "system": sys.name, "system_acronym": sys.acronym,
                "framework": act.framework_id,
                "score_pct": s.score_percentage, "total_controls": s.total_controls,
                "implemented": s.implemented, "open_findings": s.open_findings,
                "critical_findings": s.critical_findings,
            })
    return _csv_response(rows, f"compliance-summary-{date.today()}.csv")


@router.get("/conmon")
def export_conmon(
    system_id: int | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(ConMonEntry).filter(ConMonEntry.organization_id == user.organization_id, *system_scope_filter(ConMonEntry.system_id, db, user))
    if system_id:
        q = q.filter(ConMonEntry.system_id == system_id)
    rows = []
    for c in q.order_by(ConMonEntry.entry_date.desc()).all():
        rows.append({
            "id": c.id, "system_id": c.system_id, "framework_id": c.framework_id or "",
            "entry_date": str(c.entry_date) if c.entry_date else "",
            "activity_type": c.activity_type or "",
            "description": (c.description or "")[:300],
            "performed_by": c.performed_by or "",
            "findings": (c.findings or "")[:200],
            "follow_up_required": c.follow_up_required,
        })
    return _csv_response(rows, f"conmon-{date.today()}.csv")


@router.get("/audit-binder")
def audit_binder(
    system_id: int,
    framework_id: str,
    style: str = "standard",
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """One-click evidence-backed audit package (ZIP: print-ready binder.html +
    archived evidence files) for one system × framework."""
    from fastapi import HTTPException

    from services import audit as audit_svc
    from services.audit_binder import build_binder
    from routers.frameworks import loader

    system = db.query(System).filter(
        System.id == system_id, System.organization_id == user.organization_id, *system_scope_filter(System.id, db, user)
    ).first()
    if not system:
        raise HTTPException(404, "System not found")
    active = db.query(FrameworkActivation).filter(
        FrameworkActivation.organization_id == user.organization_id,
        FrameworkActivation.framework_id == framework_id,
        FrameworkActivation.is_active == True,  # noqa: E712
    ).first()
    if not active:
        raise HTTPException(404, "Framework is not active for your organization")
    meta = loader.get_metadata(framework_id)
    fw_name = meta.name if meta else framework_id

    if style not in ("standard", "rsaw"):
        raise HTTPException(422, "style must be 'standard' or 'rsaw'")
    payload = build_binder(
        db, user.organization_id, system_id, framework_id, fw_name,
        generated_by=user.display_name or user.username, style=style,
    )
    audit_svc.record(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, action="EXPORT", entity_type="audit_binder",
        system_id=system_id,
        summary=f"Audit Binder exported: {system.acronym or system.name} × {framework_id}",
    )
    db.commit()
    prefix = "rsaw" if style == "rsaw" else "audit-binder"
    fname = f"{prefix}_{(system.acronym or 'system').lower()}_{framework_id}_{date.today().isoformat()}.zip"
    return StreamingResponse(
        io.BytesIO(payload),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# NOTE: parameterized route — MUST stay registered AFTER every fixed-path route
# in this router (FastAPI matches in registration order; fixed paths first —
# this repo's route-shadowing gotcha). Any future fixed /assessment/* path must
# be added ABOVE this handler.
@router.get("/assessment/{assessment_id}", response_class=HTMLResponse)
def assessment_report(
    assessment_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Deliverable report for one assessment: self-contained print-to-PDF HTML
    (cover, per-control results with narratives + linked evidence, findings
    from the assessment window, sign-off block)."""
    from services import audit as audit_svc
    from services.assessment_report import build_assessment_report
    from routers.frameworks import loader

    assessment = db.query(Assessment).filter(
        Assessment.id == assessment_id,
        Assessment.organization_id == user.organization_id,
        *system_scope_filter(Assessment.system_id, db, user),
    ).first()
    if not assessment:
        raise HTTPException(404, "Assessment not found")

    system = db.query(System).filter(
        System.id == assessment.system_id, System.organization_id == user.organization_id,
    ).first()
    if not system:
        raise HTTPException(404, "Assessment not found")
    # An assessment recorded against another company's private custom
    # framework (possible before R2SEC-2) must not render that catalog.
    from routers.frameworks import hidden_framework_ids
    if assessment.framework_id in hidden_framework_ids(user):
        raise HTTPException(404, "Assessment not found")
    meta = loader.get_metadata(assessment.framework_id)
    fw_name = meta.name if meta else assessment.framework_id

    html = build_assessment_report(
        db, assessment, fw_name,
        generated_by=user.display_name or user.username,
    )
    audit_svc.record(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, action="EXPORT",
        entity_type="assessment_report", entity_id=assessment.id,
        system_id=assessment.system_id,
        summary=f"Assessment report generated: {assessment.assessment_type} — "
                f"{(system.acronym or system.name) if system else '?'} × {assessment.framework_id}",
    )
    db.commit()
    fname = f"assessment-report_{assessment.id}_{date.today().isoformat()}.html"
    return HTMLResponse(
        html,
        headers={"Content-Disposition": f'inline; filename="{fname}"'},
    )

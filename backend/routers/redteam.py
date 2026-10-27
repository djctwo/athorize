from datetime import date, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from dependencies import get_current_user, require_can, require_min_role
from models import System, Finding, FrameworkActivation
from models.organization import Organization
from models.redteam import RedTeamReport
from models.user import User
from services import audit as audit_svc
from services.redteam_analyzer import analyze_system
from services.risk_quantification import benchmark_info, get_industries, summarize_reports
from services.system_scope import system_scope_filter

router = APIRouter()


@router.get("")
def list_reports(
    system_id: int | None = None,
    framework_id: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(RedTeamReport).filter(
        RedTeamReport.organization_id == user.organization_id,
        *system_scope_filter(RedTeamReport.system_id, db, user),
    )
    if system_id is not None:
        q = q.filter(RedTeamReport.system_id == system_id)
    if framework_id is not None:
        q = q.filter(RedTeamReport.framework_id == framework_id)
    return q.order_by(RedTeamReport.created_at.desc()).all()


# ---------------------------------------------------------------------------
# Risk context (org-level settings for cost estimation)
# Fixed-path routes must register before /{report_id} or FastAPI matches the
# parameterized route first and 422s on the non-integer segment.
# ---------------------------------------------------------------------------

class RiskContextUpdate(BaseModel):
    industry: str | None = None
    annual_revenue: int | None = None
    largest_contract_value: int | None = None
    record_count: int | None = None
    employee_count: int | None = None


@router.get("/risk-context")
def get_risk_context(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org = db.query(Organization).filter(Organization.id == user.organization_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")
    ctx = (org.settings or {}).get("risk_context", {})
    return {"risk_context": ctx, "industries": get_industries(), "methodology": benchmark_info()}


@router.put("/risk-context")
def update_risk_context(
    body: RiskContextUpdate,
    user: User = Depends(require_min_role("compliance_manager")),
    db: Session = Depends(get_db),
):
    org = db.query(Organization).filter(Organization.id == user.organization_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")

    settings = dict(org.settings or {})
    settings["risk_context"] = {k: v for k, v in body.model_dump().items() if v is not None}
    org.settings = settings

    audit_svc.record(
        db,
        organization_id=user.organization_id,
        actor_id=user.id,
        actor_username=user.username,
        action="UPDATE",
        entity_type="organization",
        entity_id=org.id,
        summary="Updated risk context for cost estimation",
    )
    db.commit()
    return {"risk_context": settings["risk_context"]}


@router.get("/exposure-summary")
def exposure_summary(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Organization-level estimated exposure (Executive Briefing): the latest
    report per system x framework the caller can see, combined with the same
    probable-loss model and revenue cap as a single report. Estimates only."""
    rows = db.query(RedTeamReport).filter(
        RedTeamReport.organization_id == user.organization_id,
        *system_scope_filter(RedTeamReport.system_id, db, user),
    ).order_by(RedTeamReport.created_at.desc(), RedTeamReport.id.desc()).all()
    latest: dict[tuple[int, str], RedTeamReport] = {}
    for r in rows:
        latest.setdefault((r.system_id, r.framework_id), r)
    org = db.query(Organization).filter(Organization.id == user.organization_id).first()
    ctx = (org.settings or {}).get("risk_context", {}) if org else {}
    summary = summarize_reports([
        {"total_exposure_low": r.total_exposure_low, "total_exposure_high": r.total_exposure_high,
         "top5_reduction_low": r.top5_reduction_low, "top5_reduction_high": r.top5_reduction_high,
         "quick_win_count": r.quick_win_count}
        for r in latest.values()
    ], ctx)
    summary["report_ids"] = sorted(r.id for r in latest.values())
    return summary


@router.get("/{report_id}")
def get_report(
    report_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    report = db.query(RedTeamReport).filter(
        RedTeamReport.id == report_id,
        RedTeamReport.organization_id == user.organization_id,
        *system_scope_filter(RedTeamReport.system_id, db, user),
    ).first()
    if not report:
        raise HTTPException(404, "Report not found")
    return report


@router.post("/analyze/{system_id}/{framework_id}")
def run_analysis(
    system_id: int,
    framework_id: str,
    user: User = Depends(require_min_role("assessor")),
    db: Session = Depends(get_db),
):
    system = db.query(System).filter(
        System.id == system_id,
        System.organization_id == user.organization_id,
        *system_scope_filter(System.id, db, user),
    ).first()
    if not system:
        raise HTTPException(404, "System not found")

    activation = db.query(FrameworkActivation).filter(
        FrameworkActivation.organization_id == user.organization_id,
        FrameworkActivation.framework_id == framework_id,
        FrameworkActivation.is_active == True,
    ).first()
    if not activation:
        raise HTTPException(400, f"Framework {framework_id} is not activated")

    result = analyze_system(
        db, system_id, framework_id,
        organization_id=user.organization_id,
        run_by=user.display_name or user.username,
    )

    report = RedTeamReport(
        organization_id=user.organization_id,
        system_id=system_id,
        framework_id=framework_id,
        run_by=result["run_by"],
        summary=result["summary"],
        total_findings=result["total_findings"],
        critical_count=result["critical_count"],
        high_count=result["high_count"],
        medium_count=result["medium_count"],
        low_count=result["low_count"],
        total_exposure_low=result.get("total_exposure_low", 0),
        total_exposure_high=result.get("total_exposure_high", 0),
        top5_reduction_low=result.get("top5_reduction_low", 0),
        top5_reduction_high=result.get("top5_reduction_high", 0),
        quick_win_count=result.get("quick_win_count", 0),
        has_org_context=1 if result.get("has_org_context") else 0,
        findings=result["findings"],
        attack_chains=result["attack_chains"],
    )
    db.add(report)
    db.flush()

    audit_svc.record(
        db,
        organization_id=user.organization_id,
        actor_id=user.id,
        actor_username=user.username,
        action="RUN",
        entity_type="redteam",
        entity_id=report.id,
        system_id=system_id,
        summary=f"Red team analysis ({framework_id}): {result['total_findings']} findings",
    )
    db.commit()
    db.refresh(report)
    return report


@router.post("/{report_id}/findings/{finding_id}/create-finding")
def create_finding_from_report(
    report_id: int,
    finding_id: str,
    # Creates a Finding, so it takes the same permission as POST /api/findings
    # (E2E-14 / KNOWN-5): assessors may RUN analyses but not file findings.
    user: User = Depends(require_can("edit:finding")),
    db: Session = Depends(get_db),
):
    report = db.query(RedTeamReport).filter(
        RedTeamReport.id == report_id,
        RedTeamReport.organization_id == user.organization_id,
        *system_scope_filter(RedTeamReport.system_id, db, user),
    ).first()
    if not report:
        raise HTTPException(404, "Report not found")

    rt_finding = None
    for f in (report.findings or []):
        if f.get("id") == finding_id:
            rt_finding = f
            break
    if not rt_finding:
        raise HTTPException(404, f"Finding {finding_id} not found in report")

    lang = rt_finding.get("finding_language", {})
    control_ids = rt_finding.get("control_ids", [])

    finding = Finding(
        organization_id=user.organization_id,
        system_id=report.system_id,
        framework_id=report.framework_id,
        control_id=control_ids[0] if control_ids else "",
        title=lang.get("title", rt_finding["title"]),
        description=lang.get("description", rt_finding["description"]),
        severity=lang.get("severity", "MEDIUM"),
        status="OPEN",
        remediation_plan=lang.get("remediation_plan", ""),
        due_date=date.today() + timedelta(days=lang.get("scheduled_completion_days", 90)),
        owner_id=user.id,
    )
    db.add(finding)
    db.flush()

    audit_svc.record(
        db,
        organization_id=user.organization_id,
        actor_id=user.id,
        actor_username=user.username,
        action="CREATE",
        entity_type="finding",
        entity_id=finding.id,
        system_id=report.system_id,
        summary=f"Finding from red team {finding_id}: {finding.title}",
    )
    db.commit()
    db.refresh(finding)
    return finding


@router.delete("/{report_id}")
def delete_report(
    report_id: int,
    user: User = Depends(require_min_role("compliance_manager")),
    db: Session = Depends(get_db),
):
    report = db.query(RedTeamReport).filter(
        RedTeamReport.id == report_id,
        RedTeamReport.organization_id == user.organization_id,
        *system_scope_filter(RedTeamReport.system_id, db, user),
    ).first()
    if not report:
        raise HTTPException(404, "Report not found")

    audit_svc.record(
        db,
        organization_id=user.organization_id,
        actor_id=user.id,
        actor_username=user.username,
        action="DELETE",
        entity_type="redteam",
        entity_id=report.id,
        system_id=report.system_id,
        summary=f"Deleted red team report #{report.id}",
    )
    db.delete(report)
    db.commit()
    return {"ok": True}

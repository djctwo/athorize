"""Assessment Report — the deliverable a customer hands out after an assessment.

Builds a single self-contained, print-to-PDF-ready HTML document for ONE
assessment: cover (org / system / framework / assessment type / status /
dates), per-control results in the assessment's scope (implementation status,
narrative, linked evidence names), findings open or created in the assessment
window, and a sign-off block.

Follows the Audit Binder pattern (services/audit_binder.py): inline CSS, zero
new dependencies, computed from the same org-scoped queries the app itself
uses — the report is a rendering of the system of record, not a parallel data
path.
"""
from __future__ import annotations

from datetime import date, datetime, timezone

from sqlalchemy.orm import Session

from services.natural_sort import control_sort_key

from models import (
    Assessment, Control, ControlImplementation, EvidenceArtifact, Finding,
    Organization, System, User,
)
from services.aging import TERMINAL_STATUSES
from services.audit_binder import STATUS_COLOR, STATUS_LABEL, _CSS, _esc
from services.compliance_score import score_system

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

_EXTRA_CSS = """
.signoff td{height:42px}
.badge{font-weight:bold}
"""


def _naive(dt: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes; strip tzinfo so comparisons never mix."""
    if dt is not None and dt.tzinfo is not None:
        return dt.replace(tzinfo=None)
    return dt


def _fmt_dt(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%d %H:%M UTC") if dt else "—"


def assessment_window(assessment: Assessment) -> tuple[datetime | None, datetime]:
    """The period the assessment covers: start = started_at (fallback
    created_at), end = completed_at (fallback now, i.e. still running)."""
    start = _naive(assessment.started_at or assessment.created_at)
    end = _naive(assessment.completed_at) or _naive(datetime.now(timezone.utc))
    return start, end


def findings_in_window(db: Session, assessment: Assessment) -> list[Finding]:
    """Findings for the assessment's system × framework that are relevant to
    the assessment window: created inside the window (any status), or created
    before the window's end and still not in a terminal status."""
    start, end = assessment_window(assessment)
    rows = db.query(Finding).filter(
        Finding.organization_id == assessment.organization_id,
        Finding.system_id == assessment.system_id,
        Finding.framework_id == assessment.framework_id,
    ).all()
    out = []
    for f in rows:
        created = _naive(f.created_at)
        if created is None:
            in_window = True  # legacy row without a timestamp: include if open
            created_in_window = False
        else:
            created_in_window = (start is None or created >= start) and created <= end
            in_window = created <= end
        is_open = (f.status or "").upper() not in TERMINAL_STATUSES
        if created_in_window or (in_window and is_open):
            out.append(f)
    out.sort(key=lambda f: (SEVERITY_ORDER.get((f.severity or "").upper(), 9),
                            (f.status or ""), f.id or 0))
    return out


def build_assessment_report(
    db: Session,
    assessment: Assessment,
    framework_name: str,
    generated_by: str,
) -> str:
    org = db.query(Organization).filter(
        Organization.id == assessment.organization_id).first()
    # Defense in depth: never render a system outside the assessment's org,
    # even for rows written before create-time validation existed.
    system = db.query(System).filter(
        System.id == assessment.system_id,
        System.organization_id == assessment.organization_id,
    ).first()
    if system is None:
        raise LookupError("assessment system not found in its organization")
    users = {u.id: (u.display_name or u.username) for u in db.query(User).filter(
        User.organization_id == assessment.organization_id).all()}
    assessor_name = users.get(assessment.assessor_id, "") if assessment.assessor_id else ""

    controls = sorted(db.query(Control).filter(
        Control.framework_id == assessment.framework_id
    ).all(), key=lambda c: control_sort_key(c.control_id))
    impls = {
        i.control_id: i
        for i in db.query(ControlImplementation).filter(
            ControlImplementation.system_id == assessment.system_id,
            ControlImplementation.framework_id == assessment.framework_id,
        ).all()
    }
    control_ids = {c.control_id for c in controls}
    evidence = [
        e for e in db.query(EvidenceArtifact).filter(
            EvidenceArtifact.organization_id == assessment.organization_id,
            EvidenceArtifact.system_id == assessment.system_id,
        ).order_by(EvidenceArtifact.filename).all()
        if assessment.framework_id in (e.framework_ids or [])
        or control_ids & set(e.control_ids or [])
    ]
    findings = findings_in_window(db, assessment)
    score = score_system(assessment.system_id, assessment.framework_id, db)
    assessed = sum(1 for i in impls.values()
                   if (i.implementation_status or "NOT_ASSESSED") != "NOT_ASSESSED")

    start, end = assessment_window(assessment)
    today = date.today()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    h: list[str] = [
        f"<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>Assessment Report — {_esc(system.name)} × {_esc(framework_name)}</title>"
        f"<style>{_CSS}{_EXTRA_CSS}</style></head><body>"
    ]

    # ---- Cover ----
    h.append(
        f"<div class='cover'><div class='brand'>Athorize · Compliance Operations</div>"
        f"<h1>Assessment Report</h1>"
        f"<p class='meta'><b>{_esc(org.name)}</b><br>"
        f"System: <b>{_esc(system.name)} ({_esc(system.acronym)})</b><br>"
        f"Framework: <b>{_esc(framework_name)}</b><br>"
        f"Assessment: <b>{_esc(assessment.assessment_type)}</b> · Status: <b>{_esc(assessment.status)}</b><br>"
        f"Started {_esc(_fmt_dt(_naive(assessment.started_at)))} · "
        f"Completed {_esc(_fmt_dt(_naive(assessment.completed_at)))}<br>"
        f"Generated {now} by {_esc(generated_by)}</p>"
        f"<p><span class='kpi'><b>{score.score_percentage:.0f}%</b>compliance</span>"
        f"<span class='kpi'><b>{assessed}/{len(controls)}</b>controls assessed</span>"
        f"<span class='kpi'><b>{len(findings)}</b>findings in window</span>"
        f"<span class='kpi'><b>{len(evidence)}</b>evidence artifacts</span></p></div>"
    )

    # ---- 1. Assessment summary ----
    h.append("<h2>1. Assessment Summary</h2><table>")
    for label, val in (
        ("Organization", org.name),
        ("System", f"{system.name} ({system.acronym})" if system.acronym else system.name),
        ("Framework", framework_name),
        ("Assessment type / template", assessment.assessment_type),
        ("Status", assessment.status),
        ("Assessor", assessor_name),
        ("Created", _fmt_dt(_naive(assessment.created_at))),
        ("Started", _fmt_dt(_naive(assessment.started_at))),
        ("Completed", _fmt_dt(_naive(assessment.completed_at))),
        ("Notes", assessment.notes),
    ):
        h.append(f"<tr><th style='width:210px'>{_esc(label)}</th><td>{_esc(val)}</td></tr>")
    h.append("</table>")

    # ---- 2. Control results ----
    h.append(f"<h2>2. Control Results ({len(controls)} controls in scope)</h2>")
    if controls:
        h.append("<table><tr><th style='width:90px'>Control</th><th>Title / Narrative</th>"
                 "<th style='width:130px'>Status</th><th style='width:110px'>Result</th>"
                 "<th>Linked evidence</th></tr>")
        for c in controls:
            i = impls.get(c.control_id)
            status = i.implementation_status if i else "NOT_ASSESSED"
            result = i.assessment_result if i and i.assessment_result else "NOT_ASSESSED"
            linked_ev = [e.filename for e in evidence if c.control_id in (e.control_ids or [])]
            h.append(
                f"<tr><td><b>{_esc(c.control_id)}</b></td><td>{_esc(c.title)}"
                + (f"<div class='narr'>{_esc(i.narrative)}</div>" if i and i.narrative else "")
                + f"</td><td><span class='status' style='color:{STATUS_COLOR.get(status, '#333')}'>"
                f"{STATUS_LABEL.get(status, status)}</span></td>"
                f"<td class='small'>{_esc(result)}</td>"
                f"<td class='small'>{_esc(', '.join(linked_ev)) if linked_ev else '—'}</td></tr>"
            )
        h.append("</table>")
    else:
        h.append("<p class='small'>No control catalog is loaded for this framework "
                 "(the framework may have been deactivated since the assessment).</p>")

    # ---- 3. Findings in the assessment window ----
    h.append(f"<h2>3. Findings ({len(findings)} open or created in the assessment window)</h2>")
    h.append(f"<p class='small'>Window: {_esc(_fmt_dt(start))} → {_esc(_fmt_dt(end))}. "
             "Includes findings created in this period plus findings still open at its end.</p>")
    if findings:
        h.append("<table><tr><th>Finding</th><th style='width:80px'>Severity</th>"
                 "<th style='width:110px'>Status</th><th style='width:90px'>Control</th>"
                 "<th style='width:110px'>Owner</th><th style='width:90px'>Due</th></tr>")
        for f in findings:
            # Terminal statuses never show due-date-derived flags (repo rule).
            overdue = (f.status or "").upper() not in TERMINAL_STATUSES \
                and f.due_date and f.due_date < today
            h.append(
                f"<tr><td>{_esc(f.title)}"
                + (f"<div class='narr'>{_esc((f.description or '')[:400])}</div>" if f.description else "")
                + f"</td><td>{_esc(f.severity)}</td>"
                f"<td>{_esc(f.status)}"
                + (" <span class='badge' style='color:#b91c1c'>OVERDUE</span>" if overdue else "")
                + f"</td><td>{_esc(f.control_id)}</td>"
                f"<td>{_esc(f.owner_name)}</td><td>{_esc(f.due_date)}</td></tr>"
            )
        h.append("</table>")
    else:
        h.append("<p class='small'>No findings were open or created during the assessment window.</p>")

    # ---- 4. Sign-off ----
    h.append(
        "<h2>4. Sign-off</h2>"
        "<p class='small'>By signing below, the parties attest that this report accurately "
        "reflects the assessment results recorded in the compliance system of record at the "
        "time of generation.</p>"
        "<table class='signoff'><tr><th style='width:180px'>Role</th><th>Name</th>"
        "<th>Signature</th><th style='width:120px'>Date</th></tr>"
        f"<tr><td>Assessor</td><td>{_esc(assessor_name)}</td><td></td><td></td></tr>"
        "<tr><td>Compliance Manager</td><td></td><td></td><td></td></tr>"
        "<tr><td>System Owner</td><td></td><td></td><td></td></tr>"
        "</table>"
    )

    h.append(f"<p class='small' style='margin-top:40px'>Generated by Athorize · {now} · "
             f"This report reflects the compliance system of record at generation time.</p>"
             "</body></html>")
    return "".join(h)

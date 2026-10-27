"""Build the compliance digest for an organization.

Aggregates the things that rot if ignored — overdue findings, findings due
soon, expiring/expired evidence, and overdue continuous-monitoring cadences —
into a structured summary plus HTML and text renderings for email.
"""
from __future__ import annotations

import html
from datetime import date, timedelta

from sqlalchemy.orm import Session

from models.finding import Finding
from models.evidence import EvidenceArtifact
from models.system import System
from models.user import User
from models.organization import Organization
from services.aging import TERMINAL_STATUSES
from services import conmon_cadence

DUE_SOON_DAYS = 14
EVIDENCE_EXPIRING_DAYS = 30
DIGEST_ROLES = ("admin", "compliance_manager")


def recipients(db: Session, organization_id: int) -> list[str]:
    rows = db.query(User.email).filter(
        User.organization_id == organization_id,
        User.is_active == True,  # noqa: E712
        User.role.in_(DIGEST_ROLES),
        User.email.isnot(None),
        User.email != "",
    ).all()
    # Strip + drop whitespace-only addresses, which pass the != "" SQL filter but
    # would put a blank address in the To header and can reject the whole message.
    return sorted({r[0].strip() for r in rows if r[0] and r[0].strip()})


def build_digest(db: Session, organization_id: int) -> dict:
    today = date.today()
    soon = today + timedelta(days=DUE_SOON_DAYS)
    evid_horizon = today + timedelta(days=EVIDENCE_EXPIRING_DAYS)

    sys_names = {
        s.id: (s.acronym or s.name)
        for s in db.query(System).filter(System.organization_id == organization_id).all()
    }

    open_findings = db.query(Finding).filter(
        Finding.organization_id == organization_id,
        Finding.status.notin_(TERMINAL_STATUSES),
    ).all()

    overdue, due_soon = [], []
    for f in open_findings:
        if f.due_date is None:
            continue
        item = {
            "title": f.title, "severity": f.severity,
            "system": sys_names.get(f.system_id, ""), "due_date": f.due_date.isoformat(),
            "owner": f.owner_name or "", "days": (f.due_date - today).days,
        }
        if f.due_date < today:
            overdue.append(item)
        elif f.due_date <= soon:
            due_soon.append(item)
    overdue.sort(key=lambda x: x["days"])
    due_soon.sort(key=lambda x: x["days"])

    evid = db.query(EvidenceArtifact).filter(
        EvidenceArtifact.organization_id == organization_id,
        EvidenceArtifact.expiration_date.isnot(None),
        EvidenceArtifact.expiration_date <= evid_horizon,
    ).all()
    expired_ev, expiring_ev = [], []
    for e in evid:
        item = {
            "name": e.filename, "system": sys_names.get(e.system_id, ""),
            "expiration_date": e.expiration_date.isoformat(),
            "days": (e.expiration_date - today).days,
        }
        (expired_ev if e.expiration_date < today else expiring_ev).append(item)
    expired_ev.sort(key=lambda x: x["days"])
    expiring_ev.sort(key=lambda x: x["days"])

    cadence_overdue = [
        c for c in conmon_cadence.list_cadences(db, organization_id)
        if c.get("status") == "OVERDUE"
    ]

    org = db.query(Organization).filter(Organization.id == organization_id).first()
    return {
        "organization": org.name if org else "",
        "generated": today.isoformat(),
        "overdue_findings": overdue,
        "due_soon_findings": due_soon,
        "expired_evidence": expired_ev,
        "expiring_evidence": expiring_ev,
        "overdue_cadences": cadence_overdue,
        "counts": {
            "overdue_findings": len(overdue),
            "due_soon_findings": len(due_soon),
            "expired_evidence": len(expired_ev),
            "expiring_evidence": len(expiring_ev),
            "overdue_cadences": len(cadence_overdue),
        },
    }


def has_content(digest: dict) -> bool:
    return any(digest["counts"].values())


def subject(digest: dict) -> str:
    # Count everything the digest reports — including due-soon findings and
    # expiring evidence. A digest is only sent when has_content() is true, so
    # the subject must never say "all clear" for an email that has content.
    total = sum(digest["counts"].values())
    flag = f"{total} item(s) need attention" if total else "all clear"
    return f"Athorize — compliance digest ({flag})"


def _rows_html(items: list[dict], cols: list[tuple[str, str]]) -> str:
    if not items:
        return '<p style="color:#888;margin:4px 0 16px">None.</p>'
    head = "".join(f'<th align="left" style="padding:4px 8px;border-bottom:1px solid #ccc">{html.escape(h)}</th>' for _, h in cols)
    body = ""
    for it in items:
        cells = "".join(f'<td style="padding:4px 8px;border-bottom:1px solid #eee">{html.escape(str(it.get(k, "")))}</td>' for k, _ in cols)
        body += f"<tr>{cells}</tr>"
    return f'<table style="border-collapse:collapse;width:100%;margin:4px 0 16px;font-size:13px"><tr>{head}</tr>{body}</table>'


def render_html(digest: dict) -> str:
    c = digest["counts"]
    return f"""<div style="font-family:Arial,Helvetica,sans-serif;max-width:680px;margin:0 auto;color:#222">
<h2 style="margin-bottom:0">Compliance digest</h2>
<p style="color:#888;margin-top:2px">{html.escape(digest['organization'])} · {html.escape(digest['generated'])}</p>
<p style="font-size:13px">
<b>{c['overdue_findings']}</b> overdue findings · <b>{c['due_soon_findings']}</b> due soon ·
<b>{c['expired_evidence']}</b> expired evidence · <b>{c['expiring_evidence']}</b> expiring ·
<b>{c['overdue_cadences']}</b> overdue cadences</p>
<h3>Overdue findings</h3>
{_rows_html(digest['overdue_findings'], [('title', 'Finding'), ('severity', 'Severity'), ('system', 'System'), ('due_date', 'Due'), ('owner', 'Owner')])}
<h3>Findings due in {DUE_SOON_DAYS} days</h3>
{_rows_html(digest['due_soon_findings'], [('title', 'Finding'), ('severity', 'Severity'), ('system', 'System'), ('due_date', 'Due')])}
<h3>Expired evidence</h3>
{_rows_html(digest['expired_evidence'], [('name', 'Evidence'), ('system', 'System'), ('expiration_date', 'Expired')])}
<h3>Evidence expiring within {EVIDENCE_EXPIRING_DAYS} days</h3>
{_rows_html(digest['expiring_evidence'], [('name', 'Evidence'), ('system', 'System'), ('expiration_date', 'Expires')])}
<h3>Overdue monitoring cadences</h3>
{_rows_html(digest['overdue_cadences'], [('framework_id', 'Framework'), ('activity_type', 'Activity'), ('days_overdue', 'Days overdue')])}
<p style="color:#aaa;font-size:11px;margin-top:24px">Athorize — automated digest. Adjust recipients by managing admin/compliance-manager users.</p>
</div>"""


def render_text(digest: dict) -> str:
    c = digest["counts"]
    lines = [
        f"Compliance digest — {digest['organization']} ({digest['generated']})",
        "",
        f"Overdue findings:   {c['overdue_findings']}",
        f"Due soon:           {c['due_soon_findings']}",
        f"Expired evidence:   {c['expired_evidence']}",
        f"Expiring evidence:  {c['expiring_evidence']}",
        f"Overdue cadences:   {c['overdue_cadences']}",
        "",
    ]
    for f in digest["overdue_findings"]:
        lines.append(f"  [OVERDUE {abs(f['days'])}d] {f['severity']} {f['title']} ({f['system']}) due {f['due_date']}")
    return "\n".join(lines)

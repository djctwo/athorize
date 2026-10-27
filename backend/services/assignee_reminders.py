"""Per-assignee work reminders — the nudge that keeps evidence fresh and
findings moving.

The org digest (services/digest.py) tells admins/compliance managers what is
rotting; this tells each ASSIGNEE what they personally own: findings due within
7 days or overdue, and evidence they are responsible for that is expiring within
14 days or expired. One short email per user per run, sent from the same
scheduler as the digest (DIGEST_INTERVAL_HOURS) — no extra configuration.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import date, timedelta

from sqlalchemy.orm import Session

from models import EvidenceArtifact, Finding, User
from services.aging import TERMINAL_STATUSES

FINDING_HORIZON_DAYS = 7
EVIDENCE_HORIZON_DAYS = 14


def build_reminders(db: Session, organization_id: int) -> dict[int, dict]:
    """Per-user work needing a nudge: {user_id: {user, findings: [...], evidence: [...]}}"""
    today = date.today()
    per_user: dict[int, dict] = defaultdict(lambda: {"findings": [], "evidence": []})

    f_horizon = today + timedelta(days=FINDING_HORIZON_DAYS)
    findings = db.query(Finding).filter(
        Finding.organization_id == organization_id,
        Finding.owner_id.isnot(None),
        ~Finding.status.in_(TERMINAL_STATUSES),
        Finding.due_date.isnot(None),
        Finding.due_date <= f_horizon,
    ).all()
    for f in findings:
        per_user[f.owner_id]["findings"].append({
            "title": f.title, "severity": f.severity,
            "due_date": f.due_date.isoformat(),
            "days": (f.due_date - today).days,
        })

    e_horizon = today + timedelta(days=EVIDENCE_HORIZON_DAYS)
    evidence = db.query(EvidenceArtifact).filter(
        EvidenceArtifact.organization_id == organization_id,
        EvidenceArtifact.owner_id.isnot(None),
        EvidenceArtifact.expiration_date.isnot(None),
        EvidenceArtifact.expiration_date <= e_horizon,
    ).all()
    for e in evidence:
        per_user[e.owner_id]["evidence"].append({
            "filename": e.filename,
            "expiration_date": e.expiration_date.isoformat(),
            "days": (e.expiration_date - today).days,
        })

    users = {
        u.id: u for u in db.query(User).filter(
            User.id.in_(list(per_user.keys())),
            User.is_active == True,  # noqa: E712
        ).all()
    } if per_user else {}
    return {uid: {**work, "user": users[uid]} for uid, work in per_user.items() if uid in users}


def _line(days: int, what: str) -> str:
    if days < 0:
        return f"OVERDUE by {-days} day(s): {what}"
    if days == 0:
        return f"Due TODAY: {what}"
    return f"Due in {days} day(s): {what}"


def render(work: dict) -> tuple[str, str, str]:
    """(subject, html, text) for one user's reminder email."""
    findings = sorted(work["findings"], key=lambda x: x["days"])
    evidence = sorted(work["evidence"], key=lambda x: x["days"])
    n = len(findings) + len(evidence)
    subject = f"Athorize: {n} item(s) assigned to you need attention"

    lines: list[str] = []
    if findings:
        lines.append("Findings:")
        for f in findings:
            what = "[{severity}] {title} (due {due_date})".format(**f)
            lines.append(f"  - {_line(f['days'], what)}")
    if evidence:
        lines.append("Evidence to refresh:")
        for e in evidence:
            what = "{filename} (expires {expiration_date})".format(**e)
            lines.append(f"  - {_line(e['days'], what)}")
    text = "Your assigned Athorize work:\n\n" + "\n".join(lines) + "\n\nSign in to take action."

    def esc(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    html_rows = "".join(f"<li>{esc(line.strip())}</li>" for line in lines if not line.endswith(":"))
    html = (
        "<p>Your assigned Athorize work:</p>"
        f"<ul>{html_rows}</ul>"
        "<p>Sign in to take action.</p>"
    )
    return subject, html, text


def send_reminders(db: Session, organization_id: int) -> int:
    """Email each assignee their reminder. Returns emails sent."""
    from services import email as email_svc

    if not email_svc.is_configured():
        return 0
    sent = 0
    for _uid, work in build_reminders(db, organization_id).items():
        user = work["user"]
        if not user.email:
            continue
        subject, html, text = render(work)
        try:
            email_svc.send_email([user.email], subject, html, text)
            sent += 1
        except Exception as exc:  # one bad mailbox must not stop the rest
            print(f"assignee-reminders: {user.username} failed: {exc}")
    return sent

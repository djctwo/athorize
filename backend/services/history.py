"""Daily compliance snapshots — the data behind trend charts and burndown.

`take_snapshots` records, once per day per (org, system, active framework), the
compliance score and open/overdue finding counts. Re-running on the same day
updates that day's rows (idempotent), so the startup catch-up plus the daily
scheduler can both call it safely. Purely local computation — no network.

`live_pair_scores` is the single computation behind every snapshot row AND
every live company/trend number (Portfolio average, today's trend point), so
the stored history and the live Dashboard can't drift apart.
"""
from __future__ import annotations

from datetime import date

from sqlalchemy.orm import Session

from models import FrameworkActivation, Organization, System
from models.compliance_snapshot import ComplianceSnapshot
from services.compliance_score import score_system
from services.metrics import average_score


def live_pair_scores(
    db: Session,
    organization_id: int,
    system_ids: set[int] | None = None,
    framework_id: str | None = None,
    on: date | None = None,
) -> list[dict]:
    """Score + finding counts for every (system x active framework) pair of an
    org whose catalog is loaded. `system_ids` (None = all) narrows to a scope
    or a single system; `framework_id` narrows to one framework."""
    day = on or date.today()
    act_q = db.query(FrameworkActivation).filter(
        FrameworkActivation.organization_id == organization_id,
        FrameworkActivation.is_active == True,  # noqa: E712
    )
    if framework_id:
        act_q = act_q.filter(FrameworkActivation.framework_id == framework_id)
    sys_q = db.query(System).filter(System.organization_id == organization_id)
    if system_ids is not None:
        sys_q = sys_q.filter(System.id.in_(system_ids))
    systems = sys_q.all()

    rows = []
    for activation in act_q.all():
        for system in systems:
            s = score_system(system.id, activation.framework_id, db, today=day)
            if s.total_controls == 0:
                continue  # framework catalog not loaded — nothing meaningful to record
            rows.append({
                "system_id": system.id,
                "framework_id": activation.framework_id,
                "score_percentage": s.score_percentage,
                "total_controls": s.total_controls,
                "implemented": s.implemented,
                "open_findings": s.open_findings,
                "critical_findings": s.critical_findings,
                "overdue_findings": s.overdue_findings,
            })
    return rows


def live_trend_point(rows: list[dict], on: date | None = None) -> dict:
    """Aggregate pair rows exactly like GET /dashboard/history aggregates
    snapshot rows (mean score, summed counts)."""
    return {
        "date": (on or date.today()).isoformat(),
        "avg_score": average_score(r["score_percentage"] for r in rows) or 0.0,
        "open_findings": sum(r["open_findings"] for r in rows),
        "overdue_findings": sum(r["overdue_findings"] for r in rows),
        "critical_findings": sum(r["critical_findings"] for r in rows),
    }


def snapshot_org(db: Session, organization_id: int, on: date | None = None) -> int:
    """Snapshot every (system × active framework) for one org. Returns rows written."""
    day = on or date.today()
    written = 0
    for pair in live_pair_scores(db, organization_id, on=day):
        row = db.query(ComplianceSnapshot).filter(
            ComplianceSnapshot.organization_id == organization_id,
            ComplianceSnapshot.system_id == pair["system_id"],
            ComplianceSnapshot.framework_id == pair["framework_id"],
            ComplianceSnapshot.snapshot_date == day,
        ).first()
        if row is None:
            row = ComplianceSnapshot(
                organization_id=organization_id, system_id=pair["system_id"],
                framework_id=pair["framework_id"], snapshot_date=day,
            )
            db.add(row)
        row.score_percentage = pair["score_percentage"]
        row.total_controls = pair["total_controls"]
        row.implemented = pair["implemented"]
        row.open_findings = pair["open_findings"]
        row.critical_findings = pair["critical_findings"]
        row.overdue_findings = pair["overdue_findings"]
        written += 1
    db.flush()
    return written


def take_snapshots(db: Session, on: date | None = None) -> int:
    """Snapshot every organization. Returns total rows written."""
    total = 0
    for (org_id,) in db.query(Organization.id).all():
        total += snapshot_org(db, org_id, on=on)
    db.commit()
    return total

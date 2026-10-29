"""One definition per user-facing compliance number.

Every surface that shows a finding count or a compliance score (Dashboard KPI
tiles and charts, per-framework score cards, Portfolio, CSV reports, the
audit binder, red-team checks, history snapshots and the Executive Briefing,
which reads these through the API) must go through these helpers so the same
number can't be computed two different ways on two pages.

Definitions (mirrored in the in-app Help):
  - Open finding: any finding NOT in a terminal status (Closed, Risk Accepted,
    False Positive). DELAYED and IN_PROGRESS findings are open, and the UI
    says so ("incl. N delayed"); the API marks each finding `is_open` so no
    page re-derives this from status. Company-wide
    numbers (Dashboard tiles and charts, Portfolio) count findings filed under
    a framework that is ACTIVE for the company and has a loaded catalog — the
    same (system x framework) pairs the score cards and the trend use, so the
    tiles, cards and today's trend point always agree. See
    counted_framework_clause.
  - Critical: an open finding with severity CRITICAL.
  - Overdue: an open finding whose due date is before today (server date).
  - Compliance score (per system x framework): (Implemented + Inherited) /
    (catalog controls - Not Applicable), counting only implementation rows for
    controls that exist in the framework's catalog. Planned / Partially do not
    count. See services.compliance_score.score_system.
  - Inspection readiness (per framework + chosen systems): ready /
    (catalog controls x systems, minus Not Applicable pairs). A pair is ready
    when it is Implemented/Inherited AND has a narrative of at least 80 chars
    AND evidence uploaded for THAT system (tagged with the control and
    framework, or linked on the implementation) that is unexpired on the
    inspection date (today when none is set) AND has no open finding filed
    against that control on that system under that framework. See
    services.inspection_prep.build_prep.
  - Pair with work (per system x framework): at least one catalog control
    assessed (any status but Not Assessed) OR an open finding. A pair nobody
    has started is shown nowhere and averaged nowhere. See pair_has_work; the
    API returns it per pair as `has_work`, so the UI never re-derives it.
  - Average score (company / trend): the plain mean of the per-pair scores over
    the system x active framework pairs (catalog loaded) that have work, and
    how many pairs that is. Frameworks nobody has started don't drag it toward
    0%. See active_average.
"""
from __future__ import annotations

from datetime import date
from typing import Iterable, Mapping

from sqlalchemy import exists, select

from models.control import Control
from models.finding import Finding
from models.framework_activation import FrameworkActivation
from services.aging import TERMINAL_STATUSES

# Implementation statuses that satisfy a control (score numerator, and the
# first condition for Inspection Prep "ready"), and the scoped-out status that
# leaves every denominator.
SATISFIED_STATUSES = frozenset({"IMPLEMENTED", "INHERITED"})
NOT_APPLICABLE = "NOT_APPLICABLE"
# Open, but remediation slipped past its plan. Counted as open everywhere.
DELAYED = "DELAYED"


def counted_framework_clause(organization_id: int):
    """SQLAlchemy clause: the finding's framework is active for the org and its
    catalog is loaded. Findings of a deactivated framework stay on the Findings
    page but leave the company numbers, exactly as they leave the score cards."""
    active = select(FrameworkActivation.framework_id).where(
        FrameworkActivation.organization_id == organization_id,
        FrameworkActivation.is_active == True,  # noqa: E712
        exists().where(Control.framework_id == FrameworkActivation.framework_id),
    )
    return Finding.framework_id.in_(active)


def open_finding_clause():
    """SQLAlchemy clause: the finding is open (not in a terminal status)."""
    return ~Finding.status.in_(TERMINAL_STATUSES)


def is_open_status(status: str | None) -> bool:
    return (status or "").upper() not in TERMINAL_STATUSES


def finding_counts(base_query, today: date | None = None) -> dict[str, int]:
    """Open (and how many of those are Delayed) / critical / overdue counts for a Finding query that is already
    filtered to the right org / scope / system / framework."""
    day = today or date.today()
    open_q = base_query.filter(open_finding_clause())
    return {
        "open": open_q.count(),
        "delayed": open_q.filter(Finding.status == DELAYED).count(),
        "critical": open_q.filter(Finding.severity == "CRITICAL").count(),
        "overdue": open_q.filter(Finding.due_date.isnot(None), Finding.due_date < day).count(),
    }


def average_score(scores: Iterable[float]) -> float | None:
    """Mean of per-(system x framework) scores, rounded like every score (1 dp).
    None when there is nothing to average (no system or no loaded catalog)."""
    vals = list(scores)
    if not vals:
        return None
    return round(sum(vals) / len(vals), 1)


def pair_has_work(pair: Mapping) -> bool:
    """Does this system x framework pair have work in it: at least one catalog
    control assessed, or an open finding? The one rule behind the Dashboard's
    score-by-pair chart, the Executive Briefing table, every average score
    (Dashboard trend, daily snapshots, Portfolio) and the seeded demo history.

    `pair` is a score row: open_findings, implemented, assessed_controls.
    Snapshot rows recorded before assessed_controls was stored have it as None;
    for those, Implemented/Inherited controls are the evidence of work (they
    are assessed controls)."""
    if (pair.get("open_findings") or 0) > 0:
        return True
    assessed = pair.get("assessed_controls")
    if assessed is None:
        return (pair.get("implemented") or 0) > 0
    return assessed > 0


def active_average(pairs: Iterable[Mapping]) -> tuple[float | None, int]:
    """(average score, number of pairs averaged) over the pairs with work.
    The average is None when no pair has work yet."""
    active = [p for p in pairs if pair_has_work(p)]
    return average_score(p["score_percentage"] for p in active), len(active)

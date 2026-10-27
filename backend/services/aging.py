from datetime import date, datetime, timezone
from typing import Optional

# Findings in a terminal status are done — they must not show due-date
# countdowns or count toward Overdue KPIs.
TERMINAL_STATUSES = {"CLOSED", "RISK_ACCEPTED", "FALSE_POSITIVE"}


def aging_bucket(due_date: Optional[date], status: Optional[str] = None) -> str:
    if status in TERMINAL_STATUSES:
        return "RESOLVED"
    if due_date is None:
        return "ON_TRACK"
    today = date.today()
    delta = (due_date - today).days
    if delta < 0:
        return "OVERDUE"
    if delta <= 7:
        return "DUE_7"
    if delta <= 30:
        return "DUE_30"
    return "ON_TRACK"


def days_until(due_date: Optional[date]) -> Optional[int]:
    if due_date is None:
        return None
    return (due_date - date.today()).days


def days_open(created_at: Optional[datetime]) -> Optional[int]:
    if created_at is None:
        return None
    # created_at is UTC; date.today() is the server's local date. Compare like
    # with like (both local), or a finding created a minute ago reads "1 day"
    # east of UTC and "-1" west of it. The UI recomputes this in the viewer's
    # own zone; this value feeds exports and other server-side consumers.
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    return max(0, (date.today() - created_at.astimezone().date()).days)


def compute_aging(
    due_date: Optional[date],
    created_at: Optional[datetime],
    status: Optional[str] = None,
) -> dict:
    terminal = status in TERMINAL_STATUSES
    return {
        "aging_bucket": aging_bucket(due_date, status),
        "days_until_due": None if terminal else days_until(due_date),
        "days_open": days_open(created_at),
    }

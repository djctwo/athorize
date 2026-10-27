"""Continuous-monitoring cadence requirements.

Resolution order for a cadence interval, highest priority first:
  1. Org override (conmon_cadences table)
  2. Framework plugin default (metadata.json "conmon_cadences")
  3. Built-in default (DEFAULT_CADENCES below)

Status for each requirement is computed from ConMonEntry history (the most
recent matching entry's date = "last done").
"""
from __future__ import annotations

from datetime import date

from sqlalchemy.orm import Session

from config import settings
from models.conmon import ConMonEntry
from models.conmon_cadence import ConMonCadence
from models.framework_activation import FrameworkActivation
from models.system import System
from services.framework_loader import FrameworkLoader

# Built-in defaults (days). Org-wide unless a framework/plugin narrows them.
DEFAULT_CADENCES: dict[str, int] = {
    "VULNERABILITY_SCAN": 30,
    "PATCH_REVIEW": 30,
    "LOG_REVIEW": 30,
    "ACCOUNT_REVIEW": 90,
    "CONFIG_REVIEW": 90,
    "ACCESS_REVIEW": 90,
    "POLICY_REVIEW": 365,
    "USER_TRAINING": 365,
    "RISK_ASSESSMENT": 365,
    "BACKUP_VERIFICATION": 90,
    "CONTINUITY_TEST": 365,
}

DUE_SOON_WINDOW = 14  # days before next_due to flag DUE_SOON

_loader = FrameworkLoader(settings.frameworks_dir)


def _metadata_cadences(framework_id: str) -> dict[str, int]:
    """conmon_cadences from a plugin's metadata.json, if any.

    Expected shape (optional): "conmon_cadences": [{"activity_type": "...",
    "interval_days": N}, ...]
    """
    meta = _loader.get_metadata(framework_id)
    out: dict[str, int] = {}
    if meta is None:
        return out
    for entry in getattr(meta, "conmon_cadences", None) or []:
        at = entry.get("activity_type")
        iv = entry.get("interval_days")
        if at and isinstance(iv, int):
            out[at] = iv
    return out


def list_cadences(db: Session, organization_id: int) -> list[dict]:
    """Resolved cadence requirements + computed status for an org.

    Produces one row per (framework, activity_type): every active framework's
    metadata/default activities, plus org-wide defaults, plus any overrides.
    """
    active_fw = [
        a.framework_id
        for a in db.query(FrameworkActivation).filter(
            FrameworkActivation.organization_id == organization_id,
            FrameworkActivation.is_active == True,  # noqa: E712
        ).all()
    ]
    overrides = {
        (c.framework_id, c.activity_type): c
        for c in db.query(ConMonCadence).filter(
            ConMonCadence.organization_id == organization_id
        ).all()
    }

    # Build the requirement set: org-wide defaults (framework_id "") + each
    # active framework's metadata cadences, then layer overrides on top.
    requirements: dict[tuple[str, str], dict] = {}
    for at, iv in DEFAULT_CADENCES.items():
        requirements[("", at)] = {"framework_id": "", "activity_type": at, "interval_days": iv, "source": "default", "enabled": True}
    for fw in active_fw:
        for at, iv in _metadata_cadences(fw).items():
            requirements[(fw, at)] = {"framework_id": fw, "activity_type": at, "interval_days": iv, "source": "framework", "enabled": True}
    for (fw, at), c in overrides.items():
        requirements[(fw, at)] = {"framework_id": fw, "activity_type": at, "interval_days": c.interval_days, "source": "override", "enabled": c.enabled}

    # Last-done lookup: most recent entry date per (framework_id, activity_type)
    # and per activity_type org-wide (for framework_id "" requirements).
    last_by_fw_at: dict[tuple[str, str], date] = {}
    last_by_at: dict[str, date] = {}
    for e in db.query(ConMonEntry).filter(ConMonEntry.organization_id == organization_id).all():
        fw = e.framework_id or ""
        key = (fw, e.activity_type)
        if e.entry_date and (key not in last_by_fw_at or e.entry_date > last_by_fw_at[key]):
            last_by_fw_at[key] = e.entry_date
        if e.entry_date and (e.activity_type not in last_by_at or e.entry_date > last_by_at[e.activity_type]):
            last_by_at[e.activity_type] = e.entry_date

    # The monitoring clock starts when the org registers its first system: a
    # brand-new instance has nothing to monitor, and a 30-day scan cadence is not
    # overdue on day one (R2USER-18 — a blank install greeted the admin with
    # "CADENCE OVERDUE 11"). A never-logged requirement is due one interval after
    # that start and only then counts as overdue.
    first_system = db.query(System.created_at).filter(
        System.organization_id == organization_id,
    ).order_by(System.created_at).first()
    started = first_system[0].date() if first_system and first_system[0] else None

    today = date.today()
    rows = []
    for (fw, at), req in sorted(requirements.items()):
        if not req["enabled"]:
            continue
        last = last_by_fw_at.get((fw, at)) if fw else last_by_at.get(at)
        interval = req["interval_days"]
        if last is None and started is None:
            status, next_due, days_overdue = "NEVER", None, None
        elif last is None:
            next_due = started.fromordinal(started.toordinal() + interval)
            delta = (next_due - today).days
            if delta < 0:
                status, days_overdue = "OVERDUE", -delta
            else:
                status, days_overdue = "NEVER", None
        else:
            next_due = last.fromordinal(last.toordinal() + interval)
            delta = (next_due - today).days
            if delta < 0:
                status, days_overdue = "OVERDUE", -delta
            elif delta <= DUE_SOON_WINDOW:
                status, days_overdue = "DUE_SOON", 0
            else:
                status, days_overdue = "OK", 0
        rows.append({
            "framework_id": fw,
            "activity_type": at,
            "interval_days": interval,
            "source": req["source"],
            "last_done": last.isoformat() if last else None,
            "next_due": next_due.isoformat() if next_due else None,
            "status": status,
            "days_overdue": days_overdue,
        })
    return rows


def overdue_count(db: Session, organization_id: int) -> int:
    return sum(1 for r in list_cadences(db, organization_id) if r["status"] == "OVERDUE")


def set_cadence(db: Session, organization_id: int, framework_id: str, activity_type: str,
                interval_days: int, enabled: bool) -> ConMonCadence:
    row = db.query(ConMonCadence).filter(
        ConMonCadence.organization_id == organization_id,
        ConMonCadence.framework_id == framework_id,
        ConMonCadence.activity_type == activity_type,
    ).first()
    if row is None:
        row = ConMonCadence(
            organization_id=organization_id, framework_id=framework_id,
            activity_type=activity_type, interval_days=interval_days, enabled=enabled,
        )
        db.add(row)
    else:
        row.interval_days = interval_days
        row.enabled = enabled
    db.flush()
    return row

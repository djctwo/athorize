"""Inspection Prep — per-framework audit-readiness package from live data.

For a chosen framework + system(s) + inspection date, produces:
  - overall readiness score and a per-control-family breakdown
    (implementation status, narrative quality, evidence presence + freshness)
  - a prioritized punch list of gaps with owners
  - a 90/60/30-day timeline anchored on the inspection date

It reuses the same data the compliance score and red-team analyzer read, but
reframes it as "what an assessor will find" rather than adversarial findings.
Readiness is defined in services/metrics.py: Not Applicable controls leave the
denominator (as they do for the compliance score), evidence counts only for
the system it belongs to, and a control with an open finding (same system,
framework and control; "open" as everywhere else) is not ready.
"""
from __future__ import annotations

from datetime import date
from collections import defaultdict

from sqlalchemy.orm import Session

from models.control import Control
from models.control_implementation import ControlImplementation
from models.evidence import EvidenceArtifact
from models.finding import Finding
from models.system import System

from services.metrics import NOT_APPLICABLE, SATISFIED_STATUSES as SATISFIED, open_finding_clause

NARRATIVE_MIN_CHARS = 80  # below this a narrative reads as a stub to an assessor


def _evidence_index(db: Session, organization_id: int, framework_id: str,
                    system_ids: list[int], impls: dict, as_of: date | None = None) -> dict:
    """(system_id, control_id) -> {has_any, has_fresh}.

    Evidence counts only for the system it was uploaded against (an artifact
    for ERP says nothing about SCADA), via either its control/framework tags or
    an explicit link on that system's implementation (`evidence_ids`).
    Fresh = not expired on ``as_of`` (the inspection date when one is set:
    evidence that lapses before the assessor arrives is not ready — R2DATA-7)."""
    today = max(as_of or date.today(), date.today())
    idx: dict[tuple[int, str], dict] = defaultdict(lambda: {"has_any": False, "has_fresh": False})

    def mark(key, ev):
        idx[key]["has_any"] = True
        if ev.expiration_date is None or ev.expiration_date >= today:
            idx[key]["has_fresh"] = True

    rows = db.query(EvidenceArtifact).filter(
        EvidenceArtifact.organization_id == organization_id,
    ).all()
    by_id = {ev.id: ev for ev in rows}
    wanted = set(system_ids)
    for ev in rows:
        if ev.system_id not in wanted or framework_id not in (ev.framework_ids or []):
            continue
        for cid in (ev.control_ids or []):
            mark((ev.system_id, cid), ev)
    for (sid, cid), impl in impls.items():
        for eid in (impl.evidence_ids or []):
            ev = by_id.get(eid) if isinstance(eid, int) else None
            if ev is not None:
                mark((sid, cid), ev)
    return idx


def _open_findings_index(db: Session, organization_id: int, framework_id: str,
                         system_ids: list[int]) -> dict[tuple[int, str], list[str]]:
    """(system_id, control_id) -> titles of OPEN findings filed against that
    control on that system under this framework. "Open" is the one definition
    (services/metrics.open_finding_clause): Open, In Progress and Delayed."""
    idx: dict[tuple[int, str], list[str]] = defaultdict(list)
    rows = db.query(Finding.system_id, Finding.control_id, Finding.title).filter(
        Finding.organization_id == organization_id,
        Finding.framework_id == framework_id,
        Finding.system_id.in_(system_ids),
        Finding.control_id.isnot(None),
        open_finding_clause(),
    ).order_by(Finding.id).all()
    for sid, cid, title in rows:
        idx[(sid, cid)].append(title)
    return idx


def build_prep(
    db: Session,
    organization_id: int,
    framework_id: str,
    system_ids: list[int],
    inspection_date: date | None,
) -> dict:
    controls = db.query(Control).filter(Control.framework_id == framework_id).all()
    if not controls:
        return {"framework_id": framework_id, "families": [], "punch_list": [],
                "readiness_score": 0.0, "timeline": [], "control_count": 0}

    systems = {
        s.id: s for s in db.query(System).filter(
            System.organization_id == organization_id,
            System.id.in_(system_ids),
        ).all()
    }
    if not systems:
        return {"framework_id": framework_id, "families": [], "punch_list": [],
                "readiness_score": 0.0, "timeline": [], "control_count": 0,
                "error": "No matching systems"}

    impls: dict[tuple[int, str], ControlImplementation] = {}
    for i in db.query(ControlImplementation).filter(
        ControlImplementation.framework_id == framework_id,
        ControlImplementation.system_id.in_(list(systems.keys())),
    ).all():
        impls[(i.system_id, i.control_id)] = i

    ev_idx = _evidence_index(db, organization_id, framework_id, list(systems.keys()), impls, as_of=inspection_date)
    open_idx = _open_findings_index(db, organization_id, framework_id, list(systems.keys()))

    fam_stat: dict[str, dict] = defaultdict(lambda: {
        "family": "", "family_name": "", "total": 0, "ready": 0, "not_applicable": 0,
        "implemented": 0, "narrative_gaps": 0, "evidence_gaps": 0, "stale_evidence": 0,
        "open_findings": 0,
    })
    punch: list[dict] = []

    for ctrl in controls:
        fam = ctrl.family or "—"
        fs = fam_stat[fam]
        fs["family"] = fam
        fs["family_name"] = ctrl.family_name or fam

        # A control is assessed per system; aggregate worst-case readiness
        # (an assessor samples systems, so the weakest one is the exposure).
        for sid, system in systems.items():
            impl = impls.get((sid, ctrl.control_id))
            status = impl.implementation_status if impl else "NOT_ASSESSED"
            if status == NOT_APPLICABLE:
                # Scoped out (e.g. by the baseline Scoping wizard): not part of
                # what an assessor tests, so it leaves the denominator exactly as
                # it does for the compliance score.
                fs["not_applicable"] += 1
                continue
            fs["total"] += 1
            narrative = (impl.narrative or "").strip() if impl else ""
            ev = ev_idx.get((sid, ctrl.control_id), {"has_any": False, "has_fresh": False})
            open_titles = open_idx.get((sid, ctrl.control_id), [])

            issues = []
            if status not in SATISFIED:
                issues.append(f"status is {status}")
            else:
                fs["implemented"] += 1
            if open_titles:
                # An assessor tests the control and finds the open weakness: it
                # is not ready however good the paperwork is.
                fs["open_findings"] += 1
                more = f" (+{len(open_titles) - 1} more)" if len(open_titles) > 1 else ""
                issues.append(f"open finding: {open_titles[0]}{more}")
            if status in SATISFIED and len(narrative) < NARRATIVE_MIN_CHARS:
                fs["narrative_gaps"] += 1
                issues.append("narrative is thin or missing")
            if status in SATISFIED and not ev["has_any"]:
                fs["evidence_gaps"] += 1
                issues.append("no evidence linked")
            elif status in SATISFIED and ev["has_any"] and not ev["has_fresh"]:
                fs["stale_evidence"] += 1
                issues.append("evidence is expired")

            ready = (status in SATISFIED and len(narrative) >= NARRATIVE_MIN_CHARS
                     and ev["has_fresh"] and not open_titles)
            if ready:
                fs["ready"] += 1
            elif issues:
                # Priority: not-implemented / open finding > evidence gap >
                # stale > narrative. Implementing and remediating are the
                # long-lead work, so both land in the first window.
                if status not in SATISFIED:
                    pri, action = 1, "implement"
                elif open_titles:
                    pri, action = 1, "remediate"
                elif "no evidence linked" in issues:
                    pri, action = 2, "evidence"
                elif "evidence is expired" in issues:
                    pri, action = 3, "refresh"
                else:
                    pri, action = 4, "narrative"
                punch.append({
                    "priority": pri,
                    "action": action,
                    "system_id": sid,
                    "system_acronym": system.acronym,
                    "control_id": ctrl.control_id,
                    "control_title": ctrl.title,
                    "family": fam,
                    "status": status,
                    "issues": issues,
                    "owner": (impl.responsible_party if impl and impl.responsible_party else None),
                })

    families = []
    total_ready = total_items = total_na = 0
    for fam, fs in sorted(fam_stat.items()):
        total_ready += fs["ready"]
        total_items += fs["total"]
        total_na += fs["not_applicable"]
        if fs["total"] == 0:
            continue  # every control in the family is scoped out — nothing to ready
        families.append({
            "family": fs["family"],
            "family_name": fs["family_name"],
            "total": fs["total"],
            "ready": fs["ready"],
            "readiness_pct": round(fs["ready"] / fs["total"] * 100, 1) if fs["total"] else 0.0,
            "implemented": fs["implemented"],
            "narrative_gaps": fs["narrative_gaps"],
            "evidence_gaps": fs["evidence_gaps"],
            "stale_evidence": fs["stale_evidence"],
            "open_findings": fs["open_findings"],
            "not_applicable": fs["not_applicable"],
        })

    readiness_score = round(total_ready / total_items * 100, 1) if total_items else 0.0

    punch.sort(key=lambda p: (p["priority"], p["family"], p["control_id"]))

    timeline = _timeline(inspection_date, punch) if inspection_date else []

    return {
        "framework_id": framework_id,
        "system_ids": list(systems.keys()),
        "inspection_date": inspection_date.isoformat() if inspection_date else None,
        "control_count": len(controls),
        "assessed_items": total_items,
        "not_applicable": total_na,
        "readiness_score": readiness_score,
        "families": families,
        "punch_list": punch,
        "timeline": timeline,
    }


def _timeline(inspection_date: date, punch: list[dict]) -> list[dict]:
    """90/60/30-day buckets working back from the inspection date."""
    today = date.today()
    days_out = (inspection_date - today).days
    p1 = [p for p in punch if p["priority"] == 1]
    p2 = [p for p in punch if p["priority"] == 2]
    p3 = [p for p in punch if p["priority"] == 3]
    p4 = [p for p in punch if p["priority"] == 4]
    return [
        {"window": "T-90 to T-60", "focus": "Close implementation gaps & open findings",
         "items": len(p1), "detail": "Stand up the controls that are not yet implemented and remediate open findings — the longest-lead work."},
        {"window": "T-60 to T-30", "focus": "Collect missing evidence",
         "items": len(p2) + len(p3), "detail": "Gather evidence for implemented controls and refresh anything expired."},
        {"window": "T-30 to inspection", "focus": "Tighten narratives & dry run",
         "items": len(p4), "detail": "Flesh out thin control narratives and walk the assessor path end to end."},
        {"window": "status", "focus": f"{days_out} days to inspection" if days_out >= 0 else f"{-days_out} days past inspection date",
         "items": len(punch), "detail": f"{len(punch)} open punch-list items remain."},
    ]

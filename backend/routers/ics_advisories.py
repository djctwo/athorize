from __future__ import annotations

import os
from datetime import UTC, date, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from dependencies import get_current_user, require_can, require_min_role
from models import AuditEntry, ConMonEntry, Finding, Organization, System
from models.ics_advisory import IcsAdvisory, IcsAdvisoryMatch
from models.it_asset import ITAsset
from models.ot_asset import OTAsset
from models.user import User
from schemas import IcsAdvisoryPatch, IcsSpawnConmon, IcsSpawnSystem
from services import audit as audit_svc
from services.sample_advisories import is_real_cve_id, is_sample_id
from services.feed_refresh import refresh_feeds_for_org
from services.feeds_custom import validate_feed_entries
from services.payload import safe_commit
from services.system_scope import system_scope_filter

router = APIRouter()

ENTITY = "ICS_ADVISORY"
VALID_STATUSES = {"NEW", "TRIAGED", "DISMISSED", "REMEDIATED"}
FINDING_SPAWN_LIMIT = 3

SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}

_ADVISORY_TRANSITIONS: dict[str, set[str]] = {
    "NEW": {"TRIAGED", "DISMISSED"},
    "TRIAGED": {"REMEDIATED", "DISMISSED"},
    "DISMISSED": {"NEW", "TRIAGED"},
    "REMEDIATED": set(),
}


def _serialize_advisory(a: IcsAdvisory) -> dict:
    data = {c.name: getattr(a, c.name) for c in a.__table__.columns}
    # Bundled offline/demo advisories are fictional (DEMO- namespace); the UI
    # labels them as sample data so nobody mistakes them for real intel.
    data["is_sample"] = a.source == "MOCK" or is_sample_id(a.advisory_id)
    return data


def _serialize_match(m: IcsAdvisoryMatch) -> dict:
    data = {c.name: getattr(m, c.name) for c in m.__table__.columns}
    data["dismissed"] = bool(m.dismissed)
    if m.ot_asset is not None:
        data["asset_kind"] = "OT"
        data["asset_name"] = m.ot_asset.asset_name
        data["asset_vendor"] = m.ot_asset.vendor
        data["asset_model"] = m.ot_asset.model
        data["asset_firmware"] = m.ot_asset.firmware_version
        data["asset_purdue_level"] = m.ot_asset.purdue_level
    elif m.it_asset is not None:
        data["asset_kind"] = "IT"
        data["asset_name"] = m.it_asset.asset_name
        data["asset_vendor"] = m.it_asset.vendor
        data["asset_model"] = m.it_asset.model
        data["asset_firmware"] = f"{m.it_asset.os_family or ''} {m.it_asset.os_version or ''}".strip()
        data["asset_purdue_level"] = None
    return data


def _advisory_with_matches(
    a: IcsAdvisory, matches: list[IcsAdvisoryMatch], systems_by_id: dict[int, System]
) -> dict:
    # Only matches on systems the caller may see (systems_by_id is already
    # org- and system-scoped): a scoped user must not learn which assets of
    # other systems an advisory hits.
    matches = [m for m in matches if m.system_id in systems_by_id]
    payload = _serialize_advisory(a)
    payload["matches"] = [_serialize_match(m) for m in matches]
    active = [m for m in matches if not m.dismissed]
    payload["match_count"] = len(active)
    payload["system_acronyms"] = sorted(
        {
            systems_by_id[m.system_id].acronym
            for m in active
            if m.system_id in systems_by_id and systems_by_id[m.system_id].acronym
        }
    )
    return payload


def _visible_systems(db: Session, user: User) -> dict[int, System]:
    rows = db.query(System).filter(
        System.organization_id == user.organization_id,
        *system_scope_filter(System.id, db, user),
    ).all()
    return {s.id: s for s in rows}


@router.get("")
def list_advisories(
    severity: str | None = None,
    status: str | None = None,
    system_id: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    q = db.query(IcsAdvisory).filter(IcsAdvisory.organization_id == user.organization_id)
    if severity:
        q = q.filter(IcsAdvisory.severity == severity.upper())
    if status:
        q = q.filter(IcsAdvisory.status == status.upper())
    advisories = q.order_by(IcsAdvisory.published_date.desc().nullslast()).all()

    advisory_ids = [a.id for a in advisories]
    matches_by_advisory: dict[int, list[IcsAdvisoryMatch]] = {i: [] for i in advisory_ids}
    if advisory_ids:
        rows = (
            db.query(IcsAdvisoryMatch)
            .filter(IcsAdvisoryMatch.advisory_id.in_(advisory_ids))
            .all()
        )
        for m in rows:
            matches_by_advisory.setdefault(m.advisory_id, []).append(m)

    systems_by_id = _visible_systems(db, user)

    payload = [
        _advisory_with_matches(a, matches_by_advisory.get(a.id, []), systems_by_id)
        for a in advisories
    ]
    if system_id is not None:
        payload = [
            p for p in payload
            if any(m["system_id"] == system_id and not m["dismissed"] for m in p["matches"])
        ]
    return payload


# NOTE: fixed-path routes must register before /{advisory_id}
@router.get("/feed-status")
def feed_status(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """When the feeds were last pulled for this org, and the schedule config."""
    last = (
        db.query(AuditEntry)
        .filter(
            AuditEntry.organization_id == user.organization_id,
            AuditEntry.entity_type == ENTITY,
            AuditEntry.action == "REFRESH",
        )
        .order_by(AuditEntry.timestamp.desc())
        .first()
    )
    try:
        interval_hours = float(os.getenv("THREAT_FEEDS_INTERVAL_HOURS") or 0)
    except ValueError:
        interval_hours = 0
    org = db.query(Organization).filter(Organization.id == user.organization_id).first()
    custom = ((org.settings or {}).get("custom_feeds") or []) if org else []
    return {
        "last_refreshed": last.timestamp.isoformat() if last else None,
        "last_refreshed_by": last.actor_username if last else None,
        "live": (os.getenv("THREAT_FEEDS") or "mock").strip().lower() == "live",
        "auto_refresh_hours": interval_hours if interval_hours > 0 else None,
        "custom_feeds": [
            {"name": f.get("name"), "url": f.get("url"), "format": f.get("format")}
            for f in custom
        ],
    }


class CustomFeedEntryIn(BaseModel):
    name: str
    url: str
    format: str


class CustomFeedsUpdate(BaseModel):
    feeds: list[CustomFeedEntryIn]


# NOTE: fixed-path routes must register before /{advisory_id}
@router.get("/custom-feeds")
def get_custom_feeds(
    user: User = Depends(require_min_role("admin")),
    db: Session = Depends(get_db),
):
    """Admin-configured custom advisory feed sources for this organization."""
    org = db.query(Organization).filter(Organization.id == user.organization_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")
    return {"feeds": (org.settings or {}).get("custom_feeds") or []}


# NOTE: fixed-path routes must register before /{advisory_id}
@router.put("/custom-feeds")
def update_custom_feeds(
    body: CustomFeedsUpdate,
    user: User = Depends(require_min_role("admin")),
    db: Session = Depends(get_db),
):
    """Replace the org's custom feed list (validated, audit-logged)."""
    try:
        feeds = validate_feed_entries([f.model_dump() for f in body.feeds])
    except ValueError as exc:
        raise HTTPException(422, str(exc))

    org = db.query(Organization).filter(Organization.id == user.organization_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")

    settings = dict(org.settings or {})
    settings["custom_feeds"] = feeds
    org.settings = settings

    names = ", ".join(f["name"] for f in feeds) or "none"
    audit_svc.record(
        db,
        organization_id=user.organization_id,
        actor_id=user.id,
        actor_username=user.username,
        action="UPDATE",
        entity_type="organization",
        entity_id=org.id,
        summary=f"Updated custom advisory feeds ({len(feeds)} configured: {names})",
    )
    safe_commit(db)
    return {"feeds": feeds}


@router.get("/{advisory_id}")
def get_advisory(advisory_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    a = (
        db.query(IcsAdvisory)
        .filter(IcsAdvisory.id == advisory_id, IcsAdvisory.organization_id == user.organization_id)
        .first()
    )
    if not a:
        raise HTTPException(404, "Advisory not found")
    matches = db.query(IcsAdvisoryMatch).filter(IcsAdvisoryMatch.advisory_id == advisory_id).all()
    systems_by_id = _visible_systems(db, user)
    return _advisory_with_matches(a, matches, systems_by_id)


@router.patch("/{advisory_id}", dependencies=[Depends(require_can("edit:conmon"))])
def update_advisory(
    advisory_id: int,
    payload: IcsAdvisoryPatch,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    a = (
        db.query(IcsAdvisory)
        .filter(IcsAdvisory.id == advisory_id, IcsAdvisory.organization_id == user.organization_id)
        .first()
    )
    if not a:
        raise HTTPException(404, "Advisory not found")
    data = payload.model_dump(exclude_unset=True)
    changed = list(data.keys())

    new_status = data.get("status")
    if new_status is not None:
        if new_status not in VALID_STATUSES:
            raise HTTPException(422, f"Invalid status '{new_status}'")
        current = a.status or "NEW"
        if new_status != current:
            allowed = _ADVISORY_TRANSITIONS.get(current, set())
            if new_status not in allowed:
                raise HTTPException(422, f"Invalid advisory status transition from {current} to {new_status}")
        a.status = new_status
        if new_status != "NEW" and not a.triaged_at:
            a.triaged_at = datetime.now(UTC)
            a.triaged_by = user.display_name or user.username

    if "notes" in data:
        a.notes = data["notes"]

    audit_svc.record(
        db,
        organization_id=user.organization_id,
        actor_id=user.id,
        actor_username=user.username,
        action="UPDATE",
        entity_type=ENTITY,
        entity_id=a.id,
        summary=f"{a.advisory_id} ({', '.join(sorted(changed))})",
    )
    safe_commit(db)
    db.refresh(a)
    return _serialize_advisory(a)


@router.post("/refresh", dependencies=[Depends(require_can("edit:conmon"))])
def refresh_advisories(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return refresh_feeds_for_org(
        db, user.organization_id, actor_id=user.id, actor_username=user.username
    )


@router.post("/{advisory_id}/spawn-finding", dependencies=[Depends(require_can("edit:finding"))])
def spawn_finding(
    advisory_id: int,
    payload: IcsSpawnSystem,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    a = (
        db.query(IcsAdvisory)
        .filter(IcsAdvisory.id == advisory_id, IcsAdvisory.organization_id == user.organization_id)
        .first()
    )
    if not a:
        raise HTTPException(404, "Advisory not found")
    system_id = payload.system_id
    system = db.query(System).filter(
        System.id == system_id, System.organization_id == user.organization_id,
        *system_scope_filter(System.id, db, user),
    ).first()
    if not system:
        raise HTTPException(404, "System not found")

    spawn_count = (
        db.query(AuditEntry)
        .filter(
            AuditEntry.action == "SPAWN_FINDING",
            AuditEntry.entity_type == ENTITY,
            AuditEntry.entity_id == a.id,
            AuditEntry.system_id == system_id,
        )
        .count()
    )
    if spawn_count >= FINDING_SPAWN_LIMIT:
        raise HTTPException(
            422,
            f"Advisory already has {spawn_count} findings for this system (limit {FINDING_SPAWN_LIMIT})",
        )

    severity = SEVERITY_MAP.get((a.severity or "").upper(), "MEDIUM")
    due = date.today() + timedelta(days=30 if severity == "CRITICAL" else 90)

    ids = list(a.cve_ids or [])
    real_cves = [i for i in ids if is_real_cve_id(i)]
    other_ids = [i for i in ids if not is_real_cve_id(i)]
    weakness = a.summary or ""
    if real_cves:
        weakness = f"{weakness}\n\nCVE(s): {', '.join(real_cves)}".strip()
    if other_ids:
        # Fictional sample ids (DEMO-…) and other non-CVE references are never
        # presented as CVEs.
        weakness = f"{weakness}\n\nReference ID(s): {', '.join(other_ids)}".strip()
    if a.source_url:
        weakness = f"{weakness}\n\nAdvisory: {a.source_url}".strip()

    finding = Finding(
        organization_id=user.organization_id,
        system_id=system_id,
        framework_id="nist-800-82-r3",
        title=f"{a.advisory_id}: {a.title}",
        weakness_description=weakness,
        severity=severity,
        status="OPEN",
        remediation_plan=a.recommended_mitigations or "",
        due_date=due,
        scheduled_completion=due,
    )
    db.add(finding)
    db.flush()
    audit_svc.record(
        db,
        organization_id=user.organization_id,
        actor_id=user.id,
        actor_username=user.username,
        action="SPAWN_FINDING",
        entity_type=ENTITY,
        entity_id=a.id,
        system_id=system_id,
        summary=f"Spawned Finding {finding.id} from {a.advisory_id}",
    )
    audit_svc.record(
        db,
        organization_id=user.organization_id,
        actor_id=user.id,
        actor_username=user.username,
        action="CREATE",
        entity_type="FINDING",
        entity_id=finding.id,
        system_id=system_id,
        summary=f"{finding.title} (from {a.advisory_id})",
    )
    safe_commit(db)
    db.refresh(finding)
    return {"finding_id": finding.id, "advisory_id": a.id}


@router.post("/{advisory_id}/spawn-conmon", dependencies=[Depends(require_can("edit:conmon"))])
def spawn_conmon(
    advisory_id: int,
    payload: IcsSpawnConmon,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    a = (
        db.query(IcsAdvisory)
        .filter(IcsAdvisory.id == advisory_id, IcsAdvisory.organization_id == user.organization_id)
        .first()
    )
    if not a:
        raise HTTPException(404, "Advisory not found")
    system_id = payload.system_id
    system = db.query(System).filter(
        System.id == system_id, System.organization_id == user.organization_id,
        *system_scope_filter(System.id, db, user),
    ).first()
    if not system:
        raise HTTPException(404, "System not found")

    entry = ConMonEntry(
        organization_id=user.organization_id,
        system_id=system_id,
        entry_date=date.today(),
        activity_type="ICS_CERT_ADVISORY_REVIEW",
        description=f"Reviewed {a.advisory_id}: {a.title}",
        performed_by=user.display_name or user.username,
        findings=payload.findings or a.summary,
        actions_taken=a.recommended_mitigations,
    )
    db.add(entry)
    db.flush()
    audit_svc.record(
        db,
        organization_id=user.organization_id,
        actor_id=user.id,
        actor_username=user.username,
        action="SPAWN_CONMON",
        entity_type=ENTITY,
        entity_id=a.id,
        system_id=system_id,
        summary=f"Logged ConMon {entry.id} from {a.advisory_id}",
    )
    audit_svc.record(
        db,
        organization_id=user.organization_id,
        actor_id=user.id,
        actor_username=user.username,
        action="CREATE",
        entity_type="CONMON",
        entity_id=entry.id,
        system_id=system_id,
        summary=f"ICS advisory review: {a.advisory_id}",
    )
    safe_commit(db)
    db.refresh(entry)
    return {"conmon_id": entry.id, "advisory_id": a.id}


@router.post("/matches/{match_id}/dismiss", dependencies=[Depends(require_can("edit:conmon"))])
def dismiss_match(
    match_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    m = db.query(IcsAdvisoryMatch).filter(IcsAdvisoryMatch.id == match_id).first()
    if not m:
        raise HTTPException(404, "Match not found")
    adv = db.query(IcsAdvisory).filter(IcsAdvisory.id == m.advisory_id).first()
    if not adv or adv.organization_id != user.organization_id:
        raise HTTPException(404, "Match not found")
    m.dismissed = 1
    audit_svc.record(
        db,
        organization_id=user.organization_id,
        actor_id=user.id,
        actor_username=user.username,
        action="DISMISS_MATCH",
        entity_type=ENTITY,
        entity_id=m.advisory_id,
        system_id=m.system_id,
        summary=f"Dismissed match {m.id} (asset {m.ot_asset_id})",
    )
    safe_commit(db)
    db.refresh(m)
    return _serialize_match(m)


@router.post("/matches/{match_id}/restore", dependencies=[Depends(require_can("edit:conmon"))])
def restore_match(
    match_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    m = db.query(IcsAdvisoryMatch).filter(IcsAdvisoryMatch.id == match_id).first()
    if not m:
        raise HTTPException(404, "Match not found")
    adv = db.query(IcsAdvisory).filter(IcsAdvisory.id == m.advisory_id).first()
    if not adv or adv.organization_id != user.organization_id:
        raise HTTPException(404, "Match not found")
    m.dismissed = 0
    audit_svc.record(
        db,
        organization_id=user.organization_id,
        actor_id=user.id,
        actor_username=user.username,
        action="RESTORE_MATCH",
        entity_type=ENTITY,
        entity_id=m.advisory_id,
        system_id=m.system_id,
        summary=f"Restored match {m.id} (asset {m.ot_asset_id})",
    )
    safe_commit(db)
    db.refresh(m)
    return _serialize_match(m)

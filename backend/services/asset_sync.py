"""
Scheduled connector asset sync (Tanium / Cisco ISE).

Set ASSET_SYNC_INTERVAL_HOURS > 0 to pull every env-configured live asset
connector (services/asset_connectors.py) on an interval and import any new
assets automatically. Off by default — self-hosted installs stay quiet until
the operator opts in.

The import path is EXACTLY the manual one: each run reuses the
POST /api/asset-import/connectors/{key}/import/confirm helper
(routers/asset_import._confirm_payload) — fetch → normalize → dedup vs
existing assets (MAC > hostname > name) → validate → insert — so scheduled
and manual pulls can never drift apart.

Target resolution:
  - ASSET_SYNC_ORG_SLUG picks the company on multi-company installs
    (blank = the first company — mirrors OIDC_PROVISION_ORG_SLUG).
  - Assets land in that company's first system (lowest id).

Every run is audit-logged as actor 'asset-sync-scheduler' (action ASSET_SYNC,
plus the standard ASSET_IMPORT entry whenever a connector created assets).
One failing connector never stops the others or the loop.
"""
from __future__ import annotations

import os

from sqlalchemy.orm import Session

ACTOR = "asset-sync-scheduler"

_MAX_ERROR_LEN = 200


def sync_interval_hours() -> float:
    """ASSET_SYNC_INTERVAL_HOURS as a float; 0 (= off) when unset/invalid."""
    try:
        hours = float(os.getenv("ASSET_SYNC_INTERVAL_HOURS") or 0)
    except ValueError:
        return 0.0
    return hours if hours > 0 else 0.0


def sync_status() -> dict:
    """Schedule config for the connectors status endpoint (no secrets)."""
    hours = sync_interval_hours()
    return {
        "enabled": hours > 0,
        "interval_hours": hours if hours > 0 else None,
        "org_slug": (os.getenv("ASSET_SYNC_ORG_SLUG") or "").strip() or None,
    }


def resolve_sync_org(db: Session):
    """Org the scheduled sync imports into — ASSET_SYNC_ORG_SLUG, else the
    first org (single-company default, mirroring OIDC_PROVISION_ORG_SLUG)."""
    from models import Organization

    slug = (os.getenv("ASSET_SYNC_ORG_SLUG") or "").strip()
    org = None
    if slug:
        org = db.query(Organization).filter(Organization.slug == slug).first()
    if org is None:
        org = db.query(Organization).order_by(Organization.id).first()
    return org


def resolve_sync_system(db: Session, org_id: int):
    """Scheduled imports land in the org's first system (lowest id)."""
    from models.system import System

    return (
        db.query(System)
        .filter(System.organization_id == org_id)
        .order_by(System.id)
        .first()
    )


def run_asset_sync(db: Session) -> dict:
    """One scheduler tick: pull each configured connector and import new assets.

    Per-connector fault isolation — a connector that raises is rolled back and
    reported, and the remaining connectors still run. The whole run is
    audit-logged (action ASSET_SYNC, actor 'asset-sync-scheduler').
    """
    from services import audit as audit_svc
    from services.asset_connectors import connector_status, fetch_connector
    # Deliberately the router's confirm helper — the exact code path a manual
    # connector Pull → Confirm uses (dedup, validation, insert, ASSET_IMPORT
    # audit entry). No forked logic.
    from routers.asset_import import _confirm_payload
    from routers.it_assets import ENTITY as IT_ENTITY

    org = resolve_sync_org(db)
    if org is None:
        return {"ran": False, "reason": "no organization exists yet"}
    system = resolve_sync_system(db, org.id)
    if system is None:
        return {"ran": False, "reason": f"org {org.id} has no systems", "organization_id": org.id}

    configured = [c for c in connector_status() if c["configured"]]
    results: dict[str, dict] = {}
    parts: list[str] = []
    for c in configured:
        key = c["key"]
        try:
            rows = fetch_connector(key)
            payload = _confirm_payload(
                db,
                organization_id=org.id,
                actor_id=None,
                actor_username=ACTOR,
                system_id=system.id,
                source=key,
                rows=rows,
            )
            results[key] = {
                "ok": True,
                "created": payload["created"],
                "skipped": payload["skipped"],
                "error_count": payload["error_count"],
            }
            part = f"{key}: +{payload['created']} new, {payload['skipped']} duplicate(s) skipped"
            if payload["error_count"]:
                part += f", {payload['error_count']} row error(s)"
            parts.append(part)
        except Exception as exc:  # one failing connector never stops the rest
            db.rollback()
            err = str(exc)[:_MAX_ERROR_LEN]
            results[key] = {"ok": False, "error": err}
            parts.append(f"{key}: FAILED ({err})")

    summary = "Scheduled asset sync: " + ("; ".join(parts) if parts else "no live connectors configured")
    audit_svc.record(
        db, organization_id=org.id, actor_id=None, actor_username=ACTOR,
        action="ASSET_SYNC", entity_type=IT_ENTITY, system_id=system.id,
        summary=summary,
    )
    db.commit()
    return {
        "ran": True,
        "organization_id": org.id,
        "system_id": system.id,
        "connectors": results,
    }

"""Org-scoped threat-feed refresh — shared by the API endpoint and the
background scheduler.

Pulls every configured feed (CISA ICS + KEV + NVD + AA-series + PSIRT),
upserts advisories with inferred controls, recomputes IT/OT asset matches,
and audit-logs the run. One unreachable feed never kills the rest; failures
are collected and reported in the result.
"""
from __future__ import annotations

import os

from sqlalchemy.orm import Session

from models.ics_advisory import IcsAdvisory, IcsAdvisoryMatch
from models.it_asset import ITAsset
from models.organization import Organization
from models.ot_asset import OTAsset
from services import audit as audit_svc
from services.control_inference import infer_controls
from services.feeds_aa import AaFeedError, fetch_aa
from services.feeds_custom import fetch_custom_feeds
from services.feeds_kev import KevFeedError, fetch_kev
from services.feeds_nvd import NvdFeedError, fetch_nvd
from services.feeds_psirt import PsirtFeedError, fetch_psirt
from services.ics_advisories import match_advisory, match_advisory_it
from services.ics_advisory_cisa import IcsFeedError, fetch_cisa_advisories
from services.ics_advisory_mock import mock_advisories
from services.payload import safe_commit

ENTITY = "ICS_ADVISORY"


def refresh_feeds_for_org(
    db: Session,
    organization_id: int,
    actor_id: int | None,
    actor_username: str,
) -> dict:
    feed_source = (os.getenv("ICS_FEED") or "mock").strip().upper()
    feed_errors: list[str] = []
    # INSTALL.md documents ICS_FEED=live; "CISA" is the original spelling.
    if feed_source in ("CISA", "LIVE"):
        try:
            feed = fetch_cisa_advisories()
            source_tag = "CISA"
        except IcsFeedError as exc:
            feed_errors.append(f"CISA: {exc}")
            feed = []
            source_tag = "CISA"
    else:
        feed = mock_advisories()
        source_tag = "MOCK"

    feeds_live = (os.getenv("THREAT_FEEDS") or "mock").strip().lower() == "live"
    extra_feeds: list[tuple[dict, str]] = []
    for tag, fetcher, err_type in (
        ("CISA_KEV", fetch_kev, KevFeedError),
        ("NVD", fetch_nvd, NvdFeedError),
        ("CISA_AA", fetch_aa, AaFeedError),
        ("PSIRT", fetch_psirt, PsirtFeedError),
    ):
        try:
            extra_feeds.extend((adv, tag) for adv in fetcher(live=feeds_live))
        except err_type as exc:
            feed_errors.append(f"{tag}: {exc}")

    # Admin-configured custom feeds (Organization.settings["custom_feeds"]).
    # Always live (they are explicit URLs, no fixtures exist); each advisory is
    # labeled with the feed's configured name; per-feed errors are reported but
    # never fatal to the refresh.
    org = db.query(Organization).filter(Organization.id == organization_id).first()
    custom_cfg = ((org.settings or {}).get("custom_feeds") or []) if org else []
    if custom_cfg:
        custom_advisories, custom_errors = fetch_custom_feeds(custom_cfg)
        extra_feeds.extend(custom_advisories)
        feed_errors.extend(custom_errors)

    assets = db.query(OTAsset).filter(OTAsset.organization_id == organization_id).all()
    it_assets = db.query(ITAsset).filter(ITAsset.organization_id == organization_id).all()

    upserted = 0
    new_matches = 0
    dropped_matches = 0

    combined = [(adv, source_tag) for adv in feed] + extra_feeds
    for adv, adv_source in combined:
        existing = (
            db.query(IcsAdvisory)
            .filter(
                IcsAdvisory.organization_id == organization_id,
                IcsAdvisory.advisory_id == adv["advisory_id"],
            )
            .first()
        )
        related = infer_controls(adv)
        if existing is None:
            existing = IcsAdvisory(
                **adv, organization_id=organization_id,
                source=adv_source, status="NEW", related_controls=related,
            )
            db.add(existing)
            db.flush()
            upserted += 1
        else:
            for k, v in adv.items():
                setattr(existing, k, v)
            existing.source = adv_source
            existing.related_controls = related
            db.flush()

        computed_ot = {m["ot_asset_id"]: m for m in match_advisory(adv, assets)}
        computed_it = {m["it_asset_id"]: m for m in match_advisory_it(adv, it_assets)}

        current = (
            db.query(IcsAdvisoryMatch)
            .filter(IcsAdvisoryMatch.advisory_id == existing.id)
            .all()
        )
        current_ot = {m.ot_asset_id: m for m in current if m.ot_asset_id is not None}
        current_it = {m.it_asset_id: m for m in current if m.it_asset_id is not None}

        for asset_id, row in computed_ot.items():
            if asset_id in current_ot:
                current_ot[asset_id].confidence = row["confidence"]
                current_ot[asset_id].system_id = row["system_id"]
            else:
                db.add(IcsAdvisoryMatch(
                    advisory_id=existing.id, ot_asset_id=asset_id,
                    system_id=row["system_id"], confidence=row["confidence"],
                ))
                new_matches += 1
        for asset_id, row in computed_it.items():
            if asset_id in current_it:
                current_it[asset_id].confidence = row["confidence"]
                current_it[asset_id].system_id = row["system_id"]
            else:
                db.add(IcsAdvisoryMatch(
                    advisory_id=existing.id, it_asset_id=asset_id,
                    system_id=row["system_id"], confidence=row["confidence"],
                ))
                new_matches += 1

        for asset_id, row in current_ot.items():
            if asset_id not in computed_ot:
                db.delete(row)
                dropped_matches += 1
        for asset_id, row in current_it.items():
            if asset_id not in computed_it:
                db.delete(row)
                dropped_matches += 1

    audit_svc.record(
        db,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_username=actor_username,
        action="REFRESH",
        entity_type=ENTITY,
        summary=(
            f"Refreshed {len(combined)} feed items ({source_tag} + KEV/NVD/AA/PSIRT"
            + (f" + {len(custom_cfg)} custom" if custom_cfg else "")
            + f") · +{new_matches} matches · -{dropped_matches} stale"
            + (f" · feed errors: {len(feed_errors)}" if feed_errors else "")
        ),
    )
    safe_commit(db)
    return {
        "feed_source": f"{source_tag}+KEV+NVD+AA+PSIRT"
        + (f"+{len(custom_cfg)}xCUSTOM" if custom_cfg else ""),
        "feed_errors": feed_errors,
        "advisories_refreshed": len(combined),
        "advisories_new_or_updated": upserted,
        "matches_new": new_matches,
        "matches_dropped": dropped_matches,
    }

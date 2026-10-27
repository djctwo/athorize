from fastapi.concurrency import run_in_threadpool
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session
from database import get_db
from models.user import User
from models.system import System
from models.it_asset import ITAsset
from dependencies import get_current_user, require_can
from services import audit as audit_svc
from services.bulk_import import run_bulk_import
from services.asset_import import (
    SUPPORTED_SOURCES, MAX_FILE_SIZE, AssetIdentityIndex, detect_source, parse_assets_report,
)
from services.import_common import ImportFileError, RowReport, decode_text, read_upload_capped
# Reuse the IT-asset import validation (enum + required-field checks) so asset
# sources go through the exact same gate as manual CSV bulk import.
from routers.it_assets import _validate_import_row, ENTITY as IT_ENTITY

router = APIRouter()


def _require_system(db: Session, user, system_id: int) -> None:
    from services.system_scope import system_scope_filter

    if not db.query(System).filter(
        System.id == system_id, System.organization_id == user.organization_id,
        *system_scope_filter(System.id, db, user),
    ).first():
        raise HTTPException(404, "System not found")


def _decode_and_parse(raw: bytes, filename: str, source_override: str) -> tuple[str, RowReport]:
    try:
        notes: list[str] = []
        content = decode_text(raw, notes)
        source = source_override.strip() or detect_source(filename, content[:2000])
        if not source:
            raise HTTPException(422, "Could not detect asset source. Please specify source_override (tanium_csv or cisco_ise_csv).")
        if source not in {s["key"] for s in SUPPORTED_SOURCES}:
            raise HTTPException(422, f"Unknown asset source: {source}")
        rep = parse_assets_report(content, source)
        rep.notes.extend(notes)
        return source, rep
    except ImportFileError as exc:
        raise HTTPException(422, str(exc))


async def _read_and_parse(file: UploadFile, source_override: str) -> tuple[str, RowReport]:
    raw = await read_upload_capped(file, MAX_FILE_SIZE)
    # CPU-bound parse off the event loop (R2SEC-4).
    source, rep = await run_in_threadpool(_decode_and_parse, raw, file.filename or "upload.csv", source_override)
    if not rep.rows:
        detail = "No assets found in file."
        if rep.skipped:
            detail += " " + rep.skip_text() + "."
        raise HTTPException(422, detail + " Check the source/columns.")
    return source, rep


def _existing_index(db: Session, org_id: int, system_id: int) -> AssetIdentityIndex:
    """Identities (MAC and hostname) of the assets already in this system."""
    index = AssetIdentityIndex()
    for a in db.query(ITAsset).filter(
        ITAsset.organization_id == org_id, ITAsset.system_id == system_id
    ).all():
        index.add(a.mac_address or "", a.hostname or a.asset_name or "", a.asset_name or "", a)
    return index


def _mark_duplicates(rows: list[dict], existing: AssetIdentityIndex) -> list[dict]:
    """Flag rows already present (vs the DB) or repeated within the same file.
    A row matching an existing asset carries it under '_match' so the confirm
    step can fill in a MAC the existing record lacks."""
    seen = AssetIdentityIndex()
    marked: list[dict] = []
    for r in rows:
        ident = (r.get("mac_address", ""), r.get("hostname", ""), r.get("asset_name", ""))
        in_db, asset = existing.match(*ident)
        is_dup = in_db or seen.match(*ident)[0]
        seen.add(*ident)
        marked.append({**r, "is_duplicate": is_dup, "_match": asset})
    return marked


_INTERNAL = ("_dedup", "_match", "is_duplicate")


def _named_errors(errors: list[dict], rows: list[dict]) -> list[dict]:
    """run_bulk_import indexes errors by position in the rows it was given;
    attach the asset name so the user can find the row in their file."""
    out = []
    for e in errors[:100]:
        idx = e.get("row")
        name = rows[idx].get("asset_name", "") if isinstance(idx, int) and 0 <= idx < len(rows) else ""
        out.append({**e, "asset_name": name})
    return out


def _report_fields(rep: RowReport | None) -> dict:
    if rep is None:
        return {"skipped_rows": 0, "skip_reasons": {}, "truncated": False, "truncated_count": 0, "warnings": []}
    return {**rep.summary(), "warnings": rep.warnings("assets")}


def _preview_payload(db: Session, org_id: int, system_id: int, source: str, rows: list[dict],
                     rep: RowReport | None = None) -> dict:
    """Shared preview: dedup-mark parsed rows + run the IT-asset validation gate.
    Used by both the file-upload and live-connector paths."""
    marked = _mark_duplicates(rows, _existing_index(db, org_id, system_id))
    fresh = [r for r in marked if not r["is_duplicate"]]
    validation = run_bulk_import(
        db, organization_id=org_id, system_id=system_id,
        rows=[{k: v for k, v in r.items() if k not in _INTERNAL} for r in fresh],
        commit=False, system_model=System, record_model=ITAsset, validate_row=_validate_import_row,
    )
    new_count = len(fresh)
    return {
        "source": source,
        "total_parsed": len(marked),
        "new_count": new_count,
        "duplicate_count": len(marked) - new_count,
        "valid_count": validation["valid_count"],
        "error_count": validation["error_count"],
        "errors": _named_errors(validation["errors"], fresh),
        **_report_fields(rep),
        "preview": [{k: v for k, v in r.items() if k not in ("_dedup", "_match")} for r in marked[:100]],
        "system_id": system_id,
    }


def _confirm_payload(
    db: Session, *, organization_id: int, actor_id: int | None, actor_username: str,
    system_id: int, source: str, rows: list[dict], rep: RowReport | None = None,
) -> dict:
    """Shared confirm: insert non-duplicate, valid rows; audit; return counts.
    Used by the manual endpoints (actor = the requesting user) and by the
    scheduled sync (services/asset_sync.py, actor = 'asset-sync-scheduler')."""
    marked = _mark_duplicates(rows, _existing_index(db, organization_id, system_id))
    fresh = [
        {k: v for k, v in r.items() if k not in _INTERNAL}
        for r in marked if not r["is_duplicate"]
    ]
    skipped = len(marked) - len(fresh)
    # A known host seen with its MAC for the first time (e.g. Tanium without a
    # MAC column, then Cisco ISE): record the MAC on the existing asset.
    enriched = 0
    for r in marked:
        asset = r["_match"]
        if asset is not None and not asset.mac_address and r.get("mac_address"):
            asset.mac_address = r["mac_address"]
            enriched += 1
    result = run_bulk_import(
        db, organization_id=organization_id, system_id=system_id,
        rows=fresh, commit=True,
        system_model=System, record_model=ITAsset, validate_row=_validate_import_row,
    )
    created = result.get("committed", 0)
    if created or enriched:
        audit_svc.record(
            db, organization_id=organization_id, actor_id=actor_id,
            actor_username=actor_username, action="ASSET_IMPORT", entity_type=IT_ENTITY,
            system_id=system_id,
            summary=f"Asset import ({source}): {created} IT assets created, {skipped} duplicates skipped"
                    + (f", MAC address added to {enriched} existing asset(s)" if enriched else ""),
        )
        db.commit()
    return {
        "source": source,
        "created": created,
        "skipped": skipped,
        "mac_added": enriched,
        "error_count": result.get("error_count", 0),
        "errors": _named_errors(result.get("errors", []), fresh),
        "total_parsed": len(marked),
        **_report_fields(rep),
    }


@router.get("/sources")
def list_sources(user: User = Depends(get_current_user)):
    return SUPPORTED_SOURCES


@router.post("/import")
async def preview_import(
    file: UploadFile = File(...),
    system_id: int = Form(...),
    source_override: str = Form(""),
    user: User = Depends(require_can("edit:system")),
    db: Session = Depends(get_db),
):
    _require_system(db, user, system_id)
    source, rep = await _read_and_parse(file, source_override)
    return _preview_payload(db, user.organization_id, system_id, source, rep.rows, rep)


@router.post("/import/confirm")
async def confirm_import(
    file: UploadFile = File(...),
    system_id: int = Form(...),
    source_override: str = Form(""),
    user: User = Depends(require_can("edit:system")),
    db: Session = Depends(get_db),
):
    _require_system(db, user, system_id)
    source, rep = await _read_and_parse(file, source_override)
    return _confirm_payload(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, system_id=system_id, source=source, rows=rep.rows, rep=rep,
    )


# --- Live API connectors (Tanium, Cisco ISE) -------------------------------
# Connector credentials are install-wide env settings that reach ONE company's
# endpoint estate. They belong to the company the scheduled sync targets
# (ASSET_SYNC_ORG_SLUG, else the first company) — on a multi-company install
# no other company's admin may pull that inventory into their own systems
# (SECCODE-13). Instance operators may use them from any company.

_OTHER_COMPANY_NOTE = "Configured for another company on this install"


def _connectors_usable_by(db: Session, user: User) -> bool:
    from services.asset_sync import resolve_sync_org
    if getattr(user, "is_operator", False):
        return True
    org = resolve_sync_org(db)
    return org is not None and org.id == user.organization_id


def _require_connector_access(db: Session, user: User) -> None:
    if not _connectors_usable_by(db, user):
        raise HTTPException(403, "Live connectors on this install belong to another company")


@router.get("/connectors")
def list_connectors(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Connector configuration + the scheduled-sync mode (mirrors the
    advisories /feed-status pattern): auto-sync every Nh vs manual only."""
    from models.audit import AuditEntry
    from services.asset_connectors import connector_status
    from services.asset_sync import ACTOR as SYNC_ACTOR, sync_status

    last = (
        db.query(AuditEntry)
        .filter(
            AuditEntry.organization_id == user.organization_id,
            AuditEntry.action == "ASSET_SYNC",
            AuditEntry.actor_username == SYNC_ACTOR,
        )
        .order_by(AuditEntry.timestamp.desc())
        .first()
    )
    sync = sync_status()
    # Timezone-aware UTC ISO string, like every other API timestamp.
    sync["last_synced"] = last.timestamp.isoformat() if last else None
    connectors = connector_status()
    if not _connectors_usable_by(db, user):
        for c in connectors:
            c["configured"] = False
            c["note"] = _OTHER_COMPANY_NOTE
        sync = {**sync, "enabled": False, "org_slug": None}
    return {"connectors": connectors, "sync": sync}


def _fetch_connector(key: str) -> list[dict]:
    from services.asset_connectors import fetch_connector, ConnectorError
    try:
        rows = fetch_connector(key)
    except ConnectorError as exc:
        raise HTTPException(400, str(exc))
    if not rows:
        raise HTTPException(422, "Connector returned no assets")
    return rows


@router.post("/connectors/{key}/import")
def preview_connector(
    key: str,
    system_id: int = Form(...),
    user: User = Depends(require_can("edit:system")),
    db: Session = Depends(get_db),
):
    _require_connector_access(db, user)
    _require_system(db, user, system_id)
    rows = _fetch_connector(key)
    return _preview_payload(db, user.organization_id, system_id, key, rows)


@router.post("/connectors/{key}/import/confirm")
def confirm_connector(
    key: str,
    system_id: int = Form(...),
    user: User = Depends(require_can("edit:system")),
    db: Session = Depends(get_db),
):
    _require_connector_access(db, user)
    _require_system(db, user, system_id)
    rows = _fetch_connector(key)
    return _confirm_payload(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, system_id=system_id, source=key, rows=rows,
    )


@router.get("/history")
def import_history(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    from models.audit import AuditEntry
    from services.system_scope import audit_scope_filter
    entries = db.query(AuditEntry).filter(
        AuditEntry.organization_id == user.organization_id,
        AuditEntry.action == "ASSET_IMPORT",
        *audit_scope_filter(db, user),
    ).order_by(AuditEntry.timestamp.desc()).limit(50).all()
    return [
        {
            "id": e.id,
            "actor": e.actor_username,
            "summary": e.summary,
            "system_id": e.system_id,
            "created_at": e.timestamp.isoformat() if e.timestamp else None,
        }
        for e in entries
    ]

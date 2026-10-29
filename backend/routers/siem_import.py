from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session
from database import get_db
from models.user import User
from models.finding import Finding
from models.system import System
from dependencies import get_current_user, require_can
from services import audit as audit_svc
from services.payload import safe_commit
from services.control_catalog import require_active_framework
from services.import_common import ImportFileError, decode_text, read_upload_capped
from services.siem_import import (
    SUPPORTED_FORMATS, MAX_FILE_SIZE, FORMAT_LABELS, ParseReport, describe_unrecognized, detect_format,
    parse_file_report,
)
from services.system_scope import system_scope_filter, system_scope_filter_nullable, require_system_allowed

router = APIRouter()


@router.get("/formats")
def list_formats(user: User = Depends(get_current_user)):
    return SUPPORTED_FORMATS


def _require_system(db: Session, user: User, system_id: int) -> None:
    if not db.query(System).filter(
        System.id == system_id, System.organization_id == user.organization_id, *system_scope_filter(System.id, db, user)
    ).first():
        raise HTTPException(404, "System not found")


def _decode_and_parse(raw: bytes, filename: str, format_override: str) -> tuple[str, ParseReport]:
    try:
        notes: list[str] = []
        content = decode_text(raw, notes)
        fmt = format_override.strip() or detect_format(filename, content)
        if not fmt:
            raise HTTPException(
                422,
                "Could not detect the file format; nothing was imported."
                + describe_unrecognized(filename, content)
                + " Choose the format under Format Override if it is listed.",
            )
        if fmt not in FORMAT_LABELS:
            raise HTTPException(422, f"Unknown format: {fmt}")
        rep = parse_file_report(content, fmt)
        rep.notes.extend(notes)
        return fmt, rep
    except ImportFileError as exc:
        raise HTTPException(422, str(exc))


async def _parse_upload(file: UploadFile, format_override: str) -> tuple[str, ParseReport]:
    """Bounded read → decode → detect → parse. Every failure is a 4xx with a
    message the user can act on; an empty result says what was skipped and why."""
    raw = await read_upload_capped(file, MAX_FILE_SIZE)
    # Decoding and parsing a 16 MiB file is CPU work: run it off the event
    # loop so one upload never stalls every other request (R2SEC-4).
    fmt, rep = await run_in_threadpool(_decode_and_parse, raw, file.filename or "upload.txt", format_override)
    if not rep.rows:
        detail = f"No alerts found in file (read as {FORMAT_LABELS[fmt]})."
        if rep.skipped:
            detail += " " + rep.skip_text() + "."
        detail += " Check the format, or choose it under Format Override."
        raise HTTPException(422, detail)
    return fmt, rep


def _existing_hashes(db: Session, org_id: int, system_id: int) -> set[str]:
    hashes: set[str] = set()
    for (ed,) in db.query(Finding.extra_data).filter(
        Finding.organization_id == org_id, Finding.system_id == system_id,
    ).all():
        if isinstance(ed, dict) and ed.get("dedup_hash"):
            hashes.add(ed["dedup_hash"])
    return hashes


@router.post("/import")
async def import_file(
    file: UploadFile = File(...),
    system_id: int = Form(...),
    framework_id: str = Form(...),
    format_override: str = Form(""),
    user: User = Depends(require_can("edit:finding")),
    db: Session = Depends(get_db),
):
    _require_system(db, user, system_id)
    require_active_framework(db, user.organization_id, framework_id)
    fmt, rep = await _parse_upload(file, format_override)
    existing = _existing_hashes(db, user.organization_id, system_id)
    preview = [
        {**item, "is_duplicate": item["extra_data"].get("dedup_hash", "") in existing}
        for item in rep.rows
    ]
    new_count = sum(1 for p in preview if not p["is_duplicate"])
    return {
        "format": fmt,
        "total_parsed": len(preview),
        "new_count": new_count,
        "duplicate_count": len(preview) - new_count,
        **rep.summary(),
        "warnings": rep.warnings(),
        "preview": preview[:100],
        "system_id": system_id,
        "framework_id": framework_id,
    }


@router.post("/import/confirm")
async def confirm_import(
    file: UploadFile = File(...),
    system_id: int = Form(...),
    framework_id: str = Form(...),
    format_override: str = Form(""),
    user: User = Depends(require_can("edit:finding")),
    db: Session = Depends(get_db),
):
    _require_system(db, user, system_id)
    require_active_framework(db, user.organization_id, framework_id)
    fmt, rep = await _parse_upload(file, format_override)
    existing = _existing_hashes(db, user.organization_id, system_id)

    created = 0
    skipped = 0  # already imported into this system earlier
    for item in rep.rows:
        ed = item.get("extra_data", {})
        h = ed.get("dedup_hash", "")
        if h in existing:
            skipped += 1
            continue
        if h:
            existing.add(h)
        db.add(Finding(
            organization_id=user.organization_id,
            system_id=system_id,
            framework_id=framework_id,
            title=item["title"],
            description=item.get("description", ""),
            weakness_description=item.get("weakness_description", ""),
            severity=item["severity"],
            status="OPEN",
            extra_data=ed,
        ))
        created += 1

    stats = rep.summary()
    if created:
        extra = []
        if stats["merged_duplicates"]:
            extra.append(f"{stats['merged_duplicates']} repeated rows merged")
        if stats["skipped_rows"]:
            extra.append(f"{stats['skipped_rows']} rows skipped")
        if stats["truncated_count"]:
            extra.append(f"{stats['truncated_count']} not imported (row limit)")
        audit_svc.record(
            db, organization_id=user.organization_id, actor_id=user.id,
            actor_username=user.username, action="SIEM_IMPORT",
            entity_type="finding", system_id=system_id,
            summary=f"SIEM import ({fmt}): {created} findings created, {skipped} duplicates skipped"
                    + (f" ({', '.join(extra)})" if extra else ""),
        )
        safe_commit(db)

    return {
        "format": fmt,
        "created": created,
        "skipped": skipped,
        "total_parsed": len(rep.rows),
        **stats,
        "warnings": rep.warnings(),
    }


@router.get("/import/history")
def import_history(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from models.audit import AuditEntry
    from services.system_scope import audit_scope_filter
    entries = db.query(AuditEntry).filter(
        AuditEntry.organization_id == user.organization_id,
        AuditEntry.action == "SIEM_IMPORT",
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

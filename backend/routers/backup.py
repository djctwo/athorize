"""Instance backup & restore.

A backup is the ENTIRE instance — every company's database rows (including
password hashes), all evidence files and the custom frameworks — and a restore
replaces all of it. Both are therefore limited to the instance operator: an
admin who is an operator, or the admin of a single-company install (where the
company admin already is the whole instance). An admin of one company in a
multi-company install must not be able to read or overwrite the others.

Restore is destructive — it requires a one-time nonce issued by GET /info plus
CSRF, and it keeps a timestamped rollback copy of what it replaced.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from database import get_db
from dependencies import require_role
from models.organization import Organization
from models.user import User
from services import audit as audit_svc
from services import backup as backup_svc

router = APIRouter()

_MAX_RESTORE_BYTES = backup_svc.MAX_RESTORE_UPLOAD_BYTES


def require_instance_operator(
    user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> User:
    if user.is_operator:
        return user
    if db.query(Organization.id).limit(2).count() <= 1:
        return user  # single-company install: its admin is the instance admin
    raise HTTPException(
        403,
        "Backups contain every company on this instance, so only an instance operator can "
        "back up or restore.",
    )


def _error_status(exc: backup_svc.BackupError) -> int:
    return 409 if isinstance(exc, backup_svc.BackupBusy) else 400


@router.get("/info")
def backup_info(user: User = Depends(require_instance_operator)):
    """Current data size + last backup, plus a one-time restore nonce."""
    return backup_svc.backup_info()


@router.post("/download")
def download_backup(
    passphrase: str = Form(""),
    user: User = Depends(require_instance_operator),
    db: Session = Depends(get_db),
):
    """Create a verified archive of the DB + evidence + custom frameworks and
    stream it back. An optional passphrase produces an AES-encrypted archive
    (.tar.gz.enc). A copy is also kept in the backups directory."""
    try:
        result = backup_svc.create_backup(passphrase or None)
    except backup_svc.BackupError as exc:
        raise HTTPException(_error_status(exc), str(exc)) from exc
    m = result.manifest
    audit_svc.record(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, action="BACKUP", entity_type="system",
        summary=f"Created backup {result.filename} ({result.size} bytes, "
                f"{'encrypted' if passphrase else 'unencrypted'}; {m['evidence_file_count']} evidence files, "
                f"{m['custom_framework_count']} custom frameworks"
                + (f"; {m['missing_evidence_files']} evidence record(s) without a file" if m.get("missing_evidence_files") else "")
                + ")",
    )
    db.commit()
    notes = list(result.warnings)
    if result.size > _MAX_RESTORE_BYTES:
        notes.append(
            "This backup is larger than the in-app restore limit; restore it with "
            "'python -m services.backup restore' (docs/INSTALL.md section 10)."
        )
    # Header values must be latin-1; the notes are plain ASCII apart from the ellipsis.
    headers = {"X-Backup-Warning": " ".join(notes).replace("…", "...")} if notes else {}
    return FileResponse(
        str(result.path), media_type="application/octet-stream", filename=result.filename, headers=headers,
    )


@router.post("/restore")
async def restore_backup(
    file: UploadFile = File(...),
    nonce: str = Form(...),
    passphrase: str = Form(""),
    user: User = Depends(require_instance_operator),
    db: Session = Depends(get_db),
):
    """Replace the DB + evidence (+ custom frameworks) from an uploaded archive.

    Requires a one-time nonce from GET /info (confirms the operator just
    reviewed the destructive action). Keeps a rollback copy of the replaced
    data. Every session in the restored data is signed out and every API token
    in it is revoked."""
    if not backup_svc.consume_restore_nonce(nonce):
        raise HTTPException(409, "Invalid or expired confirmation. Reload the backup panel and try again.")

    blob = await file.read(_MAX_RESTORE_BYTES + 1)
    if len(blob) > _MAX_RESTORE_BYTES:
        raise HTTPException(
            413,
            f"Backup archive exceeds the in-app restore limit ({_MAX_RESTORE_BYTES // (1024 * 1024)} MB). "
            "Restore it with 'python -m services.backup restore' (docs/INSTALL.md section 10).",
        )
    if not blob:
        raise HTTPException(400, "Empty upload.")

    # Audit the attempt in the CURRENT database (kept in the rollback copy). The
    # restored database gets its own RESTORE entry for every company.
    audit_svc.record(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, action="RESTORE", entity_type="system",
        summary=f"Restore initiated from {file.filename} ({len(blob)} bytes)",
    )
    db.commit()

    try:
        result = await run_in_threadpool(
            backup_svc.restore_from_bytes, blob, passphrase or None,
            actor={"username": user.username, "user_id": user.id}, source_name=file.filename,
        )
    except backup_svc.BackupError as exc:
        audit_svc.record(
            db, organization_id=user.organization_id, actor_id=user.id,
            actor_username=user.username, action="RESTORE_FAILED", entity_type="system",
            summary=f"Restore from {file.filename} refused, nothing changed: {exc}"[:1000],
        )
        db.commit()
        raise HTTPException(_error_status(exc), str(exc)) from exc

    tokens = result["api_tokens_revoked"]
    note = (
        "Restore complete. Everyone was signed out, including you — sign in again with the "
        "passwords from when the backup was taken."
    )
    if tokens:
        note += f" {tokens} API token(s) from the backup were revoked; issue new API tokens for integrations."
    else:
        note += " Any API tokens in the backup were revoked."
    return {
        "restored_db": result["restored_db"],
        "restored_evidence_files": result["restored_evidence_files"],
        "restored_custom_frameworks": result["restored_custom_frameworks"],
        "rollback_path": result["rollback_path"],
        "sessions_revoked": result["sessions_revoked"],
        "api_tokens_revoked": tokens,
        "audit_key_matches": result["audit_key_matches"],
        "warnings": result["warnings"],
        "note": note,
    }

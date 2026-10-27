import hashlib
import logging
import uuid
from datetime import date, timedelta
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from database import get_db
from models.user import User
from models.system import System
from models.evidence import EvidenceArtifact
from schemas import EvidenceUpdate
from dependencies import get_current_user, require_can, require_min_role
from services import audit as audit_svc
from config import settings
from services.system_scope import system_scope_filter, system_scope_filter_nullable, require_system_allowed
from services.import_common import save_upload_capped
from services.evidence_store import resolve_evidence_path
from services.control_catalog import require_known_controls

router = APIRouter()
_log = logging.getLogger(__name__)

MAX_EVIDENCE_SIZE = 100 * 1024 * 1024  # 100 MiB
ALLOWED_EXTENSIONS = {
    ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".csv", ".txt", ".json", ".xml", ".yaml", ".yml",
    ".zip", ".tar", ".gz", ".7z",
    ".eml", ".msg",
}
MAX_EXPIRATION_DAYS = 3650  # 10 years


def _check_expiry_date(expiry: date, collected: date) -> None:
    """An explicit expiry may be in the past (recording evidence that is already
    stale) but stays within the same 10-year window as expiration_days."""
    if abs((expiry - collected).days) > MAX_EXPIRATION_DAYS:
        raise HTTPException(422, "Expiration date must be within 10 years of the collection date")
_MAX_LINKED_IDS = 500


def _id_list(raw: str, field: str) -> list[str]:
    """control_ids / framework_ids form field: a JSON array of non-empty strings.
    Anything else is a 422 — a stray int or object here used to break the
    evidence export and the Audit Binder for the whole system."""
    import json

    if not (raw or "").strip():
        return []
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(422, f"{field} must be a JSON array of strings, e.g. [\"AC-2\"]")
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise HTTPException(422, f"{field} must be a JSON array of strings, e.g. [\"AC-2\"]")
    if len(value) > _MAX_LINKED_IDS:
        raise HTTPException(422, f"{field} lists more than {_MAX_LINKED_IDS} ids")
    cleaned = [v.strip()[:100] for v in value if v.strip()]
    return list(dict.fromkeys(cleaned))


@router.get("")
def list_evidence(
    system_id: int | None = None,
    framework_id: str | None = None,
    owner_id: int | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(EvidenceArtifact).filter(EvidenceArtifact.organization_id == user.organization_id, *system_scope_filter(EvidenceArtifact.system_id, db, user))
    if system_id:
        q = q.filter(EvidenceArtifact.system_id == system_id)
    if framework_id:
        q = q.filter(EvidenceArtifact.framework_ids.contains(framework_id))
    if owner_id:
        q = q.filter(EvidenceArtifact.owner_id == owner_id)
    rows = q.order_by(EvidenceArtifact.created_at.desc()).all()

    # Attach the refresh owner's display name so the list can render an Owner
    # column without a per-row user lookup client-side.
    owner_ids = {r.owner_id for r in rows if r.owner_id}
    owner_names: dict[int, str] = {}
    if owner_ids:
        for uid, display_name, username in db.query(User.id, User.display_name, User.username).filter(
            User.id.in_(owner_ids), User.organization_id == user.organization_id,
        ):
            owner_names[uid] = display_name or username

    out = []
    for r in rows:
        d = {c.name: getattr(r, c.name) for c in EvidenceArtifact.__table__.columns}
        d["owner_name"] = owner_names.get(r.owner_id) if r.owner_id else None
        out.append(d)
    return out


@router.post("/upload")
async def upload_evidence(
    system_id: int = Form(...),
    description: str = Form(""),
    artifact_type: str = Form("OTHER"),
    control_ids: str = Form("[]"),
    framework_ids: str = Form("[]"),
    expiration_days: int = Form(365, ge=1, le=MAX_EXPIRATION_DAYS),
    expiration_date: date | None = Form(None),
    file: UploadFile = File(...),
    user: User = Depends(require_can("upload:evidence")),
    db: Session = Depends(get_db),
):
    if not db.query(System).filter(
        System.id == system_id, System.organization_id == user.organization_id, *system_scope_filter(System.id, db, user)
    ).first():
        raise HTTPException(404, "System not found")

    original_name = Path(file.filename or "upload").name
    ext = Path(original_name).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(415, f"File type '{ext}' not allowed")

    # Validate every field BEFORE anything touches the disk, so a rejected
    # upload never leaves an orphan file behind.
    if expiration_date is not None:
        _check_expiry_date(expiration_date, date.today())
        expiration_days = max(1, (expiration_date - date.today()).days)
    ctrl_ids = _id_list(control_ids, "control_ids")
    fw_ids = _id_list(framework_ids, "framework_ids")
    ctrl_ids = require_known_controls(db, user.organization_id, ctrl_ids, fw_ids)

    safe_name = f"{uuid.uuid4().hex}{ext}"
    evidence_dir = settings.evidence_dir / str(system_id)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    file_path = evidence_dir / safe_name
    if not file_path.resolve().is_relative_to(evidence_dir.resolve()):
        raise HTTPException(400, "Invalid file path")
    # Streamed to disk in bounded chunks (hashing as it goes) — never the
    # whole upload in memory, and a 413 the moment it passes the cap.
    file_hash = await save_upload_capped(file, file_path, MAX_EVIDENCE_SIZE)

    artifact = EvidenceArtifact(
        organization_id=user.organization_id,
        system_id=system_id,
        filename=file.filename,
        description=description,
        artifact_type=artifact_type,
        control_ids=ctrl_ids,
        framework_ids=fw_ids,
        date_collected=date.today(),
        expiration_date=expiration_date or date.today() + timedelta(days=expiration_days),
        expiration_days=expiration_days,
        uploaded_by_id=user.id,
        file_path=file_path.relative_to(settings.evidence_dir).as_posix(),  # portable (R2INSTALL-12)
        file_hash=file_hash,
    )
    try:
        db.add(artifact)
        db.flush()
        audit_svc.record(db, organization_id=user.organization_id, actor_id=user.id,
                         actor_username=user.username, action="UPLOAD", entity_type="evidence",
                         entity_id=artifact.id, system_id=system_id,
                         summary=f"Uploaded: {file.filename}")
        db.commit()
    except Exception:
        db.rollback()
        file_path.unlink(missing_ok=True)
        raise
    db.refresh(artifact)
    return artifact


@router.get("/{evidence_id}")
def get_evidence(evidence_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    artifact = db.query(EvidenceArtifact).filter(
        EvidenceArtifact.id == evidence_id,
        EvidenceArtifact.organization_id == user.organization_id, *system_scope_filter(EvidenceArtifact.system_id, db, user),
    ).first()
    if not artifact:
        raise HTTPException(404, "Evidence not found")
    return artifact


@router.get("/{evidence_id}/download")
def download_evidence(evidence_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Stream one stored evidence file back to anyone who may read the artifact
    (same org + system scope as GET /{id}). Always an attachment with a generic
    content type + nosniff, so an uploaded .svg/.xml can never render inline in
    the app's origin. The SHA-256 recorded at upload is re-checked first: a file
    that no longer matches is refused rather than handed out as genuine."""
    artifact = db.query(EvidenceArtifact).filter(
        EvidenceArtifact.id == evidence_id,
        EvidenceArtifact.organization_id == user.organization_id, *system_scope_filter(EvidenceArtifact.system_id, db, user),
    ).first()
    if not artifact:
        raise HTTPException(404, "Evidence not found")
    path = resolve_evidence_path(artifact.file_path)
    if path is None or not path.is_file():
        raise HTTPException(404, "No file is stored for this evidence record")

    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    if artifact.file_hash and digest.hexdigest() != artifact.file_hash:
        raise HTTPException(409, "The stored file no longer matches the SHA-256 recorded at upload "
                                 "— it may have been altered on disk. Download refused.")

    audit_svc.record(db, organization_id=user.organization_id, actor_id=user.id,
                     actor_username=user.username, action="EXPORT", entity_type="evidence",
                     entity_id=artifact.id, system_id=artifact.system_id,
                     summary=f"Downloaded: {artifact.filename}")
    db.commit()
    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename=Path(artifact.filename or path.name).name or path.name,
        headers={
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "Cache-Control": "no-store",
        },
    )


@router.patch("/{evidence_id}")
def update_evidence(evidence_id: int, req: EvidenceUpdate, user: User = Depends(require_can("upload:evidence")), db: Session = Depends(get_db)):
    artifact = db.query(EvidenceArtifact).filter(
        EvidenceArtifact.id == evidence_id,
        EvidenceArtifact.organization_id == user.organization_id, *system_scope_filter(EvidenceArtifact.system_id, db, user),
    ).first()
    if not artifact:
        raise HTTPException(404, "Evidence not found")

    # An assigned refresh owner must be an active user in the caller's org.
    if "owner_id" in req.model_fields_set and req.owner_id is not None:
        ok = db.query(User).filter(
            User.id == req.owner_id,
            User.organization_id == user.organization_id,
            User.is_active == True,  # noqa: E712
        ).first()
        if not ok:
            raise HTTPException(422, "owner_id is not an active user in your organization")

    changes = req.model_dump(exclude_unset=True)
    if "control_ids" in changes or "framework_ids" in changes:
        # Unknown control ids would be stored and silently never counted (R2USER-7).
        fw_ids = changes.get("framework_ids")
        fw_ids = list(artifact.framework_ids or []) if fw_ids is None else fw_ids
        ctrl_ids = changes.get("control_ids")
        ctrl_ids = list(artifact.control_ids or []) if ctrl_ids is None else ctrl_ids
        changes["control_ids"] = require_known_controls(db, user.organization_id, ctrl_ids, fw_ids)
    new_expiry = changes.pop("expiration_date", None)
    for field, val in changes.items():
        setattr(artifact, field, val)

    if new_expiry is not None:
        _check_expiry_date(new_expiry, artifact.date_collected or date.today())
        artifact.expiration_date = new_expiry
        artifact.expiration_days = max(1, (new_expiry - (artifact.date_collected or date.today())).days)
    elif req.expiration_days and artifact.date_collected:
        artifact.expiration_date = artifact.date_collected + timedelta(days=req.expiration_days)

    audit_svc.record(db, organization_id=user.organization_id, actor_id=user.id,
                     actor_username=user.username, action="UPDATE", entity_type="evidence",
                     entity_id=artifact.id, system_id=artifact.system_id,
                     summary=f"Updated: {artifact.filename}")
    db.commit()
    db.refresh(artifact)
    return artifact


@router.delete("/{evidence_id}")
def delete_evidence(evidence_id: int, user: User = Depends(require_min_role("compliance_manager")), db: Session = Depends(get_db)):
    artifact = db.query(EvidenceArtifact).filter(
        EvidenceArtifact.id == evidence_id,
        EvidenceArtifact.organization_id == user.organization_id, *system_scope_filter(EvidenceArtifact.system_id, db, user),
    ).first()
    if not artifact:
        raise HTTPException(404, "Evidence not found")

    file_path = resolve_evidence_path(artifact.file_path)
    audit_svc.record(db, organization_id=user.organization_id, actor_id=user.id,
                     actor_username=user.username, action="DELETE", entity_type="evidence",
                     entity_id=artifact.id, system_id=artifact.system_id,
                     summary=f"Deleted: {artifact.filename}")
    db.delete(artifact)
    db.commit()
    # The file goes only after the row is gone for good: a failed commit must
    # never leave a row whose file was already deleted (R2DATA-10). A leftover
    # file (unlink failing after the commit) is harmless.
    if file_path is not None and file_path.is_file():
        try:
            file_path.unlink()
        except OSError:
            _log.warning("evidence %s deleted but its file could not be removed: %s", evidence_id, file_path)
    return {"ok": True}

"""Custom framework builder — customer-authored compliance frameworks.

Custom frameworks are ordinary plugins (metadata.json + catalog.json) that live
under the DATA dir (settings.custom_frameworks_dir), not the read-only bundle.
They appear in the Marketplace, activate like any framework, and bypass license
entitlement (the content is the customer's own). Admin-only; frameworks are
install-wide (shared across companies in a multi-company install, like every
other framework). Each custom framework records the company that created it
(`owner_organization_id` in metadata.json): only that company's admins (or an
instance operator) can see, edit, activate or delete it, so one tenant can
never overwrite or read another tenant's in-house catalog. Custom frameworks
created before ownership was recorded stay visible install-wide but are
editable by operators only.
"""
import json
import re
import shutil

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from config import settings
from database import get_db
from dependencies import require_role
from models.framework_activation import FrameworkActivation
from models.user import User
from routers.frameworks import loader
from services import audit as audit_svc

router = APIRouter()

_ID_RE = re.compile(r"^custom-[a-z0-9][a-z0-9-]{1,58}$")


class CustomFrameworkCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    short_name: str = ""
    description: str = ""
    publisher: str = ""
    category: str = "general"
    version: str = "1.0"


class CustomControl(BaseModel):
    id: str = Field(min_length=1, max_length=40)
    family: str = ""
    family_name: str = ""
    title: str = Field(min_length=1, max_length=200)
    description: str = ""
    supplemental_guidance: str = ""
    baselines: list[str] = []


class ControlsReplace(BaseModel):
    controls: list[CustomControl]


def _dir_for(framework_id: str):
    """Resolve a custom framework's directory — refuses anything that is not a
    well-formed custom id inside the custom dir (no path tricks, no bundled)."""
    if not _ID_RE.match(framework_id):
        raise HTTPException(404, "Custom framework not found")
    base = settings.custom_frameworks_dir.resolve()
    target = (base / framework_id).resolve()
    if target.parent != base:
        raise HTTPException(404, "Custom framework not found")
    return target


def _require_custom(framework_id: str, user: User):
    """The custom framework, if the caller's company may manage it. 404 (not
    403) for another company's framework — don't reveal it exists."""
    meta = loader.get_metadata(framework_id)
    if meta is None or not meta.is_custom or not meta.manageable_by(
            user.organization_id, bool(getattr(user, "is_operator", False))):
        raise HTTPException(404, "Custom framework not found")
    return meta


@router.get("")
def list_custom(user: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    out = []
    for meta in loader.list_all():
        if not meta.is_custom or not meta.manageable_by(
                user.organization_id, bool(getattr(user, "is_operator", False))):
            continue
        active_orgs = db.query(FrameworkActivation).filter(
            FrameworkActivation.framework_id == meta.id,
            FrameworkActivation.is_active == True,  # noqa: E712
        ).count()
        out.append({
            "id": meta.id, "name": meta.name, "short_name": meta.short_name,
            "description": meta.description, "publisher": meta.publisher,
            "category": meta.category, "version": meta.version,
            "control_count": meta.control_count, "active_in_orgs": active_orgs,
        })
    return out


@router.post("")
def create_custom(req: CustomFrameworkCreate, user: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    slug = re.sub(r"[^a-z0-9]+", "-", req.name.lower()).strip("-")[:50]
    if not slug:
        raise HTTPException(422, "Name must contain letters or numbers")
    # The id carries the creating company (R2SEC-12): two companies may use
    # the same name, and the answer never depends on another company's
    # frameworks — a bare custom-<slug> id let a 409 confirm that a hidden
    # framework existed, and let one company squat a name for everyone.
    framework_id = f"custom-{user.organization_id}-{slug}"
    if not _ID_RE.match(framework_id):
        raise HTTPException(422, "Name produces an invalid framework id")
    if loader.get_metadata(framework_id) is not None:
        raise HTTPException(409, "A framework with this name already exists")

    target = _dir_for(framework_id)
    target.mkdir(parents=True, exist_ok=True)
    (target / "metadata.json").write_text(json.dumps({
        "id": framework_id,
        "name": req.name.strip(),
        "short_name": (req.short_name or req.name).strip()[:40],
        "version": req.version,
        "catalog_version": "custom",
        "description": req.description.strip(),
        "publisher": (req.publisher or "Custom (in-house)").strip(),
        "category": req.category or "general",
        "tags": ["custom"],
        "status": "available",
        "icon": "wrench",
        "color": "#7c3aed",
        "owner_organization_id": user.organization_id,
    }, indent=2))
    (target / "catalog.json").write_text(json.dumps({
        "framework_id": framework_id, "controls": [],
    }, indent=2))
    loader.discover()

    audit_svc.record(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, action="CREATE", entity_type="custom_framework",
        summary=f"Created custom framework {framework_id} ({req.name})",
    )
    db.commit()
    return {"id": framework_id, "name": req.name}


@router.get("/{framework_id}/controls")
def get_controls(framework_id: str, user: User = Depends(require_role("admin"))):
    _require_custom(framework_id, user)
    catalog = json.loads((_dir_for(framework_id) / "catalog.json").read_text())
    return catalog.get("controls", [])


@router.put("/{framework_id}/controls")
def replace_controls(
    framework_id: str,
    req: ControlsReplace,
    user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Replace the full control list (the builder edits client-side and saves).
    If the framework is active anywhere, the global catalog reloads so the app
    reflects the edit immediately."""
    _require_custom(framework_id, user)
    ids = [c.id for c in req.controls]
    if len(ids) != len(set(ids)):
        raise HTTPException(422, "Duplicate control ids")

    (_dir_for(framework_id) / "catalog.json").write_text(json.dumps({
        "framework_id": framework_id,
        "controls": [c.model_dump() for c in req.controls],
    }, indent=2))
    loader.discover()

    is_active_somewhere = db.query(FrameworkActivation).filter(
        FrameworkActivation.framework_id == framework_id,
        FrameworkActivation.is_active == True,  # noqa: E712
    ).count() > 0
    if is_active_somewhere:
        loader.load_catalog(framework_id, db)  # controls table is global

    audit_svc.record(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, action="UPDATE", entity_type="custom_framework",
        summary=f"Updated {framework_id}: {len(req.controls)} control(s)",
    )
    db.commit()
    return {"controls": len(req.controls), "reloaded": is_active_somewhere}


@router.delete("/{framework_id}")
def delete_custom(framework_id: str, user: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    _require_custom(framework_id, user)
    active = db.query(FrameworkActivation).filter(
        FrameworkActivation.framework_id == framework_id,
        FrameworkActivation.is_active == True,  # noqa: E712
    ).count()
    if active:
        raise HTTPException(409, "Deactivate this framework in every company before deleting it")
    shutil.rmtree(_dir_for(framework_id), ignore_errors=True)
    loader.discover()
    audit_svc.record(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, action="DELETE", entity_type="custom_framework",
        summary=f"Deleted custom framework {framework_id}",
    )
    db.commit()
    return {"ok": True}

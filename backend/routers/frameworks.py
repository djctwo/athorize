from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from models.user import User
from models.framework_activation import FrameworkActivation
from schemas import FrameworkActivateRequest
from dependencies import get_current_user, require_role
from services.framework_loader import FrameworkLoader
from services import audit as audit_svc
from config import settings

router = APIRouter()

loader = FrameworkLoader(settings.frameworks_dir)


def _visible_meta(framework_id: str, user: User):
    """Framework metadata if the caller's company may see it (another
    company's private custom framework reads as not found)."""
    meta = loader.get_metadata(framework_id)
    if meta is None or not meta.visible_to(user.organization_id, bool(getattr(user, "is_operator", False))):
        return None
    return meta


def hidden_framework_ids(user: User) -> set[str]:
    """Framework ids the caller's company must not see (other companies'
    private custom frameworks). Their catalog rows live in the shared controls
    table once the owner activates them, so catalog reads exclude these."""
    is_op = bool(getattr(user, "is_operator", False))
    return {m.id for m in loader.list_all() if not m.visible_to(user.organization_id, is_op)}


def require_framework_visible(framework_id: str, user: User) -> None:
    """404 for another company's private custom framework (R2SEC-2). Every
    endpoint that reads or writes the shared catalog by a client-supplied
    framework id calls this first — an unknown id reads the same way, so the
    answer never confirms that a hidden framework exists. Unknown ids that are
    not hidden are left to the caller (most already 404 on an empty catalog)."""
    if framework_id in hidden_framework_ids(user):
        raise HTTPException(404, "Framework not found")


@router.get("")
def list_frameworks(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    all_frameworks = loader.list_all()
    activations = {
        a.framework_id: a
        for a in db.query(FrameworkActivation).filter(
            FrameworkActivation.organization_id == user.organization_id,
        ).all()
    }

    is_op = bool(getattr(user, "is_operator", False))
    result = []
    for fw in all_frameworks:
        if not fw.visible_to(user.organization_id, is_op):
            continue  # another company's private custom framework
        activation = activations.get(fw.id)
        result.append({
            "id": fw.id,
            "name": fw.name,
            "short_name": fw.short_name,
            "version": fw.version,
            "description": fw.description,
            "publisher": fw.publisher,
            "category": fw.category,
            "tags": fw.tags,
            "status": fw.status,
            "icon": fw.icon,
            "color": fw.color,
            "control_count": fw.control_count,
            "license": fw.license,
            # Every bundled framework is free to activate. `attestable` flags
            # third-party content (`restriction: licensed`) that the user unlocks
            # by attesting their own publisher license key. CUSTOM frameworks are
            # the user's own content — always entitled.
            "entitled": fw.is_custom or (fw.license or {}).get("restriction") != "licensed",
            "attestable": (fw.license or {}).get("restriction") == "licensed",
            "is_custom": fw.is_custom,
            "is_active": activation.is_active if activation else False,
            "activated_at": activation.activated_at if activation else None,
        })

    return result


@router.get("/{framework_id}")
def get_framework(framework_id: str, user: User = Depends(get_current_user)):
    meta = _visible_meta(framework_id, user)
    if not meta:
        raise HTTPException(404, "Framework not found")
    return meta.__dict__


@router.post("/{framework_id}/activate")
def activate_framework(
    framework_id: str,
    req: FrameworkActivateRequest,
    user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    meta = _visible_meta(framework_id, user)
    if not meta:
        raise HTTPException(404, "Framework not found")

    is_third_party = (meta.license or {}).get("restriction") == "licensed"

    # Bundled frameworks activate freely. Third-party-content frameworks
    # (`restriction: licensed`) are unlocked only by the user attesting their
    # own publisher license key.
    if not meta.is_custom and is_third_party and not (req.license_key or "").strip():
        licensor = (meta.license or {}).get("licensor") or "the publisher"
        raise HTTPException(
            403,
            f"{meta.name} is licensed third-party content. Enable it by entering your own "
            f"{licensor} license key (your organization is responsible for holding it).",
        )

    existing = db.query(FrameworkActivation).filter(
        FrameworkActivation.organization_id == user.organization_id,
        FrameworkActivation.framework_id == framework_id,
    ).first()

    if existing and existing.is_active:
        raise HTTPException(400, "Framework already active")

    try:
        control_count = loader.load_catalog(framework_id, db)
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    mapping_count = loader.load_mappings(framework_id, db)

    if existing:
        existing.is_active = True
        existing.activated_at = datetime.now(timezone.utc)
        existing.catalog_version = meta.catalog_version
        existing.license_key = req.license_key
        existing.activated_by_id = user.id
    else:
        activation = FrameworkActivation(
            organization_id=user.organization_id,
            framework_id=framework_id,
            license_key=req.license_key,
            catalog_version=meta.catalog_version,
            is_active=True,
            activated_by_id=user.id,
        )
        db.add(activation)

    if is_third_party:
        summary = f"Activated licensed framework '{framework_id}' via customer-attested license key"
    else:
        summary = f"Activated framework '{framework_id}'"
    audit_svc.record(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, action="ACTIVATE", entity_type="framework",
        summary=summary,
    )

    db.commit()
    return {"framework_id": framework_id, "controls_loaded": control_count, "mappings_loaded": mapping_count}


@router.post("/{framework_id}/deactivate")
def deactivate_framework(
    framework_id: str,
    user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    activation = db.query(FrameworkActivation).filter(
        FrameworkActivation.organization_id == user.organization_id,
        FrameworkActivation.framework_id == framework_id,
    ).first()

    if not activation or not activation.is_active:
        raise HTTPException(400, "Framework not active")

    activation.is_active = False
    db.flush()
    # The controls + control_mappings tables are install-wide (one catalog per
    # framework, shared by every company). Unload them only when no company
    # still has this framework active — otherwise one tenant's toggle would
    # wipe the catalog, scores and crosswalk out from under every other tenant.
    still_active = db.query(FrameworkActivation.id).filter(
        FrameworkActivation.framework_id == framework_id,
        FrameworkActivation.is_active == True,  # noqa: E712
    ).first() is not None
    if not still_active:
        loader.unload_catalog(framework_id, db)
        loader.unload_mappings(framework_id, db)
    audit_svc.record(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, action="DEACTIVATE", entity_type="framework",
        summary=f"Deactivated framework '{framework_id}'",
    )
    db.commit()
    return {"ok": True, "catalog_unloaded": not still_active}


@router.get("/{framework_id}/reports")
def get_report_templates(framework_id: str, user: User = Depends(get_current_user)):
    if not _visible_meta(framework_id, user):
        return []
    return loader.get_report_templates(framework_id)


@router.get("/{framework_id}/assessments")
def get_assessment_templates(framework_id: str, user: User = Depends(get_current_user)):
    if not _visible_meta(framework_id, user):
        return []
    return loader.get_assessment_templates(framework_id)

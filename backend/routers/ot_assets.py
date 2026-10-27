from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from dependencies import get_current_user, require_can
from models.ot_asset import OTAsset
from models.system import System
from models.user import User
from schemas import OTAssetCreate, OTAssetUpdate, BulkImportPayload
from services import audit as audit_svc
from services.bulk_import import run_bulk_import
from services.payload import coerce_dates, coerce_bool, coerce_list, safe_commit
from services.system_scope import system_scope_filter, system_scope_filter_nullable, require_system_allowed

router = APIRouter()

ENTITY = "OT_ASSET"
DATE_FIELDS = {"last_firmware_review"}
LIST_FIELDS = {"protocols", "connected_to"}
VALID_ASSET_TYPES = {
    "PLC", "HMI", "ENGINEERING_WORKSTATION", "HISTORIAN", "RTU",
    "FIELD_DEVICE", "NETWORK_DEVICE", "SERVER", "OTHER",
}
VALID_PURDUE_LEVELS = {"LEVEL_0", "LEVEL_1", "LEVEL_2", "LEVEL_3", "DMZ"}
VALID_PATCH_STATUSES = {"CURRENT", "BEHIND", "NOT_PATCHABLE", "VENDOR_ONLY"}
VALID_STIG_STATUSES = {"COMPLIANT", "NON_COMPLIANT", "NA", "NOT_REVIEWED"}
ENUM_RULES: dict[str, set[str]] = {
    "asset_type": VALID_ASSET_TYPES,
    "purdue_level": VALID_PURDUE_LEVELS,
    "patch_status": VALID_PATCH_STATUSES,
    "stig_compliance_status": VALID_STIG_STATUSES,
}
_SORTED_ENUMS: dict[str, list[str]] = {k: sorted(v) for k, v in ENUM_RULES.items()}
IMPORT_FIELDS = {
    "asset_name", "asset_type", "vendor", "model", "firmware_version",
    "ip_address", "mac_address", "purdue_level", "protocols", "network_zone",
    "patch_status", "patch_notes", "last_firmware_review", "stig_applicable",
    "stig_id", "stig_compliance_status", "connected_to", "notes",
}
def _summary(a: OTAsset) -> str:
    return a.asset_name or f"asset #{a.id}"


@router.get("")
def list_assets(
    system_id: int | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(OTAsset).filter(OTAsset.organization_id == user.organization_id, *system_scope_filter(OTAsset.system_id, db, user))
    if system_id is not None:
        q = q.filter(OTAsset.system_id == system_id)
    return q.order_by(OTAsset.asset_name).all()


@router.get("/{asset_id}")
def get_asset(asset_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    a = db.query(OTAsset).filter(
        OTAsset.id == asset_id, OTAsset.organization_id == user.organization_id, *system_scope_filter(OTAsset.system_id, db, user)
    ).first()
    if not a:
        raise HTTPException(404, "OT asset not found")
    return a


@router.post("")
def create_asset(
    payload: OTAssetCreate,
    user: User = Depends(require_can("edit:system")),
    db: Session = Depends(get_db),
):
    system = db.query(System).filter(
        System.id == payload.system_id, System.organization_id == user.organization_id, *system_scope_filter(System.id, db, user)
    ).first()
    if not system:
        raise HTTPException(404, "System not found")

    a = OTAsset(organization_id=user.organization_id, **payload.model_dump())
    db.add(a)
    db.flush()
    audit_svc.record(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, action="CREATE", entity_type=ENTITY,
        entity_id=a.id, system_id=a.system_id, summary=_summary(a),
    )
    safe_commit(db)
    db.refresh(a)
    return a


@router.patch("/{asset_id}")
def update_asset(
    asset_id: int,
    payload: OTAssetUpdate,
    user: User = Depends(require_can("edit:system")),
    db: Session = Depends(get_db),
):
    a = db.query(OTAsset).filter(
        OTAsset.id == asset_id, OTAsset.organization_id == user.organization_id, *system_scope_filter(OTAsset.system_id, db, user)
    ).first()
    if not a:
        raise HTTPException(404, "OT asset not found")
    for k, v in payload.model_dump(exclude_unset=True).items():
        setattr(a, k, v)
    audit_svc.record(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, action="UPDATE", entity_type=ENTITY,
        entity_id=a.id, system_id=a.system_id, summary=_summary(a),
    )
    safe_commit(db)
    db.refresh(a)
    return a


@router.delete("/{asset_id}")
def delete_asset(
    asset_id: int,
    user: User = Depends(require_can("edit:system")),
    db: Session = Depends(get_db),
):
    a = db.query(OTAsset).filter(
        OTAsset.id == asset_id, OTAsset.organization_id == user.organization_id, *system_scope_filter(OTAsset.system_id, db, user)
    ).first()
    if not a:
        raise HTTPException(404, "OT asset not found")
    audit_svc.record(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, action="DELETE", entity_type=ENTITY,
        entity_id=a.id, system_id=a.system_id, summary=_summary(a),
    )
    db.delete(a)
    safe_commit(db)
    return {"deleted": asset_id}


def _validate_import_row(idx: int, row: dict) -> tuple[dict | None, list[dict]]:
    errors: list[dict] = []
    clean: dict = {}
    for key, raw in row.items():
        if key not in IMPORT_FIELDS:
            continue
        if raw in (None, ""):
            continue
        if key in LIST_FIELDS:
            clean[key] = coerce_list(raw)
            continue
        if key == "stig_applicable":
            b = coerce_bool(raw)
            if b is None:
                errors.append({"row": idx, "field": key, "message": f"'{raw}' is not a boolean"})
                continue
            clean[key] = b
            continue
        clean[key] = raw
    if not clean.get("asset_name"):
        errors.append({"row": idx, "field": "asset_name", "message": "asset_name is required"})
    for field, allowed in ENUM_RULES.items():
        v = clean.get(field)
        if v is not None and v not in allowed:
            errors.append({"row": idx, "field": field, "message": f"'{v}' not one of {_SORTED_ENUMS[field]}"})
    if errors:
        return None, errors
    return coerce_dates(clean, DATE_FIELDS), []


@router.post("/bulk-import/{system_id}")
def bulk_import(
    system_id: int,
    payload: BulkImportPayload,
    user: User = Depends(require_can("edit:system")),
    db: Session = Depends(get_db),
):
    result = run_bulk_import(
        db, organization_id=user.organization_id, system_id=system_id,
        rows=payload.rows, commit=payload.commit,
        system_model=System, record_model=OTAsset, validate_row=_validate_import_row,
    )
    if payload.commit and result.get("committed"):
        audit_svc.record(
            db, organization_id=user.organization_id, actor_id=user.id,
            actor_username=user.username, action="BULK_IMPORT", entity_type=ENTITY,
            system_id=system_id, summary=f"Imported {result['committed']} OT assets",
        )
        db.commit()
    return result

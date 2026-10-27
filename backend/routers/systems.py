from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from models.user import User
from models.system import System
from schemas import SystemCreate, SystemUpdate
from dependencies import get_current_user, require_can, require_min_role
from services import audit as audit_svc
from services.system_scope import system_scope_filter, system_scope_filter_nullable, require_system_allowed
from services.org_refs import require_org_user

router = APIRouter()


@router.get("")
def list_systems(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(System).filter(System.organization_id == user.organization_id, *system_scope_filter(System.id, db, user)).all()


@router.post("")
def create_system(req: SystemCreate, user: User = Depends(require_can("edit:system")), db: Session = Depends(get_db)):
    require_org_user(db, user, req.owner_id)
    system = System(organization_id=user.organization_id, **req.model_dump())
    db.add(system)
    db.flush()
    audit_svc.record(db, organization_id=user.organization_id, actor_id=user.id,
                     actor_username=user.username, action="CREATE", entity_type="system",
                     entity_id=system.id, summary=f"Created system: {system.name}")
    db.commit()
    db.refresh(system)
    return system


@router.get("/{system_id}")
def get_system(system_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    system = db.query(System).filter(System.id == system_id, System.organization_id == user.organization_id, *system_scope_filter(System.id, db, user)).first()
    if not system:
        raise HTTPException(404, "System not found")
    return system


@router.patch("/{system_id}")
def update_system(system_id: int, req: SystemUpdate, user: User = Depends(require_can("edit:system")), db: Session = Depends(get_db)):
    system = db.query(System).filter(System.id == system_id, System.organization_id == user.organization_id, *system_scope_filter(System.id, db, user)).first()
    if not system:
        raise HTTPException(404, "System not found")

    changes = req.model_dump(exclude_unset=True)
    if "owner_id" in changes:
        require_org_user(db, user, changes["owner_id"])
    for field, val in changes.items():
        setattr(system, field, val)

    audit_svc.record(db, organization_id=user.organization_id, actor_id=user.id,
                     actor_username=user.username, action="UPDATE", entity_type="system",
                     entity_id=system.id, summary=f"Updated system: {system.name}")
    db.commit()
    db.refresh(system)
    return system


@router.delete("/{system_id}")
def delete_system(system_id: int, user: User = Depends(require_min_role("compliance_manager")), db: Session = Depends(get_db)):
    system = db.query(System).filter(System.id == system_id, System.organization_id == user.organization_id, *system_scope_filter(System.id, db, user)).first()
    if not system:
        raise HTTPException(404, "System not found")
    audit_svc.record(db, organization_id=user.organization_id, actor_id=user.id,
                     actor_username=user.username, action="DELETE", entity_type="system",
                     entity_id=system.id, summary=f"Deleted system: {system.name}")
    db.delete(system)
    db.commit()
    return {"ok": True}

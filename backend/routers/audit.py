from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from database import get_db
from models.user import User
from models.audit import AuditEntry
from dependencies import get_current_user
from services.system_scope import audit_scope_filter

router = APIRouter()


@router.get("")
def list_audit(
    entity_type: str | None = None,
    entity_id: int | None = None,
    system_id: int | None = None,
    actor_id: int | None = None,
    limit: int = Query(100, le=500),
    offset: int = 0,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(AuditEntry).filter(AuditEntry.organization_id == user.organization_id,
                                    *audit_scope_filter(db, user))
    if entity_type:
        q = q.filter(AuditEntry.entity_type == entity_type)
    if entity_id is not None:
        q = q.filter(AuditEntry.entity_id == entity_id)
    if system_id:
        q = q.filter(AuditEntry.system_id == system_id)
    if actor_id:
        q = q.filter(AuditEntry.actor_id == actor_id)
    return q.order_by(AuditEntry.timestamp.desc()).offset(offset).limit(limit).all()


@router.get("/verify")
def verify_integrity(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    from services.audit import verify
    return verify(db, user.organization_id)

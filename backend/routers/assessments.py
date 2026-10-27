from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from models.user import User
from models.assessment import Assessment
from schemas import AssessmentCreate, AssessmentUpdate
from dependencies import get_current_user, require_min_role
from services import audit as audit_svc
from services.system_scope import system_scope_filter, system_scope_filter_nullable, require_system_allowed
from services.org_refs import require_org_system, require_org_user

router = APIRouter()


@router.get("")
def list_assessments(
    system_id: int | None = None,
    framework_id: str | None = None,
    status: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(Assessment).filter(Assessment.organization_id == user.organization_id, *system_scope_filter(Assessment.system_id, db, user))
    if system_id:
        q = q.filter(Assessment.system_id == system_id)
    if framework_id:
        q = q.filter(Assessment.framework_id == framework_id)
    if status:
        q = q.filter(Assessment.status == status)
    return q.order_by(Assessment.created_at.desc()).all()


@router.post("")
def create_assessment(req: AssessmentCreate, user: User = Depends(require_min_role("assessor")), db: Session = Depends(get_db)):
    # The client picks system_id/assessor_id: both must be in the caller's org
    # (and the system in their scope), or the assessment report would render
    # another company's system (SECCODE-2).
    require_org_system(db, user, req.system_id)
    require_org_user(db, user, req.assessor_id, "assessor_id")
    from routers.frameworks import require_framework_visible
    require_framework_visible(req.framework_id, user)
    assessment = Assessment(organization_id=user.organization_id, **req.model_dump())
    db.add(assessment)
    db.flush()
    audit_svc.record(db, organization_id=user.organization_id, actor_id=user.id,
                     actor_username=user.username, action="CREATE", entity_type="assessment",
                     entity_id=assessment.id, system_id=assessment.system_id,
                     summary=f"Created assessment: {assessment.assessment_type}")
    db.commit()
    db.refresh(assessment)
    return assessment


@router.get("/{assessment_id}")
def get_assessment(assessment_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    assessment = db.query(Assessment).filter(
        Assessment.id == assessment_id,
        Assessment.organization_id == user.organization_id, *system_scope_filter(Assessment.system_id, db, user),
    ).first()
    if not assessment:
        raise HTTPException(404, "Assessment not found")
    return assessment


@router.put("/{assessment_id}")
def update_assessment(assessment_id: int, req: AssessmentUpdate, user: User = Depends(require_min_role("assessor")), db: Session = Depends(get_db)):
    assessment = db.query(Assessment).filter(
        Assessment.id == assessment_id,
        Assessment.organization_id == user.organization_id, *system_scope_filter(Assessment.system_id, db, user),
    ).first()
    if not assessment:
        raise HTTPException(404, "Assessment not found")

    for field, val in req.model_dump(exclude_unset=True).items():
        setattr(assessment, field, val)

    if req.status == "IN_PROGRESS" and not assessment.started_at:
        assessment.started_at = datetime.now(timezone.utc)
    if req.status == "COMPLETE":
        assessment.completed_at = datetime.now(timezone.utc)

    audit_svc.record(db, organization_id=user.organization_id, actor_id=user.id,
                     actor_username=user.username, action="UPDATE", entity_type="assessment",
                     entity_id=assessment.id, system_id=assessment.system_id,
                     summary=f"Updated assessment: {assessment.assessment_type}")
    db.commit()
    db.refresh(assessment)
    return assessment


@router.delete("/{assessment_id}")
def delete_assessment(assessment_id: int, user: User = Depends(require_min_role("compliance_manager")), db: Session = Depends(get_db)):
    assessment = db.query(Assessment).filter(
        Assessment.id == assessment_id,
        Assessment.organization_id == user.organization_id, *system_scope_filter(Assessment.system_id, db, user),
    ).first()
    if not assessment:
        raise HTTPException(404, "Assessment not found")
    audit_svc.record(db, organization_id=user.organization_id, actor_id=user.id,
                     actor_username=user.username, action="DELETE", entity_type="assessment",
                     entity_id=assessment.id, system_id=assessment.system_id,
                     summary=f"Deleted assessment: {assessment.assessment_type}")
    db.delete(assessment)
    db.commit()
    return {"ok": True}

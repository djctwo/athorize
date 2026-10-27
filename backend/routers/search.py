"""Global content search — powers the ⌘K palette's cross-entity results.

Org- and system-scoped LIKE search over the entities users actually hunt for: findings,
systems, evidence, risks, advisories, and controls (active frameworks only).
Capped per type; the palette shows grouped results that navigate to the page.
"""
from fastapi import APIRouter, Depends
from sqlalchemy import or_
from sqlalchemy.orm import Session

from database import get_db
from dependencies import get_current_user
from services.system_scope import system_scope_filter
from models import (
    Control, EvidenceArtifact, Finding, FrameworkActivation, IcsAdvisory,
    RiskRegisterEntry, System, User,
)

router = APIRouter()

LIMIT = 5


@router.get("")
def search(q: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    term = (q or "").strip()
    if len(term) < 2:
        return {"findings": [], "systems": [], "evidence": [], "risks": [], "advisories": [], "controls": []}
    like = f"%{term}%"
    org = user.organization_id

    findings = db.query(Finding).filter(
        Finding.organization_id == org, Finding.title.ilike(like),
        *system_scope_filter(Finding.system_id, db, user),
    ).limit(LIMIT).all()
    systems = db.query(System).filter(
        System.organization_id == org,
        or_(System.name.ilike(like), System.acronym.ilike(like)),
        *system_scope_filter(System.id, db, user),
    ).limit(LIMIT).all()
    evidence = db.query(EvidenceArtifact).filter(
        EvidenceArtifact.organization_id == org,
        or_(EvidenceArtifact.filename.ilike(like), EvidenceArtifact.description.ilike(like)),
        *system_scope_filter(EvidenceArtifact.system_id, db, user),
    ).limit(LIMIT).all()
    risks = db.query(RiskRegisterEntry).filter(
        RiskRegisterEntry.organization_id == org, RiskRegisterEntry.title.ilike(like),
        *system_scope_filter(RiskRegisterEntry.system_id, db, user),
    ).limit(LIMIT).all()
    advisories = db.query(IcsAdvisory).filter(
        IcsAdvisory.organization_id == org,
        or_(IcsAdvisory.advisory_id.ilike(like), IcsAdvisory.title.ilike(like)),
    ).limit(LIMIT).all()

    active_fw = [
        a.framework_id for a in db.query(FrameworkActivation).filter(
            FrameworkActivation.organization_id == org,
            FrameworkActivation.is_active == True,  # noqa: E712
        ).all()
    ]
    controls = db.query(Control).filter(
        Control.framework_id.in_(active_fw),
        or_(Control.control_id.ilike(like), Control.title.ilike(like)),
    ).limit(LIMIT).all() if active_fw else []

    return {
        "findings": [{"id": f.id, "title": f.title, "severity": f.severity, "status": f.status} for f in findings],
        "systems": [{"id": s.id, "name": s.name, "acronym": s.acronym} for s in systems],
        "evidence": [{"id": e.id, "filename": e.filename} for e in evidence],
        "risks": [{"id": r.id, "title": r.title} for r in risks],
        "advisories": [{"id": a.id, "advisory_id": a.advisory_id, "title": a.title} for a in advisories],
        "controls": [{"framework_id": c.framework_id, "control_id": c.control_id, "title": c.title} for c in controls],
    }

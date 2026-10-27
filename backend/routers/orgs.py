"""Organizations (companies) — list, create, and operator company-switching.

Only `is_operator` users are cross-company: they can see every organization,
create new ones, and switch the company they are actively viewing. Regular users
are locked to their single organization (GET returns only their own; create and
switch are 403). The active company lives on the session
(`UserSession.active_organization_id`) and is applied in-memory per request by
dependencies.get_current_user — so switching transparently re-scopes the whole app.
"""
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import set_committed_value

from database import get_db
from dependencies import get_current_user, get_current_session, require_role
from models.organization import Organization
from models.session import UserSession
from models.user import User
from services import audit as audit_svc
from services.branding import validate_logo_data_uri

router = APIRouter()


class OrgOut(BaseModel):
    id: int
    name: str
    slug: str


class OrgListOut(BaseModel):
    organizations: list[OrgOut]
    is_operator: bool
    active_organization_id: int


class OrgCreate(BaseModel):
    name: str


class OrgSwitch(BaseModel):
    org_id: int


@router.get("", response_model=OrgListOut)
def list_orgs(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Operators see every company; everyone else sees only their own."""
    if user.is_operator:
        orgs = db.query(Organization).order_by(Organization.name).all()
    else:
        orgs = db.query(Organization).filter(Organization.id == user.organization_id).all()
    return OrgListOut(
        organizations=[OrgOut(id=o.id, name=o.name, slug=o.slug) for o in orgs],
        is_operator=user.is_operator,
        active_organization_id=user.organization_id,
    )


@router.post("", response_model=OrgOut)
def create_org(req: OrgCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Create a new company. Operators only."""
    if not user.is_operator:
        raise HTTPException(403, "Only operators can create companies")
    name = req.name.strip()
    if not name:
        raise HTTPException(422, "Company name is required")
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    if not slug:
        raise HTTPException(422, "Company name must contain letters or numbers")
    if db.query(Organization).filter(Organization.slug == slug).first():
        raise HTTPException(409, "A company with this name already exists")
    org = Organization(name=name, slug=slug)
    db.add(org)
    db.flush()
    audit_svc.record(
        db, organization_id=org.id, actor_id=user.id, actor_username=user.username,
        action="CREATE", entity_type="organization", entity_id=org.id,
        summary=f"Created company {name}",
    )
    db.commit()
    return OrgOut(id=org.id, name=org.name, slug=org.slug)


@router.post("/switch", response_model=OrgListOut)
def switch_org(
    req: OrgSwitch,
    user: User = Depends(get_current_user),
    session: UserSession = Depends(get_current_session),
    db: Session = Depends(get_db),
):
    """Set the company the operator is actively viewing. Operators only."""
    if not user.is_operator:
        raise HTTPException(403, "Only operators can switch companies")
    target = db.query(Organization).filter(Organization.id == req.org_id).first()
    if not target:
        raise HTTPException(404, "Company not found")
    session.active_organization_id = target.id
    # Audit the switch under the TARGET company so its log shows the operator entering.
    audit_svc.record(
        db, organization_id=target.id, actor_id=user.id, actor_username=user.username,
        action="SWITCH_ORG", entity_type="organization", entity_id=target.id,
        summary=f"Operator {user.username} switched to {target.name}",
    )
    db.commit()
    orgs = db.query(Organization).order_by(Organization.name).all()
    return OrgListOut(
        organizations=[OrgOut(id=o.id, name=o.name, slug=o.slug) for o in orgs],
        is_operator=True,
        active_organization_id=target.id,
    )


# ---------------------------------------------------------------------------
# Branding — per-company logo (operator/MSP model)
# ---------------------------------------------------------------------------

class BrandingUpdate(BaseModel):
    logo_data_uri: str


def _shield_org_switch_override(user: User) -> None:
    """Make our flush/commit safe under an operator org-switch.

    get_current_user applies the switch by mutating user.organization_id IN
    MEMORY (multi-company invariant: that change must never reach the
    database). These endpoints flush and commit (audit hash chain + settings),
    and any flush writes every dirty object in the session — including that
    override, which would permanently move the operator's home company. Erase
    the attribute's pending history (keeping the overridden value) so the
    users row stays untouched. MUST be called BEFORE the first flush-capable
    operation (audit_svc.record flushes). No-op for non-switched requests.
    """
    set_committed_value(user, "organization_id", user.organization_id)


def _active_org(db: Session, user: User) -> Organization:
    """The company the caller is currently viewing (org-switch-aware)."""
    org = db.query(Organization).filter(Organization.id == user.organization_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")
    return org


@router.put("/branding")
def set_branding(
    req: BrandingUpdate,
    user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Upload or replace the ACTIVE company's logo. Admin only.

    Honors the operator org-switch: an operator brands the company they are
    currently viewing. The payload is strictly validated (PNG/JPEG magic-byte
    sniff, ~300 KB decoded cap — SVG is rejected as an XSS vector) and stored
    canonicalized in Organization.settings['branding'].
    """
    try:
        canonical = validate_logo_data_uri(req.logo_data_uri)
    except ValueError as e:
        raise HTTPException(422, str(e))
    _shield_org_switch_override(user)
    org = _active_org(db, user)
    org_settings = dict(org.settings or {})
    org_settings["branding"] = {
        "logo_data_uri": canonical,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    org.settings = org_settings
    audit_svc.record(
        db, organization_id=org.id, actor_id=user.id, actor_username=user.username,
        action="UPDATE", entity_type="organization", entity_id=org.id,
        summary=f"Updated company logo for {org.name}",
    )
    db.commit()
    return {"branding": org_settings["branding"]}


@router.delete("/branding")
def clear_branding(
    user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Remove the ACTIVE company's logo. Admin only. Idempotent."""
    _shield_org_switch_override(user)
    org = _active_org(db, user)
    org_settings = dict(org.settings or {})
    if "branding" not in org_settings:
        return {"branding": None}
    org_settings.pop("branding")
    org.settings = org_settings
    audit_svc.record(
        db, organization_id=org.id, actor_id=user.id, actor_username=user.username,
        action="UPDATE", entity_type="organization", entity_id=org.id,
        summary=f"Removed company logo for {org.name}",
    )
    db.commit()
    return {"branding": None}


@router.get("/portfolio")
def portfolio(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Cross-company overview for operators: each company's compliance posture
    on one screen (the consultant/MSP cockpit). Operator-only."""
    from datetime import date, timedelta

    from models import EvidenceArtifact, Finding, System
    from services.history import live_pair_scores
    from services.metrics import average_score, counted_framework_clause, finding_counts

    if not user.is_operator:
        raise HTTPException(403, "Only operators can view the portfolio")

    today = date.today()
    ev_horizon = today + timedelta(days=14)
    out = []
    for org in db.query(Organization).order_by(Organization.name).all():
        counts = finding_counts(db.query(Finding).filter(
            Finding.organization_id == org.id, counted_framework_clause(org.id)), today)
        open_findings, overdue, critical = counts["open"], counts["overdue"], counts["critical"]
        systems = db.query(System).filter(System.organization_id == org.id).count()
        evidence_stale = db.query(EvidenceArtifact).filter(
            EvidenceArtifact.organization_id == org.id,
            EvidenceArtifact.expiration_date.isnot(None),
            EvidenceArtifact.expiration_date <= ev_horizon,
        ).count()
        # Live, same computation as the Dashboard score cards and today's trend
        # point (services.history.live_pair_scores) — never a stale snapshot.
        avg_score = average_score(p["score_percentage"] for p in live_pair_scores(db, org.id, on=today))
        out.append({
            "id": org.id, "name": org.name, "slug": org.slug,
            "systems": systems,
            "open_findings": open_findings,
            "overdue_findings": overdue,
            "critical_findings": critical,
            "evidence_stale": evidence_stale,
            "avg_score": avg_score,
        })
    return {"companies": out, "active_organization_id": user.organization_id}

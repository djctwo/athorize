import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from dependencies import get_current_user, require_can
from models import Control, ControlImplementation, EvidenceArtifact, Finding, FrameworkActivation, System
from models.user import User
from services import audit as audit_svc
from services import crosswalk as crosswalk_svc
from services.natural_sort import control_sort_key
from services.payload import safe_commit
from services.system_scope import system_scope_filter, system_scope_filter_nullable, require_system_allowed

router = APIRouter()

# Finding statuses that still represent live non-compliance
ACTIVE_FINDING_STATUSES = ("OPEN", "IN_PROGRESS", "DELAYED")

# Implementation statuses considered "satisfied" for propagation purposes
SATISFIED_STATUSES = ("IMPLEMENTED", "INHERITED")
# Relationships strong enough to suggest an implementation carries over
PROPAGATION_RELATIONSHIPS = ("equivalent", "superset")


def _active_framework_ids(db: Session, organization_id: int) -> set[str]:
    return {
        a.framework_id
        for a in db.query(FrameworkActivation).filter(
            FrameworkActivation.organization_id == organization_id,
            FrameworkActivation.is_active == True,  # noqa: E712
        ).all()
    }


def _titles_for(db: Session, keys: set[tuple[str, str]]) -> dict[tuple[str, str], str]:
    if not keys:
        return {}
    rows = db.query(Control).filter(
        Control.framework_id.in_({k[0] for k in keys}),
        Control.control_id.in_({k[1] for k in keys}),
    ).all()
    return {(r.framework_id, r.control_id): r.title for r in rows}


# Suggestion ranking: strongest relationship first, then the most trustworthy
# mapping, then a direct mapping before one composed through the hub.
_RELATIONSHIP_RANK = {"equivalent": 0, "superset": 1, "subset": 2, "intersects": 3, "related": 4}
_CONFIDENCE_ORDER = {"official": 0, "derived": 1, "vendor": 2}
_STOP_WORDS = frozenset({"and", "or", "of", "the", "for", "to", "in", "on", "a", "an", "with",
                         "policy", "area", "control", "controls", "requirement", "requirements"})


def _title_words(title: str) -> set[str]:
    """Significant, crudely stemmed words of a control title ("Users" ~ "User")."""
    words = set()
    for w in re.findall(r"[a-z]+", (title or "").lower()):
        if len(w) < 3 or w in _STOP_WORDS:
            continue
        words.add(w[:-1] if w.endswith("s") and len(w) > 4 else w)
    return words


def _suggestion_rank(sug: dict, source_titles: dict[tuple[str, str], str]):
    """Sort key for an evidence suggestion. Within one relationship tier the
    controls whose titles share the most words with the evidence's own control
    come first (a CJIS "Identification and Authentication" before CJIS "Mobile
    Devices" for an MFA export), then catalog order."""
    src = _title_words(source_titles.get((sug["source_framework_id"], sug["source_control_id"]), ""))
    overlap = len(src & _title_words(sug.get("title", "")))
    return (
        _RELATIONSHIP_RANK.get(sug["relationship"], 9),
        _CONFIDENCE_ORDER.get(sug["confidence"], 9),
        0 if sug["path"] == "direct" else 1,
        -overlap,
        sug["framework_id"],
        control_sort_key(sug["control_id"]),
    )


# NOTE: fixed-path routes must register before /{framework_id}/{control_id},
# or FastAPI matches their first segment as a framework_id.


@router.get("/evidence/{evidence_id}/suggestions")
def evidence_suggestions(
    evidence_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Phase B: controls in other active frameworks this evidence likely also
    satisfies, via the crosswalk. Excludes 'related' mappings (too weak) and
    anything the evidence already covers. Accepting is just an evidence PATCH
    adding the control/framework — the frontend uses the existing endpoint."""
    artifact = db.query(EvidenceArtifact).filter(
        EvidenceArtifact.id == evidence_id,
        EvidenceArtifact.organization_id == user.organization_id,
        *system_scope_filter(EvidenceArtifact.system_id, db, user),
    ).first()
    if not artifact:
        raise HTTPException(404, "Evidence not found")

    control_ids = artifact.control_ids or []
    framework_ids = artifact.framework_ids or []
    if not control_ids or not framework_ids:
        return {"evidence_id": evidence_id, "suggestions": []}

    active = _active_framework_ids(db, user.organization_id)
    linked_controls = set(control_ids)
    linked_frameworks = set(framework_ids)

    # Only resolve pairs that actually exist in the catalog
    valid_pairs = {
        (r.framework_id, r.control_id)
        for r in db.query(Control).filter(
            Control.framework_id.in_(framework_ids),
            Control.control_id.in_(control_ids),
        ).all()
    }

    suggestions: dict[tuple[str, str], dict] = {}
    for fw, ctrl in sorted(valid_pairs):
        for e in crosswalk_svc.resolve(db, fw, ctrl, active):
            if e.relationship == "related":
                continue
            key = (e.framework_id, e.control_id)
            already = e.control_id in linked_controls and e.framework_id in linked_frameworks
            if already or key in suggestions:
                continue
            suggestions[key] = {
                "framework_id": e.framework_id,
                "control_id": e.control_id,
                "relationship": e.relationship,
                "confidence": e.confidence,
                "path": e.path,
                "source_framework_id": fw,
                "source_control_id": ctrl,
            }

    titles = _titles_for(db, set(suggestions.keys()) | valid_pairs)
    out = []
    for key, sug in suggestions.items():
        sug["title"] = titles.get(key, "")
        out.append(sug)
    # Strongest, most relevant first — not alphabetical by framework id, which
    # put CJIS "Mobile Devices" above the EQUIVALENT FedRAMP control.
    out.sort(key=lambda x: _suggestion_rank(x, titles))
    return {"evidence_id": evidence_id, "suggestions": out}


@router.get("/suggestions")
def implementation_suggestions(
    system_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Phase C: review queue. For every satisfied control implementation on
    this system, the mapped controls in other active frameworks that have no
    implementation (or sit at NOT_ASSESSED) and would likely be satisfied by
    the same work. Suggest-only — accepting creates a PLANNED-state row the
    assessor finishes; nothing is ever auto-set."""
    system = db.query(System).filter(
        System.id == system_id,
        System.organization_id == user.organization_id, *system_scope_filter(System.id, db, user),
    ).first()
    if not system:
        raise HTTPException(404, "System not found")

    active = _active_framework_ids(db, user.organization_id)
    impls = db.query(ControlImplementation).filter(
        ControlImplementation.system_id == system_id,
    ).all()
    by_key = {(i.framework_id, i.control_id): i for i in impls}

    suggestions: dict[tuple[str, str], dict] = {}
    # Why the queue may be empty (R2USER-15): nothing implemented yet, only
    # weaker mappings (intersects/related, never auto-proposed), or every
    # qualifying target already assessed. The UI words its empty state from these.
    satisfied = qualifying = weaker = covered = 0
    for impl in impls:
        if impl.implementation_status not in SATISFIED_STATUSES:
            continue
        satisfied += 1
        for e in crosswalk_svc.resolve(db, impl.framework_id, impl.control_id, active):
            if e.relationship not in PROPAGATION_RELATIONSHIPS or e.confidence == "vendor":
                weaker += 1
                continue
            qualifying += 1
            key = (e.framework_id, e.control_id)
            existing = by_key.get(key)
            if existing is not None and existing.implementation_status != "NOT_ASSESSED":
                covered += 1
                continue
            if key in suggestions:
                continue
            suggestions[key] = {
                "framework_id": e.framework_id,
                "control_id": e.control_id,
                "relationship": e.relationship,
                "confidence": e.confidence,
                "path": e.path,
                "source_framework_id": impl.framework_id,
                "source_control_id": impl.control_id,
                "source_status": impl.implementation_status,
            }

    titles = _titles_for(db, set(suggestions.keys()))
    out = []
    for key, sug in suggestions.items():
        sug["title"] = titles.get(key, "")
        out.append(sug)
    out.sort(key=lambda x: (x["framework_id"], x["control_id"]))
    return {"system_id": system_id, "suggestions": out, "stats": {
        "active_frameworks": len(active), "satisfied_controls": satisfied,
        "qualifying_mappings": qualifying, "weaker_mappings": weaker, "already_implemented": covered,
    }}


class AcceptSuggestion(BaseModel):
    system_id: int
    framework_id: str
    control_id: str
    source_framework_id: str
    source_control_id: str


@router.post("/suggestions/accept")
def accept_suggestion(
    req: AcceptSuggestion,
    user: User = Depends(require_can("assess:control")),
    db: Session = Depends(get_db),
):
    """Accept one propagation suggestion: create (or upgrade a NOT_ASSESSED)
    implementation row at PLANNED, seeded from the source implementation's
    narrative and evidence, with crosswalk provenance recorded. The assessor
    reviews and promotes it — acceptance is a starting point, not a sign-off."""
    system = db.query(System).filter(
        System.id == req.system_id,
        System.organization_id == user.organization_id, *system_scope_filter(System.id, db, user),
    ).first()
    if not system:
        raise HTTPException(404, "System not found")

    # The suggestion must still be derivable — guards stale/forged accepts
    active = _active_framework_ids(db, user.organization_id)
    entries = crosswalk_svc.resolve(db, req.source_framework_id, req.source_control_id, active)
    match = next(
        (e for e in entries
         if e.framework_id == req.framework_id and e.control_id == req.control_id
         and e.relationship in PROPAGATION_RELATIONSHIPS and e.confidence != "vendor"),
        None,
    )
    if match is None:
        raise HTTPException(409, "No qualifying crosswalk mapping for this suggestion")

    source = db.query(ControlImplementation).filter(
        ControlImplementation.system_id == req.system_id,
        ControlImplementation.framework_id == req.source_framework_id,
        ControlImplementation.control_id == req.source_control_id,
    ).first()
    if source is None or source.implementation_status not in SATISFIED_STATUSES:
        raise HTTPException(409, "Source implementation is not in a satisfied state")

    target = db.query(ControlImplementation).filter(
        ControlImplementation.system_id == req.system_id,
        ControlImplementation.framework_id == req.framework_id,
        ControlImplementation.control_id == req.control_id,
    ).first()
    if target is not None and target.implementation_status != "NOT_ASSESSED":
        raise HTTPException(409, "Target control already has an implementation")

    provenance = (
        f"[Crosswalk] Seeded from {req.source_framework_id} {req.source_control_id} "
        f"({match.relationship}, {match.confidence}) — review and confirm before assessment."
    )
    narrative = (source.narrative or "").strip()
    narrative = f"{provenance}\n\n{narrative}" if narrative else provenance

    if target is None:
        target = ControlImplementation(
            system_id=req.system_id,
            framework_id=req.framework_id,
            control_id=req.control_id,
        )
        db.add(target)
    target.implementation_status = "PLANNED"
    target.narrative = narrative
    target.responsible_party = source.responsible_party
    target.evidence_ids = list(source.evidence_ids or [])
    db.flush()

    audit_svc.record(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, action="CREATE", entity_type="control_implementation",
        entity_id=target.id, system_id=req.system_id,
        summary=(
            f"Accepted crosswalk suggestion: {req.framework_id}/{req.control_id} "
            f"PLANNED from {req.source_framework_id}/{req.source_control_id}"
        ),
    )
    safe_commit(db)
    return {
        "framework_id": req.framework_id,
        "control_id": req.control_id,
        "implementation_status": target.implementation_status,
    }


@router.get("/findings/{finding_id}")
def finding_impact(
    finding_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Cross-framework impact of one finding: every control in another active
    framework that maps to the finding's control, with the implementation
    status it puts at risk on the finding's system."""
    finding = db.query(Finding).filter(
        Finding.id == finding_id,
        Finding.organization_id == user.organization_id, *system_scope_filter(Finding.system_id, db, user),
    ).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    if not finding.control_id:
        return {"finding_id": finding_id, "impacts": []}

    active = _active_framework_ids(db, user.organization_id)
    entries = crosswalk_svc.resolve(db, finding.framework_id, finding.control_id, active)
    keys = {(e.framework_id, e.control_id) for e in entries}
    titles = _titles_for(db, keys)

    impls: dict[tuple[str, str], str] = {}
    if keys:
        rows = db.query(ControlImplementation).filter(
            ControlImplementation.system_id == finding.system_id,
            ControlImplementation.framework_id.in_({k[0] for k in keys}),
            ControlImplementation.control_id.in_({k[1] for k in keys}),
        ).all()
        impls = {(r.framework_id, r.control_id): r.implementation_status for r in rows}

    return {
        "finding_id": finding_id,
        "framework_id": finding.framework_id,
        "control_id": finding.control_id,
        "impacts": [
            {
                "framework_id": e.framework_id,
                "control_id": e.control_id,
                "title": titles.get((e.framework_id, e.control_id), ""),
                "relationship": e.relationship,
                "confidence": e.confidence,
                "path": e.path,
                "implementation_status": impls.get((e.framework_id, e.control_id)),
            }
            for e in entries
        ],
    }


@router.get("/{framework_id}/{control_id}")
def get_crosswalk(
    framework_id: str,
    control_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """All controls mapped to (framework_id, control_id), limited to the org's
    active frameworks. Direct edges first, then hub-transitive ones. Each
    entry carries the count of active findings on the mapped control so
    cross-framework non-compliance is visible from the catalog."""
    from routers.frameworks import require_framework_visible
    require_framework_visible(framework_id, user)
    active = _active_framework_ids(db, user.organization_id)
    entries = crosswalk_svc.resolve(db, framework_id, control_id, active)
    keys = {(e.framework_id, e.control_id) for e in entries}
    titles = _titles_for(db, keys)

    finding_counts: dict[tuple[str, str], int] = {}
    if keys:
        rows = db.query(Finding.framework_id, Finding.control_id).filter(
            Finding.organization_id == user.organization_id, *system_scope_filter(Finding.system_id, db, user),
            Finding.status.in_(ACTIVE_FINDING_STATUSES),
            Finding.framework_id.in_({k[0] for k in keys}),
            Finding.control_id.in_({k[1] for k in keys}),
        ).all()
        for fw, ctrl in rows:
            if (fw, ctrl) in keys:
                finding_counts[(fw, ctrl)] = finding_counts.get((fw, ctrl), 0) + 1

    return {
        "framework_id": framework_id,
        "control_id": control_id,
        "mappings": [
            {
                "framework_id": e.framework_id,
                "control_id": e.control_id,
                "title": titles.get((e.framework_id, e.control_id), ""),
                "relationship": e.relationship,
                "confidence": e.confidence,
                "path": e.path,
                "rationale": e.rationale,
                "open_findings": finding_counts.get((e.framework_id, e.control_id), 0),
            }
            for e in entries
        ],
    }

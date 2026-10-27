"""Permanent permission / tenancy sweep: every route x every role x
other-company x other-system.

Each API route the app registers is called over HTTP in a fresh two-company
world and must match the INTENDED matrix in ``SWEEP`` below:

1. Role gate: every role (plus an instance operator, anonymous and a revoked
   API token) is called with company-A ids on system ERP. A 401/403 means
   "denied" and anything else means "passed the gate". The set of roles that
   pass must equal the expected set. The first role expected to pass must get
   a 2xx (a positive control that proves the request is valid, so the next
   two checks mean something). This runs first, on a pristine world.
2. Other company: a company-A admin (not an operator) calls the route with
   company B's ids. The response must never contain company B's marker text.
   Where the request references a company-B object (path, query or body: a
   system, a user, a custom framework) it must be refused (non-2xx). Bulk
   routes are checked by effect instead: the B row must not change.
3. Other system: users assigned to SCADA only (assessor, system owner,
   evidence contributor, auditor) call the route with ids on another system
   (MES, kept apart from the role-sweep records). That system's marker text
   must never appear in a response. Where the request references one of its
   objects it must be refused. Every list route is also called with the other
   side's ``system_id`` filter, which probes client-supplied ids generically.

Routes are enumerated from the live app at test time, so a NEW route with no
SWEEP entry fails ``test_every_route_has_a_sweep_expectation``.

The role expectation for every route that test_permission_parity.py
classifies comes from that test's UI_ACTION_FOR, resolved through the
frontend MATRIX (lib/permissions.ts). The two tests share one source:
test_permission_parity checks that each guard is wired to the right action
(statically, against the UI). This sweep checks that the live HTTP behaviour,
including inline checks, lookups and scoping, matches it. SWEEP only gives
explicit roles for routes parity does not classify (reads, public and inline
rules).

Dimensions owned by another fix team carry an ``xfail`` note. Like
xfail(strict=True), the note turns into a failure once that dimension starts
passing, so the marker gets removed when the fix lands.

Built from the seclive team's matrix.py / attacks.py sweep (hunt, 2026-10-21).
All data is synthetic (Acme / example.com).
"""
from __future__ import annotations

import hashlib
import io
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date

import pytest
from fastapi.testclient import TestClient

from main import app
from models import (
    ApiToken, AuditEntry, CalendarEvent, Comment, ConMonEntry, Control, ControlImplementation,
    EvidenceArtifact, Finding, FrameworkActivation, IcsAdvisory, IcsAdvisoryMatch, ITAsset,
    Organization, OTAsset, RedTeamReport, RiskRegisterEntry, SavedView, System, SystemAssignment, User,
)
from models.assessment import Assessment
from services import api_token as token_svc
from services.auth import hash_password
from tests.test_permission_parity import EXEMPT, UI_ACTION_FOR, _frontend_matrix
from tests.test_permission_parity import _routes as _parity_routes

XORG = "XORGMARK"    # appears in every company-B record
SCOPE = "SCOPEMARK"  # appears in every company-A ERP record (outside the scoped users' SCADA)
PW = "Sweep-Pass-Word-77!"
FW = "sox"           # small bundled framework, active in both companies
ACTIVATE_FW = "glba"  # bundled framework NOT yet active (activate route)

ROLES_ASC = ["auditor", "evidence_contributor", "system_owner", "assessor", "compliance_manager", "admin"]
PRINCIPALS = ["anon", "revoked", *ROLES_ASC, "operator"]
SCOPED_ROLES = ["auditor", "evidence_contributor", "system_owner", "assessor"]
SESSION_ONLY = {  # need a browser session, not a bearer token
    ("POST", "/api/orgs/switch"),
    ("POST", "/api/auth/change-password"),
    ("POST", "/api/tokens"), ("DELETE", "/api/tokens/{token_id}"),  # R2SEC-1: tokens can't mint tokens
    ("POST", "/api/auth/start-fresh"),  # wipes the instance: interactive sign-in + password only
}

_PW_HASH: list[str] = []


def _pw_hash() -> str:
    if not _PW_HASH:
        _PW_HASH.append(hash_password(PW))
    return _PW_HASH[0]


# =========================================================================== expectations

@dataclass(frozen=True)
class E:
    """Intended behaviour of one route.

    roles: None = take from test_permission_parity.UI_ACTION_FOR; else
        "any" (every authenticated role), "public", "operator", or a set of
        role names ("operator" may be listed, admins are NOT implied).
    xorg / scope: "ref" = the request references an object of the other
        company / other system, which must be refused (non-2xx). "none" = the
        response must only be free of the other side's marker text. "effect" =
        bulk route; the other side's row must not change.
    positive: True, or the reason the first allowed role cannot reach 2xx in
        this hermetic world.
    owner: inline per-object rule, given as the principal that owns the target
        object (it passes even though its role does not). Denial is then
        verified by the object surviving rather than by status code.
    refused: status codes that count as refusing an other-side reference
        (default 403/404 — the authorization check itself; a body field
        validated as "not in your organization" may answer 422).
    xfail: {dimension: "ID (team): why"} for gaps another fix team owns.
    stricter: why this route is deliberately stricter than its parity action
        (the role gate passes, then an extra in-handler check narrows it), so
        explicit roles here may coexist with a parity classification.
    """
    roles: object = None
    xorg: str = "none"
    scope: str = "none"
    positive: object = True
    owner: str | None = None
    refused: tuple = (403, 404)
    xfail: dict = field(default_factory=dict)
    stricter: str = ""


ANY = "any"
R = E(xorg="ref", scope="ref")            # object route, parity-classified roles
RA = E(roles=ANY, xorg="ref", scope="ref")  # object read, any role
LA = E(roles=ANY)                         # list / org-level read, any role

NEEDS_FILE = "multipart import of a third-party file format: only the gate and refusal are swept"
OPERATOR_ONLY = "SECCODE-1: backup/restore is instance-wide, so manage:settings + instance-operator check"

SWEEP: dict[tuple[str, str], E] = {
    # ---- public / auth
    ("GET", "/api/health"): E(roles="public"),
    ("GET", "/api/auth/status"): E(roles="public"),
    ("POST", "/api/auth/login"): E(roles="public"),
    ("POST", "/api/auth/setup"): E(roles="public", positive="instance is already set up"),
    ("POST", "/api/auth/setup/demo"): E(roles="public", positive="instance is already set up"),
    ("POST", "/api/auth/logout"): E(roles="public"),
    ("POST", "/api/auth/change-password"): E(
        roles=ANY, positive="swept with a wrong current password (400): a real change would sign the sweep's users out"),
    ("GET", "/api/auth/oidc/login"): E(roles="public", positive="OIDC is not configured"),
    ("GET", "/api/auth/oidc/callback"): E(roles="public", positive="OIDC is not configured"),
    ("GET", "/api/auth/me"): LA,
    ("POST", "/api/auth/start-fresh"): E(
        roles={"operator"}, stricter="instance-wide wipe: manage:settings + instance-operator check, like restore",
        positive="the sweep world is real data, so it answers 409 (demo instances only) after the gate"),
    # ---- companies (operator = cross-company flag, not a role)
    ("GET", "/api/orgs"): LA,
    ("POST", "/api/orgs"): E(roles={"operator"}),
    ("POST", "/api/orgs/switch"): E(roles={"operator"}),
    ("GET", "/api/orgs/portfolio"): E(roles={"operator"}),
    ("PUT", "/api/orgs/branding"): E(),
    ("DELETE", "/api/orgs/branding"): E(),
    # ---- users
    ("GET", "/api/users"): E(),
    ("GET", "/api/users/assignable"): LA,
    ("POST", "/api/users"): E(),
    ("PATCH", "/api/users/{user_id}"): E(xorg="ref"),
    ("DELETE", "/api/users/{user_id}"): E(xorg="ref"),
    ("DELETE", "/api/users/{user_id}/sso"): E(xorg="ref"),
    ("GET", "/api/users/{user_id}/systems"): E(xorg="ref"),
    ("PUT", "/api/users/{user_id}/systems"): E(xorg="ref"),
    # ---- API tokens / saved views (own objects)
    ("GET", "/api/tokens"): LA,
    ("POST", "/api/tokens"): E(roles=ANY),
    ("DELETE", "/api/tokens/{token_id}"): E(roles={"admin", "operator"}, owner="auditor", xorg="ref"),
    ("GET", "/api/views"): LA,
    ("POST", "/api/views"): E(roles=ANY),
    ("DELETE", "/api/views/{view_id}"): E(roles=set(), owner="auditor", xorg="ref"),
    # ---- systems
    ("GET", "/api/systems"): LA,
    ("POST", "/api/systems"): E(xorg="ref", refused=(403, 404, 422)),  # body owner_id: 422 "not in your org"
    ("GET", "/api/systems/{system_id}"): RA,
    ("PATCH", "/api/systems/{system_id}"): R,
    ("DELETE", "/api/systems/{system_id}"): R,
    # ---- findings
    ("GET", "/api/findings"): LA,
    ("POST", "/api/findings"): R,
    ("GET", "/api/findings/{finding_id}"): RA,
    ("PATCH", "/api/findings/{finding_id}"): E(
        roles={"admin", "compliance_manager", "operator"}, xorg="ref", scope="ref",
        stricter="R2USER-12: the gate is work:own_finding so a finding's assigned owner can move its status and "
                 "milestones; any other field (the sweep edits description) still needs edit:finding. The owner "
                 "rule is covered in tests/hunts/test_w2ux.py"),
    ("DELETE", "/api/findings/{finding_id}"): R,
    ("POST", "/api/findings/bulk"): E(xorg="effect", scope="effect"),
    ("POST", "/api/findings/bulk-import/{system_id}"): R,
    # ---- evidence
    ("GET", "/api/evidence"): LA,
    ("POST", "/api/evidence/upload"): R,
    ("GET", "/api/evidence/{evidence_id}"): RA,
    ("GET", "/api/evidence/{evidence_id}/download"): RA,
    ("PATCH", "/api/evidence/{evidence_id}"): R,
    ("DELETE", "/api/evidence/{evidence_id}"): R,
    # ---- controls / catalog
    ("GET", "/api/controls"): LA,
    ("GET", "/api/controls/baselines"): LA,
    ("GET", "/api/controls/{framework_id}/{control_id}"): LA,
    ("GET", "/api/controls/systems/{system_id}"): RA,
    ("PUT", "/api/controls/systems/{system_id}/{framework_id}/{control_id}"): R,
    ("POST", "/api/controls/systems/{system_id}/bulk"): R,
    ("POST", "/api/controls/systems/{system_id}/scope"): E(
        xorg="ref", scope="ref", positive="the sweep's framework (sox) has no baselines"),
    ("POST", "/api/controls/bulk"): E(xorg="effect", scope="effect"),
    # ---- crosswalk
    ("GET", "/api/crosswalk/evidence/{evidence_id}/suggestions"): RA,
    ("GET", "/api/crosswalk/suggestions"): RA,
    ("POST", "/api/crosswalk/suggestions/accept"): E(
        xorg="ref", scope="ref", positive="needs a qualifying crosswalk mapping (409 otherwise)"),
    ("GET", "/api/crosswalk/findings/{finding_id}"): RA,
    ("GET", "/api/crosswalk/{framework_id}/{control_id}"): LA,
    # ---- frameworks
    ("GET", "/api/frameworks"): LA,
    ("GET", "/api/frameworks/{framework_id}"): LA,
    ("GET", "/api/frameworks/{framework_id}/reports"): LA,
    ("GET", "/api/frameworks/{framework_id}/assessments"): LA,
    ("POST", "/api/frameworks/{framework_id}/activate"): E(),
    ("POST", "/api/frameworks/{framework_id}/deactivate"): E(),
    ("GET", "/api/custom-frameworks"): E(),
    ("POST", "/api/custom-frameworks"): E(),
    ("GET", "/api/custom-frameworks/{framework_id}/controls"): E(xorg="ref"),
    ("PUT", "/api/custom-frameworks/{framework_id}/controls"): E(xorg="ref"),
    ("DELETE", "/api/custom-frameworks/{framework_id}"): E(xorg="ref"),
    # ---- assessments
    ("GET", "/api/assessments"): LA,
    ("POST", "/api/assessments"): R,
    ("GET", "/api/assessments/{assessment_id}"): RA,
    ("PUT", "/api/assessments/{assessment_id}"): R,
    ("DELETE", "/api/assessments/{assessment_id}"): R,
    # ---- calendar
    ("GET", "/api/calendar"): LA,
    ("POST", "/api/calendar"): R,
    ("PATCH", "/api/calendar/{event_id}"): R,
    ("DELETE", "/api/calendar/{event_id}"): R,
    # ---- comments
    ("GET", "/api/comments"): RA,
    ("POST", "/api/comments"): R,
    ("DELETE", "/api/comments/{comment_id}"): E(roles={"admin", "operator"}, owner="compliance_manager",
                                                 xorg="ref", scope="ref"),
    # ---- ConMon
    ("GET", "/api/conmon"): LA,
    ("GET", "/api/conmon/cadences"): LA,
    ("PUT", "/api/conmon/cadences"): E(),  # org-level setting
    ("POST", "/api/conmon"): R,
    ("GET", "/api/conmon/{entry_id}"): RA,
    ("PATCH", "/api/conmon/{entry_id}"): R,
    ("DELETE", "/api/conmon/{entry_id}"): R,
    # ---- assets
    ("GET", "/api/it-assets"): LA,
    ("POST", "/api/it-assets"): R,
    ("GET", "/api/it-assets/{asset_id}"): RA,
    ("PATCH", "/api/it-assets/{asset_id}"): R,
    ("DELETE", "/api/it-assets/{asset_id}"): R,
    ("POST", "/api/it-assets/bulk-import/{system_id}"): R,
    ("GET", "/api/ot-assets"): LA,
    ("POST", "/api/ot-assets"): R,
    ("GET", "/api/ot-assets/{asset_id}"): RA,
    ("PATCH", "/api/ot-assets/{asset_id}"): R,
    ("DELETE", "/api/ot-assets/{asset_id}"): R,
    ("POST", "/api/ot-assets/bulk-import/{system_id}"): R,
    ("GET", "/api/asset-import/sources"): LA,
    ("GET", "/api/asset-import/connectors"): LA,
    ("GET", "/api/asset-import/history"): LA,
    ("POST", "/api/asset-import/import"): E(xorg="ref", scope="ref"),
    ("POST", "/api/asset-import/import/confirm"): E(xorg="ref", scope="ref"),
    ("POST", "/api/asset-import/connectors/{key}/import"): E(
        xorg="ref", scope="ref", positive="no live connector is configured"),
    ("POST", "/api/asset-import/connectors/{key}/import/confirm"): E(
        xorg="ref", scope="ref", positive="no live connector is configured"),
    # ---- risks
    ("GET", "/api/risks"): LA,
    ("POST", "/api/risks"): R,
    ("GET", "/api/risks/{risk_id}"): RA,
    ("PATCH", "/api/risks/{risk_id}"): R,
    ("DELETE", "/api/risks/{risk_id}"): R,
    ("POST", "/api/risks/{risk_id}/spawn-finding"): R,
    # ---- red team
    ("GET", "/api/redteam"): LA,
    ("GET", "/api/redteam/risk-context"): LA,
    ("GET", "/api/redteam/exposure-summary"): LA,
    ("PUT", "/api/redteam/risk-context"): E(),
    ("GET", "/api/redteam/{report_id}"): RA,
    ("POST", "/api/redteam/analyze/{system_id}/{framework_id}"): R,
    ("POST", "/api/redteam/{report_id}/findings/{finding_id}/create-finding"): R,
    ("DELETE", "/api/redteam/{report_id}"): R,
    # ---- threat advisories (org-level intel; per-system matches are scoped)
    ("GET", "/api/advisories"): LA,
    ("GET", "/api/advisories/feed-status"): LA,
    ("GET", "/api/advisories/custom-feeds"): E(),
    ("PUT", "/api/advisories/custom-feeds"): E(),
    ("GET", "/api/advisories/{advisory_id}"): E(roles=ANY, xorg="ref"),
    ("PATCH", "/api/advisories/{advisory_id}"): E(xorg="ref"),
    ("POST", "/api/advisories/refresh"): E(),
    ("POST", "/api/advisories/{advisory_id}/spawn-finding"): R,
    ("POST", "/api/advisories/{advisory_id}/spawn-conmon"): R,
    ("POST", "/api/advisories/matches/{match_id}/dismiss"): R,
    ("POST", "/api/advisories/matches/{match_id}/restore"): R,
    # ---- SIEM / migration imports
    ("GET", "/api/siem/formats"): LA,
    ("GET", "/api/siem/import/history"): LA,
    ("POST", "/api/siem/import"): E(xorg="ref", scope="ref"),
    ("POST", "/api/siem/import/confirm"): E(xorg="ref", scope="ref"),
    ("POST", "/api/migration/poam"): E(xorg="ref", scope="ref"),
    ("POST", "/api/migration/ssp"): E(xorg="ref", scope="ref"),
    # ---- dashboards / reports / audit / search
    ("GET", "/api/dashboard/onboarding"): LA,
    ("GET", "/api/dashboard/snapshot"): LA,
    ("GET", "/api/dashboard/finding-aging"): LA,
    ("GET", "/api/dashboard/finding-severity"): LA,
    ("GET", "/api/dashboard/evidence-freshness"): LA,
    ("GET", "/api/dashboard/activity"): LA,
    ("GET", "/api/dashboard/compliance"): LA,
    ("GET", "/api/dashboard/history"): LA,
    ("GET", "/api/dashboard/my-work"): LA,
    ("GET", "/api/reports/findings"): LA,
    ("GET", "/api/reports/evidence"): LA,
    ("GET", "/api/reports/risks"): LA,
    ("GET", "/api/reports/conmon"): LA,
    ("GET", "/api/reports/compliance-summary"): LA,
    ("GET", "/api/reports/audit-binder"): RA,
    ("GET", "/api/reports/assessment/{assessment_id}"): RA,
    ("GET", "/api/inspection/prep"): E(roles=ANY),
    ("GET", "/api/inspection/prep/punch-list.csv"): E(roles=ANY),
    ("GET", "/api/audit"): LA,
    ("GET", "/api/audit/verify"): LA,
    ("GET", "/api/search"): LA,
    ("GET", "/api/digest/config"): E(),
    ("GET", "/api/digest/preview"): E(),
    ("POST", "/api/digest/send-test"): E(positive="SMTP is not configured"),
    # ---- backup (instance-wide)
    ("GET", "/api/backup/info"): E(roles={"operator"}, stricter=OPERATOR_ONLY),
    ("POST", "/api/backup/download"): E(roles={"operator"}, stricter=OPERATOR_ONLY),
    ("POST", "/api/backup/restore"): E(roles={"operator"}, positive="needs an archive upload",
                                       stricter=OPERATOR_ONLY),
}


def _expected_roles(key, exp: E) -> set[str]:
    """Principals expected to pass the gate."""
    if exp.roles is None:
        action = UI_ACTION_FOR[key]
        roles = set(_frontend_matrix()[action])
        if "admin" in roles:
            roles.add("operator")
    elif exp.roles == ANY:
        roles = set(ROLES_ASC) | {"operator"}
    elif exp.roles == "public":
        roles = set(PRINCIPALS)
    else:
        roles = set(exp.roles)
    if exp.owner:
        roles.add(exp.owner)
    return roles


# The app registers ~170 API routes. If enumeration ever finds fewer (e.g. a
# FastAPI release changes how included routers are stored, as 0.137 did), the
# per-route cases would silently vanish — fail loudly instead (R2SEC-15).
MIN_EXPECTED_ROUTES = 150
# A refusal of another company's / system's object must come from the
# authorization check itself (E.refused, default 403/404). Any other 4xx (e.g.
# a parser 422) can mask a missing check — the import routes did exactly that
# (R2SEC-16).


def _route_map() -> dict[tuple[str, str], object]:
    """(method, path) -> route, via the same walk as test_permission_parity
    (handles FastAPI >= 0.137's lazily included routers)."""
    return {(m, p): r for m, p, r in _parity_routes()}


def _routes() -> list[tuple[str, str]]:
    return sorted(_route_map())


# =========================================================================== world

def _user(db, org, username, role, *, display=None, operator=False):
    u = User(organization_id=org.id, username=username, password_hash=_pw_hash(), role=role,
             email=f"{username}@example.com", display_name=display or username, is_operator=operator)
    db.add(u)
    db.flush()
    return u


def _token(db, user, name="sweep"):
    raw, prefix, digest = token_svc.generate()
    t = ApiToken(organization_id=user.organization_id, user_id=user.id, name=name,
                 token_prefix=prefix, token_hash=digest)
    db.add(t)
    db.flush()
    return raw, t


def _side(db, org, system, mark, author, owner):
    """One record of every system-bound type on `system`, each carrying `mark`."""
    from services import audit as audit_svc
    ctl = db.query(Control.control_id).filter(Control.framework_id == FW).order_by(Control.control_id).first()[0]
    f = Finding(organization_id=org.id, system_id=system.id, framework_id=FW, control_id=ctl,
                title=f"Finding {mark}", severity="HIGH", status="OPEN")
    # A real stored file (with its true hash) so the download route can succeed for
    # allowed callers; the sweep then proves who may and may not fetch the bytes.
    from config import settings
    content = f"sweep evidence {mark}".encode()
    settings.evidence_dir.mkdir(parents=True, exist_ok=True)
    (settings.evidence_dir / f"{mark}.pdf").write_bytes(content)
    ev = EvidenceArtifact(organization_id=org.id, system_id=system.id, filename=f"{mark}.pdf",
                          description=f"Evidence {mark}", file_path=f"{mark}.pdf",
                          file_hash=hashlib.sha256(content).hexdigest(),
                          control_ids=[ctl], framework_ids=[FW])
    risk = RiskRegisterEntry(organization_id=org.id, system_id=system.id, title=f"Risk {mark}")
    asm = Assessment(organization_id=org.id, system_id=system.id, framework_id=FW,
                     assessment_type="SELF", notes=f"Assessment {mark}")
    cm = ConMonEntry(organization_id=org.id, system_id=system.id, entry_date=date.today(),
                     activity_type="REVIEW", description=f"ConMon {mark}")
    ev_cal = CalendarEvent(organization_id=org.id, system_id=system.id, title=f"Event {mark}",
                           event_date=date.today())
    it = ITAsset(organization_id=org.id, system_id=system.id, asset_name=f"Server {mark}")
    ot = OTAsset(organization_id=org.id, system_id=system.id, asset_name=f"PLC {mark}")
    rt = RedTeamReport(
        organization_id=org.id, system_id=system.id, framework_id=FW, run_by="sweep", summary=f"Red team {mark}",
        findings=[{"id": "RT-001", "title": f"Gap {mark}", "description": "d", "control_ids": [ctl],
                   "finding_language": {"title": f"Gap {mark}", "severity": "HIGH"}}],
        attack_chains=[])
    adv = IcsAdvisory(organization_id=org.id, advisory_id=f"DEMO-ICSA-{system.id:02d}-001", title=f"Advisory {org.slug}")
    impl = ControlImplementation(system_id=system.id, framework_id=FW, control_id=ctl,
                                 implementation_status="PARTIALLY", narrative=f"Narrative {mark}")
    db.add_all([f, ev, risk, asm, cm, ev_cal, it, ot, rt, adv, impl])
    db.flush()
    match = IcsAdvisoryMatch(advisory_id=adv.id, ot_asset_id=ot.id, system_id=system.id, confidence="HIGH")
    com = Comment(organization_id=org.id, entity_type="finding", entity_id=f.id, author_id=author.id,
                  body=f"Comment {mark}")
    view = SavedView(organization_id=org.id, user_id=owner.id, page="findings", name=f"View {mark}", params={})
    db.add_all([match, com, view])
    db.flush()
    audit_svc.record(db, organization_id=org.id, actor_id=author.id, actor_username=author.username,
                     action="CREATE", entity_type="finding", entity_id=f.id, system_id=system.id,
                     summary=f"Created finding: Finding {mark}")
    audit_svc.record(db, organization_id=org.id, actor_id=author.id, actor_username=author.username,
                     action="CREATE", entity_type="system", entity_id=system.id,
                     summary=f"Created system: {system.name}")
    return {
        "system_id": system.id, "finding_id": f.id, "evidence_id": ev.id, "risk_id": risk.id,
        "assessment_id": asm.id, "entry_id": cm.id, "event_id": ev_cal.id, "it_asset_id": it.id,
        "ot_asset_id": ot.id, "report_id": rt.id, "advisory_id": adv.id, "match_id": match.id,
        "comment_id": com.id, "view_id": view.id, "control_id": ctl, "impl_id": impl.id,
    }


def _custom_framework(org_id: int, fid: str, mark: str) -> None:
    from routers.frameworks import loader
    d = loader._custom_dir / fid
    d.mkdir(parents=True, exist_ok=True)
    (d / "metadata.json").write_text(json.dumps({
        "id": fid, "name": f"Policy {mark}", "catalog_version": "custom", "owner_organization_id": org_id}))
    (d / "catalog.json").write_text(json.dumps({"controls": [{"id": "POL-1", "title": f"Policy {mark}"}]}))


def build_world(db):
    from routers.frameworks import loader
    a = Organization(name="Acme Sweep", slug="acme-sweep")
    b = Organization(name=f"Northwind {XORG}", slug="northwind-sweep")
    db.add_all([a, b])
    db.flush()
    users = {role: _user(db, a, f"u_{role}", role) for role in ROLES_ASC}
    users["operator"] = _user(db, a, "u_operator", "admin", operator=True)
    scoped = {role: _user(db, a, f"s_{role}", role) for role in SCOPED_ROLES}
    target_a = _user(db, a, "u_target", "auditor")
    b_admin = _user(db, b, "b_admin", "admin", display=f"B admin {XORG}")
    target_b = _user(db, b, "b_target", "auditor", display=f"B target {XORG}")
    # SSO-linked targets, so the admin "Unlink SSO" route has something to unlink
    target_a.oidc_issuer = target_b.oidc_issuer = "https://idp.example.com"
    target_a.oidc_subject, target_b.oidc_subject = "sweep-a", "sweep-b"
    erp = System(organization_id=a.id, name=f"ERP {SCOPE}", acronym=f"ERP-{SCOPE}")
    mes = System(organization_id=a.id, name=f"MES {SCOPE}", acronym=f"MES-{SCOPE}")
    scada = System(organization_id=a.id, name="SCADA plant", acronym="SCADA")
    cln = System(organization_id=b.id, name=f"Clinic {XORG}", acronym=f"CLN-{XORG}")
    db.add_all([erp, mes, scada, cln])
    db.flush()
    for u in scoped.values():
        db.add(SystemAssignment(user_id=u.id, system_id=scada.id))
    for org in (a, b):
        db.add(FrameworkActivation(organization_id=org.id, framework_id=FW, is_active=True))
    loader.load_catalog(FW, db)
    loader.load_mappings(FW, db)
    side_a = _side(db, a, erp, SCOPE, author=users["compliance_manager"], owner=users["auditor"])
    side_b = _side(db, b, cln, XORG, author=b_admin, owner=b_admin)
    side_s = _side(db, a, mes, SCOPE, author=users["compliance_manager"], owner=users["auditor"])
    side_a["user_id"], side_b["user_id"], side_s["user_id"] = target_a.id, target_b.id, target_a.id
    side_a["org_id"], side_b["org_id"], side_s["org_id"] = a.id, b.id, a.id
    side_a["mark"], side_b["mark"], side_s["mark"] = SCOPE, XORG, SCOPE
    _custom_framework(a.id, "custom-sweep-a", "own")
    _custom_framework(b.id, "custom-sweep-b", XORG)
    loader.discover()
    side_a["custom_id"], side_s["custom_id"], side_b["custom_id"] = "custom-sweep-a", "custom-sweep-a", "custom-sweep-b"
    _, victim_a = _token(db, users["auditor"], "victim")
    _, victim_b = _token(db, b_admin, f"victim {XORG}")
    side_a["token_id"], side_b["token_id"] = victim_a.id, victim_b.id
    side_s["token_id"] = _token(db, users["auditor"], "victim-s")[1].id
    tokens = {p: _token(db, u)[0] for p, u in {**users, **{f"s_{r}": u for r, u in scoped.items()}}.items()}
    revoked_raw, revoked = _token(db, users["admin"], "revoked")
    from datetime import datetime, timezone
    revoked.revoked_at = datetime.now(timezone.utc)
    tokens["revoked"] = revoked_raw
    db.commit()
    return {"a": side_a, "b": side_b, "s": side_s, "tokens": tokens,
            "owner_ids": {"auditor": users["auditor"].id, "compliance_manager": users["compliance_manager"].id},
            "org_a": a.id}


# =========================================================================== requests

def _fill_path(path: str, t: dict) -> str:
    vals = dict(t)
    vals["framework_id"] = FW
    vals["key"] = "tanium"
    vals["asset_id"] = t["ot_asset_id"] if path.startswith("/api/ot-assets") else t["it_asset_id"]
    if path.startswith("/api/redteam/{report_id}/findings/"):
        vals["finding_id"] = "RT-001"
    if path.startswith("/api/custom-frameworks/"):
        vals["framework_id"] = t["custom_id"]
    if path.endswith("/activate"):
        vals["framework_id"] = ACTIVATE_FW
    out = path
    for name in [seg[1:-1] for seg in path.split("/") if seg.startswith("{")]:
        out = out.replace("{" + name + "}", str(vals[name]))
    return out


def _query(route, t: dict) -> dict:
    """Required query params, plus every optional `system_id` filter (probes
    client-supplied system ids on every list/dashboard route)."""
    candidates = {
        "q": t["mark"], "page": "findings", "entity_type": "finding", "entity_id": t["finding_id"],
        "system_id": t["system_id"], "system_ids": t["system_id"], "framework_id": FW,
    }
    out = {}
    for p in route.dependant.query_params:
        if p.name in candidates and (p.field_info.is_required() or p.name in ("system_id", "system_ids")):
            out[p.name] = candidates[p.name]
    return out


SIEM_CSV = "alert_name,severity,host\nSweep probe alert,high,h1\n"
ASSET_CSV = "Computer Name,IP Address,Operating System\nsweep-ws-1,10.0.0.5,Windows\n"
POAM_CSV = "Weakness Name,Severity\nSweep probe weakness,High\n"


def _csv(text: str):
    return {"file": ("sweep.csv", io.BytesIO(text.encode()), "text/csv")}


def _body(method: str, path: str, t: dict, w: dict):
    """(json, data, files) for a mutating request against target ids t."""
    sid, fid, ctl = t["system_id"], t["finding_id"], t["control_id"]
    J = {
        ("POST", "/api/auth/login"): {"username": "u_auditor", "password": PW},
        ("POST", "/api/auth/change-password"): {"current_password": "not-the-password", "new_password": "Sweep-New-Pass-88!"},
        ("POST", "/api/auth/setup"): {"setup_token": "x", "username": "setupuser", "password": PW,
                                      "organization_name": "Acme"},
        ("POST", "/api/auth/setup/demo"): {"setup_token": "x"},
        ("POST", "/api/auth/start-fresh"): {"password": PW, "confirm": "START FRESH"},
        ("POST", "/api/orgs"): {"name": "Sweep Co"},
        ("POST", "/api/orgs/switch"): {"org_id": w["b"]["org_id"]},
        ("PUT", "/api/orgs/branding"): {"logo_data_uri": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="},
        ("POST", "/api/users"): {"username": "sweep_new", "password": PW, "role": "auditor"},
        ("PATCH", "/api/users/{user_id}"): {"display_name": "renamed"},
        ("PUT", "/api/users/{user_id}/systems"): {"system_ids": [sid]},
        ("POST", "/api/tokens"): {"name": "probe"},
        ("POST", "/api/views"): {"page": "findings", "name": "probe", "params": {}},
        ("POST", "/api/systems"): {"name": "Probe system", "owner_id": t["user_id"]},
        ("PATCH", "/api/systems/{system_id}"): {"description": "probe", "owner_id": t["user_id"]},
        ("POST", "/api/findings"): {"system_id": sid, "framework_id": FW, "title": "probe", "owner_id": t["user_id"]},
        ("PATCH", "/api/findings/{finding_id}"): {"description": "probe"},
        ("POST", "/api/findings/bulk"): {"ids": [fid], "status": "IN_PROGRESS"},
        ("POST", "/api/findings/bulk-import/{system_id}"): {"rows": [{"title": "probe"}], "commit": False},
        ("PATCH", "/api/evidence/{evidence_id}"): {"description": "probe"},
        ("PUT", "/api/controls/systems/{system_id}/{framework_id}/{control_id}"): {"implementation_status": "IMPLEMENTED"},
        ("POST", "/api/controls/systems/{system_id}/bulk"): {"framework_id": FW, "control_ids": [ctl],
                                                             "implementation_status": "IMPLEMENTED"},
        ("POST", "/api/controls/systems/{system_id}/scope"): {"framework_id": FW, "baseline": "MODERATE"},
        ("POST", "/api/controls/bulk"): {"targets": [{"system_id": sid, "framework_id": FW, "control_id": ctl}],
                                         "implementation_status": "IMPLEMENTED"},
        ("POST", "/api/crosswalk/suggestions/accept"): {"system_id": sid, "framework_id": FW, "control_id": ctl,
                                                        "source_framework_id": FW, "source_control_id": ctl},
        ("POST", "/api/frameworks/{framework_id}/activate"): {},
        ("POST", "/api/custom-frameworks"): {"name": "Sweep Policy"},
        ("PUT", "/api/custom-frameworks/{framework_id}/controls"): {"controls": []},
        ("POST", "/api/assessments"): {"system_id": sid, "framework_id": FW, "assessment_type": "SELF",
                                       "assessor_id": t["user_id"]},
        ("PUT", "/api/assessments/{assessment_id}"): {"notes": "probe"},
        ("POST", "/api/calendar"): {"title": "probe", "event_date": "2026-12-01", "system_id": sid},
        ("PATCH", "/api/calendar/{event_id}"): {"title": "probe"},
        ("POST", "/api/comments"): {"entity_type": "finding", "entity_id": fid, "body": "probe"},
        ("PUT", "/api/conmon/cadences"): {"framework_id": FW, "activity_type": "REVIEW", "interval_days": 30},
        ("POST", "/api/conmon"): {"system_id": sid, "entry_date": date.today().isoformat(),
                                  "activity_type": "REVIEW", "description": "probe"},
        ("PATCH", "/api/conmon/{entry_id}"): {"description": "probe"},
        ("POST", "/api/it-assets"): {"system_id": sid, "asset_name": "probe"},
        ("PATCH", "/api/it-assets/{asset_id}"): {"notes": "probe"},
        ("POST", "/api/it-assets/bulk-import/{system_id}"): {"rows": [{"asset_name": "probe"}], "commit": False},
        ("POST", "/api/ot-assets"): {"system_id": sid, "asset_name": "probe"},
        ("PATCH", "/api/ot-assets/{asset_id}"): {"notes": "probe"},
        ("POST", "/api/ot-assets/bulk-import/{system_id}"): {"rows": [{"asset_name": "probe"}], "commit": False},
        ("POST", "/api/risks"): {"system_id": sid, "title": "probe"},
        ("PATCH", "/api/risks/{risk_id}"): {"description": "probe"},
        ("POST", "/api/risks/{risk_id}/spawn-finding"): {},
        ("PUT", "/api/redteam/risk-context"): {"industry": "manufacturing"},
        ("PUT", "/api/advisories/custom-feeds"): {"feeds": []},
        ("PATCH", "/api/advisories/{advisory_id}"): {"notes": "probe"},
        ("POST", "/api/advisories/{advisory_id}/spawn-finding"): {"system_id": sid},
        ("POST", "/api/advisories/{advisory_id}/spawn-conmon"): {"system_id": sid},
    }
    form_sys = {"system_id": str(sid), "framework_id": FW}
    siem_form = {**form_sys, "format_override": "splunk_csv"}
    asset_form = {**form_sys, "source_override": "tanium_csv"}
    MP = {
        ("POST", "/api/evidence/upload"): (form_sys, {"file": ("sweep.txt", io.BytesIO(b"sweep evidence"), "text/plain")}),
        # Valid files, so the positive control runs and the company/system
        # refusals are proven by the handler, not by a parser 422 (R2SEC-16).
        ("POST", "/api/asset-import/import"): (asset_form, _csv(ASSET_CSV)),
        ("POST", "/api/asset-import/import/confirm"): (asset_form, _csv(ASSET_CSV)),
        ("POST", "/api/asset-import/connectors/{key}/import"): (form_sys, None),
        ("POST", "/api/asset-import/connectors/{key}/import/confirm"): (form_sys, None),
        ("POST", "/api/siem/import"): (siem_form, _csv(SIEM_CSV)),
        ("POST", "/api/siem/import/confirm"): (siem_form, _csv(SIEM_CSV)),
        ("POST", "/api/migration/poam"): (form_sys, _csv(POAM_CSV)),
        ("POST", "/api/migration/ssp"): (form_sys, _csv(f"control_id,status\n{ctl},Implemented\n")),
        ("POST", "/api/backup/restore"): ({}, None),
    }
    key = (method, path)
    if key in MP:
        data, files = MP[key]
        return None, data, files
    return J.get(key, {}), None, None


def _client():
    # The conftest `client` fixture installs the get_db override; this client
    # records 500s instead of raising so they show up as sweep failures.
    return TestClient(app, raise_server_exceptions=False)


def _call(c, db, w, principal, method, path, t, route):
    db.expire_all()
    headers = {}
    c.cookies.clear()
    if (method, path) in SESSION_ONLY and principal not in ("anon", "revoked"):
        username = "u_operator" if principal == "operator" else (
            principal if principal.startswith("s_") else f"u_{principal}")
        r = c.post("/api/auth/login", json={"username": username, "password": PW})
        assert r.status_code == 200, r.text
        headers["X-CSRF-Token"] = c.cookies.get("universal_csrf")
    elif principal != "anon":
        headers["Authorization"] = f"Bearer {w['tokens'][principal]}"
    js, data, files = _body(method, path, t, w) if method != "GET" else (None, None, None)
    kwargs = {"params": _query(route, t), "headers": headers}
    if files is not None or data is not None:
        kwargs.update(data=data or {}, files=files)
    elif js is not None:
        kwargs["json"] = js
    r = c.request(method, _fill_path(path, t), **kwargs)
    if r.status_code >= 500:
        db.rollback()
    c.cookies.clear()
    return r


# ---- effect checks for bulk routes: the foreign row must not change

def _snapshot(db, path, t):
    db.expire_all()
    if path == "/api/findings/bulk":
        return db.get(Finding, t["finding_id"]).status
    if path == "/api/controls/bulk":
        return db.get(ControlImplementation, t["impl_id"]).implementation_status
    raise AssertionError(f"no effect snapshot for {path}")


def _fresh_owned_object(db, path, w) -> None:
    """Re-create the owned target (token / view / comment) so every principal
    is judged against an object that exists."""
    t, a = w["a"], w["org_a"]
    if path.startswith("/api/tokens/"):
        owner = db.get(User, w["owner_ids"]["auditor"])
        t["token_id"] = _token(db, owner, "victim")[1].id
    elif path.startswith("/api/views/"):
        v = SavedView(organization_id=a, user_id=w["owner_ids"]["auditor"], page="findings", name="v", params={})
        db.add(v)
        db.flush()
        t["view_id"] = v.id
    elif path.startswith("/api/comments/"):
        cm = Comment(organization_id=a, entity_type="finding", entity_id=t["finding_id"],
                     author_id=w["owner_ids"]["compliance_manager"], body="c")
        db.add(cm)
        db.flush()
        t["comment_id"] = cm.id
    db.commit()


def _owned_object_survives(db, path, t) -> bool:
    db.expire_all()
    if path.startswith("/api/tokens/"):
        tok = db.get(ApiToken, t["token_id"])
        return tok is not None and tok.revoked_at is None
    if path.startswith("/api/views/"):
        return db.get(SavedView, t["view_id"]) is not None
    if path.startswith("/api/comments/"):
        return db.get(Comment, t["comment_id"]) is not None
    raise AssertionError(f"no owner check for {path}")


# =========================================================================== tests

def test_the_sweep_enumerates_every_route():
    """An empty or shrunken parametrisation must not pass silently."""
    n = len(_routes())
    assert n >= MIN_EXPECTED_ROUTES, (
        f"only {n} API routes enumerated (expected >= {MIN_EXPECTED_ROUTES}): the route walk no longer "
        "sees the app's routers, so the per-route permission cases would be skipped")
    assert n == len(SWEEP), f"{n} live routes vs {len(SWEEP)} SWEEP entries"


def test_every_route_has_a_sweep_expectation():
    live = set(_routes())
    missing = sorted(f"{m} {p}" for m, p in live - set(SWEEP))
    stale = sorted(f"{m} {p}" for m, p in set(SWEEP) - live)
    assert not missing, (
        "New routes need an intended-permission entry in SWEEP (tests/hunts/test_permission_sweep.py): "
        f"{missing}")
    assert not stale, f"SWEEP lists routes that no longer exist: {stale}"


def test_role_source_is_unambiguous():
    """roles=None means 'from test_permission_parity'; such routes must be
    classified there, and parity-classified routes may only be overridden
    here when another team's xfail explains why they still differ."""
    problems = []
    for key, exp in SWEEP.items():
        in_parity = key in UI_ACTION_FOR
        if exp.roles is None and not in_parity:
            problems.append(f"{key}: roles=None but not in test_permission_parity.UI_ACTION_FOR")
        if exp.roles is not None and in_parity and "role" not in exp.xfail and not exp.stricter:
            problems.append(f"{key}: roles given here AND in test_permission_parity — keep one source")
        if key in EXEMPT and exp.roles is None:
            problems.append(f"{key}: parity-exempt route needs explicit roles here")
    assert not problems, "\n".join(problems)


@pytest.fixture
def custom_dir(tmp_path, monkeypatch, request):
    """Company-owned custom frameworks live in a per-test dir."""
    from config import settings
    from routers.frameworks import loader
    monkeypatch.setattr(settings, "data_dir", tmp_path)
    monkeypatch.setattr(loader, "_custom_dir", tmp_path / "custom_frameworks")
    request.addfinalizer(lambda: loader.discover())  # runs after monkeypatch undo
    return tmp_path / "custom_frameworks"


@pytest.mark.parametrize("method,path", _routes(), ids=lambda v: v)
def test_route_matches_intended_matrix(method, path, client, db, custom_dir):
    key = (method, path)
    exp = SWEEP.get(key)
    if exp is None:
        pytest.fail(f"{method} {path} has no SWEEP expectation (see test_every_route_has_a_sweep_expectation)")
    route = _route_map()[key]
    w = build_world(db)
    c = _client()
    fails: dict[str, list[str]] = defaultdict(list)

    def mark_check(dim, r, mark, who):
        if mark in r.text:
            fails[dim].append(f"{who}: response contains {mark} (status {r.status_code})")
        if r.status_code >= 500:
            fails["errors"].append(f"{who}: HTTP {r.status_code}")

    is_public = exp.roles == "public"

    # ---- 1. role gate + positive control, least privileged first
    expected = _expected_roles(key, exp)
    passed, positive_done = set(), False
    for p in PRINCIPALS:
        if exp.owner:
            _fresh_owned_object(db, path, w)
        r = _call(c, db, w, p, method, path, w["a"], route)
        if r.status_code >= 500:
            fails["errors"].append(f"{p}: HTTP {r.status_code}")
        if exp.owner:
            # per-object rule: judged by effect (403 and 404 both mean "not yours")
            gate = not _owned_object_survives(db, path, w["a"])
        else:
            gate = r.status_code not in (401, 403)
        if gate:
            passed.add(p)
        if p in expected and not positive_done and p not in ("anon", "revoked"):
            positive_done = True
            if exp.positive is True and not r.is_success:
                fails["positive"].append(f"{p} (first allowed) got {r.status_code}: {r.text[:200]}")
    if passed != expected:
        fails["role"].append(f"passed the gate: {sorted(passed)}; intended: {sorted(expected)}")

    # ---- 2. other company: A's (non-operator) admin with B's ids
    if not is_public:
        before = _snapshot(db, path, w["b"]) if exp.xorg == "effect" else None
        r = _call(c, db, w, "admin", method, path, w["b"], route)
        mark_check("xorg", r, XORG, "company-A admin with company-B ids")
        if exp.xorg == "ref" and r.status_code not in exp.refused:
            fails["xorg"].append(f"company-A admin with company-B ids got {r.status_code} (expected {exp.refused})")
        if exp.xorg == "effect" and _snapshot(db, path, w["b"]) != before:
            fails["xorg"].append("company-A admin changed a company-B row through a bulk route")

    # ---- 3. other system: SCADA-only users with ids on another system (MES)
    if not is_public:
        for role in SCOPED_ROLES:
            before = _snapshot(db, path, w["s"]) if exp.scope == "effect" else None
            r = _call(c, db, w, f"s_{role}", method, path, w["s"], route)
            mark_check("scope", r, SCOPE, f"SCADA-only {role} with MES ids")
            if exp.scope == "ref" and r.status_code not in exp.refused:
                fails["scope"].append(f"SCADA-only {role} with MES ids got {r.status_code} (expected {exp.refused})")
            if exp.scope == "effect" and _snapshot(db, path, w["s"]) != before:
                fails["scope"].append(f"SCADA-only {role} changed a MES row through a bulk route")

    # ---- verdict, with per-dimension xfail notes for other teams' gaps
    for dim, note in exp.xfail.items():
        if fails.get(dim):
            fails.pop(dim)
            if not fails:
                pytest.xfail(note)
        else:
            fails["xpass"].append(f"{dim} now passes — remove the xfail note: {note}")
    assert not fails, f"{method} {path}\n" + "\n".join(
        f"  [{dim}] {msg}" for dim, msgs in fails.items() for msg in msgs)

"""Frontend permission map ↔ backend endpoint guards must not drift.

The UI decides which buttons/editors to show from frontend/src/lib/permissions.ts
(`can(role, action)` / `useCan(action)`). The server decides from the
require_can / require_role / require_min_role dependency on each route. When
the two disagree, users either see controls that 403 (e.g. an auditor offered
"Refresh feeds") or are denied controls the server would allow (assessors
could not assess controls because the page used a generic admin/CM "write"
gate while the API requires assess:control).

This test evaluates every route's real guard against each role and compares it
with the frontend action the UI uses for that endpoint. A new mutating route
must be classified here, so it cannot silently ship without a UI gate decision.
"""
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute

from main import app
from services.permissions import MATRIX as BACKEND_MATRIX

ROLES = ["admin", "compliance_manager", "assessor", "system_owner", "evidence_contributor", "auditor"]
PERMISSIONS_TS = Path(__file__).resolve().parents[2] / "frontend" / "src" / "lib" / "permissions.ts"

# (method, path) → the frontend action the UI gates that call on.
UI_ACTION_FOR: dict[tuple[str, str], str] = {
    # Findings (incl. imports that create findings)
    ("POST", "/api/findings"): "edit:finding",
    # Coarse guard: the assigned owner may work their own finding (R2USER-12);
    # every other field is re-checked against edit:finding inside the handler.
    ("PATCH", "/api/findings/{finding_id}"): "work:own_finding",
    ("POST", "/api/findings/bulk"): "edit:finding",
    ("DELETE", "/api/findings/{finding_id}"): "edit:finding",
    ("POST", "/api/findings/bulk-import/{system_id}"): "edit:finding",
    ("POST", "/api/siem/import"): "edit:finding",
    ("POST", "/api/siem/import/confirm"): "edit:finding",
    ("POST", "/api/migration/poam"): "edit:finding",
    # Evidence
    ("POST", "/api/evidence/upload"): "upload:evidence",
    ("PATCH", "/api/evidence/{evidence_id}"): "upload:evidence",
    ("DELETE", "/api/evidence/{evidence_id}"): "delete:evidence",
    # ConMon + threat-advisory triage
    ("PUT", "/api/conmon/cadences"): "edit:conmon",
    ("POST", "/api/conmon"): "edit:conmon",
    ("PATCH", "/api/conmon/{entry_id}"): "edit:conmon",
    ("DELETE", "/api/conmon/{entry_id}"): "edit:conmon",
    ("PATCH", "/api/advisories/{advisory_id}"): "edit:conmon",
    ("POST", "/api/advisories/refresh"): "edit:conmon",
    ("POST", "/api/advisories/{advisory_id}/spawn-finding"): "edit:finding",
    ("POST", "/api/advisories/{advisory_id}/spawn-conmon"): "edit:conmon",
    ("POST", "/api/advisories/matches/{match_id}/dismiss"): "edit:conmon",
    ("POST", "/api/advisories/matches/{match_id}/restore"): "edit:conmon",
    # Systems + asset inventory
    ("POST", "/api/systems"): "edit:system",
    ("PATCH", "/api/systems/{system_id}"): "edit:system",
    ("DELETE", "/api/systems/{system_id}"): "delete:system",
    ("POST", "/api/it-assets"): "edit:system",
    ("PATCH", "/api/it-assets/{asset_id}"): "edit:system",
    ("DELETE", "/api/it-assets/{asset_id}"): "edit:system",
    ("POST", "/api/it-assets/bulk-import/{system_id}"): "edit:system",
    ("POST", "/api/ot-assets"): "edit:system",
    ("PATCH", "/api/ot-assets/{asset_id}"): "edit:system",
    ("DELETE", "/api/ot-assets/{asset_id}"): "edit:system",
    ("POST", "/api/ot-assets/bulk-import/{system_id}"): "edit:system",
    ("POST", "/api/asset-import/import"): "edit:system",
    ("POST", "/api/asset-import/import/confirm"): "edit:system",
    ("POST", "/api/asset-import/connectors/{key}/import"): "edit:system",
    ("POST", "/api/asset-import/connectors/{key}/import/confirm"): "edit:system",
    # Risk register
    ("POST", "/api/risks"): "edit:risk",
    ("PATCH", "/api/risks/{risk_id}"): "edit:risk",
    ("DELETE", "/api/risks/{risk_id}"): "edit:risk",
    ("POST", "/api/risks/{risk_id}/spawn-finding"): "edit:finding",
    # Control assessment
    ("POST", "/api/controls/bulk"): "assess:control",
    ("POST", "/api/controls/systems/{system_id}/scope"): "assess:control",
    ("PUT", "/api/controls/systems/{system_id}/{framework_id}/{control_id}"): "assess:control",
    ("POST", "/api/controls/systems/{system_id}/bulk"): "assess:control",
    ("POST", "/api/crosswalk/suggestions/accept"): "assess:control",
    ("POST", "/api/migration/ssp"): "assess:control",
    # Assessments
    ("POST", "/api/assessments"): "edit:assessment",
    ("PUT", "/api/assessments/{assessment_id}"): "edit:assessment",
    ("DELETE", "/api/assessments/{assessment_id}"): "delete:assessment",
    # Calendar
    ("POST", "/api/calendar"): "edit:calendar",
    ("PATCH", "/api/calendar/{event_id}"): "edit:calendar",
    ("DELETE", "/api/calendar/{event_id}"): "delete:calendar",
    # Red team
    ("POST", "/api/redteam/analyze/{system_id}/{framework_id}"): "run:redteam",
    ("POST", "/api/redteam/{report_id}/findings/{finding_id}/create-finding"): "edit:finding",
    ("PUT", "/api/redteam/risk-context"): "manage:redteam",
    ("DELETE", "/api/redteam/{report_id}"): "manage:redteam",
    # Framework catalog
    ("POST", "/api/frameworks/{framework_id}/activate"): "manage:frameworks",
    ("POST", "/api/frameworks/{framework_id}/deactivate"): "manage:frameworks",
    ("GET", "/api/custom-frameworks"): "manage:frameworks",
    ("POST", "/api/custom-frameworks"): "manage:frameworks",
    ("GET", "/api/custom-frameworks/{framework_id}/controls"): "manage:frameworks",
    ("PUT", "/api/custom-frameworks/{framework_id}/controls"): "manage:frameworks",
    ("DELETE", "/api/custom-frameworks/{framework_id}"): "manage:frameworks",
    # Organization settings (admin)
    ("PUT", "/api/orgs/branding"): "manage:settings",
    ("DELETE", "/api/orgs/branding"): "manage:settings",
    ("GET", "/api/backup/info"): "manage:settings",
    ("POST", "/api/backup/download"): "manage:settings",
    ("POST", "/api/backup/restore"): "manage:settings",
    ("POST", "/api/auth/start-fresh"): "manage:settings",  # demo instances only (Settings -> Start fresh)
    ("GET", "/api/advisories/custom-feeds"): "manage:settings",
    ("PUT", "/api/advisories/custom-feeds"): "manage:settings",
    ("POST", "/api/digest/send-test"): "manage:settings",
    ("GET", "/api/digest/config"): "view:digest",
    ("GET", "/api/digest/preview"): "view:digest",
    # Comments (scope-checked via the parent; auditors read only)
    ("POST", "/api/comments"): "post:comment",
    # Users
    ("POST", "/api/users"): "manage:users",
    ("PATCH", "/api/users/{user_id}"): "manage:users",
    ("DELETE", "/api/users/{user_id}"): "manage:users",
    ("DELETE", "/api/users/{user_id}/sso"): "manage:users",
    ("GET", "/api/users"): "view:users",
    ("GET", "/api/users/{user_id}/systems"): "assign:systems",
    ("PUT", "/api/users/{user_id}/systems"): "assign:systems",
}

# Routes deliberately not gated by role (reason in the comment). The UI mirrors
# any per-object rule (comment author/admin delete, own tokens/views).
EXEMPT: set[tuple[str, str]] = {
    ("POST", "/api/auth/setup"),            # unauthenticated first-run (setup token)
    ("POST", "/api/auth/setup/demo"),       # first-run "Explore with demo data" (same setup token)
    ("POST", "/api/auth/login"),
    ("POST", "/api/auth/logout"),
    ("POST", "/api/auth/change-password"),  # any signed-in user, own account only (current password required)
    ("POST", "/api/tokens"),                # any user mints their own token
    ("DELETE", "/api/tokens/{token_id}"),   # inline: owner or admin
    ("GET", "/api/tokens"),                 # inline: admin sees all, others own
    ("DELETE", "/api/comments/{comment_id}"),  # inline: author or admin
    ("POST", "/api/views"),                 # personal saved views
    ("DELETE", "/api/views/{view_id}"),
    ("POST", "/api/orgs"),                  # inline: is_operator flag, not a role
    ("POST", "/api/orgs/switch"),           # inline: is_operator flag, not a role
}

MUTATING = {"POST", "PUT", "PATCH", "DELETE"}


def _frontend_matrix() -> dict[str, set[str]]:
    if not PERMISSIONS_TS.is_file():
        pytest.skip("frontend/src/lib/permissions.ts not present in this checkout")
    src = PERMISSIONS_TS.read_text()
    body = re.search(r"const MATRIX[^=]*=\s*\{(.*?)\n\}", src, re.S)
    assert body, "could not find the MATRIX literal in permissions.ts"
    matrix = {}
    for action, roles in re.findall(r"'([a-z_:]+)':\s*new Set\(\[([^\]]*)\]\)", body.group(1)):
        matrix[action] = set(re.findall(r"'([a-z_]+)'", roles))
    assert matrix, "parsed an empty MATRIX from permissions.ts"
    return matrix


def _checkers(dependant):
    for dep in dependant.dependencies:
        call = dep.call
        if getattr(call, "__module__", "") == "dependencies" and call.__qualname__.endswith(".<locals>.checker"):
            yield call
        yield from _checkers(dep)


def _routes():
    # FastAPI >= 0.137 keeps included routers as lazy _IncludedRouter entries
    # in app.routes; iter_route_contexts flattens them to the effective routes
    # (full path + methods). Older FastAPI lists APIRoute objects directly.
    try:
        from fastapi.routing import iter_route_contexts
    except ImportError:
        iter_route_contexts = None
    if iter_route_contexts is None:
        for r in app.routes:
            if isinstance(r, APIRoute):
                for m in r.methods - {"HEAD", "OPTIONS"}:
                    yield m, r.path, r
        return
    for rc in iter_route_contexts(app.routes):
        if isinstance(rc.original_route, APIRoute):
            route = rc if getattr(rc, "dependant", None) is not None else rc.original_route
            for m in (rc.methods or set()) - {"HEAD", "OPTIONS"}:
                yield m, rc.path, route


def _effective_roles(route) -> set[str] | None:
    """Roles the route's dependency guards admit; None = no role guard."""
    checkers = list(_checkers(route.dependant))
    if not checkers:
        return None
    allowed = set()
    for role in ROLES:
        try:
            for chk in checkers:
                chk(user=SimpleNamespace(role=role, is_operator=False))
        except HTTPException as e:
            assert e.status_code == 403
            continue
        allowed.add(role)
    return allowed


def test_every_mutating_or_role_guarded_route_is_classified():
    unclassified = []
    for method, path, route in _routes():
        key = (method, path)
        if key in UI_ACTION_FOR or key in EXEMPT:
            continue
        if method in MUTATING or _effective_roles(route) is not None:
            unclassified.append(f"{method} {path}")
    assert not unclassified, (
        "New role-guarded/mutating routes need a UI gate decision — add them to "
        f"UI_ACTION_FOR (and the frontend MATRIX) or EXEMPT: {unclassified}"
    )


def test_classified_routes_exist():
    live = {(m, p) for m, p, _ in _routes()}
    stale = sorted(f"{m} {p}" for m, p in (set(UI_ACTION_FOR) | EXEMPT) - live)
    assert not stale, f"mapping lists routes that no longer exist: {stale}"


def test_frontend_matrix_matches_each_endpoint_guard():
    fe = _frontend_matrix()
    by_key = {(m, p): r for m, p, r in _routes()}
    mismatches = []
    for key, action in UI_ACTION_FOR.items():
        route = by_key.get(key)
        if route is None:
            continue
        backend = _effective_roles(route)
        backend = set(ROLES) if backend is None else backend
        frontend = fe.get(action)
        if frontend is None:
            mismatches.append(f"{key[0]} {key[1]}: frontend has no '{action}' action")
        elif frontend != backend:
            mismatches.append(
                f"{key[0]} {key[1]}: UI '{action}' = {sorted(frontend)} but server allows {sorted(backend)}"
            )
    assert not mismatches, "\n".join(mismatches)


def test_shared_action_names_have_identical_roles():
    fe = _frontend_matrix()
    diff = {a: (sorted(fe.get(a, set())), sorted(r)) for a, r in BACKEND_MATRIX.items() if fe.get(a) != r}
    assert not diff, f"frontend vs backend MATRIX differ: {diff}"


def test_no_orphan_frontend_actions():
    fe = _frontend_matrix()
    used = set(UI_ACTION_FOR.values()) | set(BACKEND_MATRIX)
    assert not (set(fe) - used), f"frontend actions with no backend counterpart: {sorted(set(fe) - used)}"


def test_route_walk_sees_the_app():
    """R2SEC-15/R2DATA-18: if the walk stops seeing the included routers (a
    FastAPI storage change), every check here would pass vacuously."""
    assert len(list(_routes())) >= 150

"""Multi-company (operator org-switch) behavior.

Operators can list/create companies and switch the active company; the switch is
applied in-memory in get_current_user so the whole app re-scopes. Regular users
stay locked to their one company.
"""
import pytest

from models import Control, FrameworkActivation, Organization, User, System, Finding
from services.auth import hash_password


def _login(client, username, password):
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return client.cookies.get("universal_csrf")


def _h(csrf):
    return {"X-CSRF-Token": csrf} if csrf else {}


@pytest.fixture
def multi(db):
    """Two companies (A/B) with a finding each, plus an operator (home = A) and a
    non-operator admin in A."""
    orgA = Organization(name="Alpha Co", slug="alpha")
    orgB = Organization(name="Beta Co", slug="beta")
    db.add_all([orgA, orgB])
    db.flush()

    operator = User(organization_id=orgA.id, username="op", role="admin",
                    is_operator=True, display_name="Operator",
                    password_hash=hash_password("oppass1234!"))
    adminA = User(organization_id=orgA.id, username="alphaadmin", role="admin",
                  display_name="Alpha Admin", password_hash=hash_password("apass1234!"))
    db.add_all([operator, adminA])
    db.flush()

    sysA = System(organization_id=orgA.id, name="Alpha System", acronym="ASYS")
    sysB = System(organization_id=orgB.id, name="Beta System", acronym="BSYS")
    db.add_all([sysA, sysB])
    db.flush()

    db.add_all([
        Finding(organization_id=orgA.id, system_id=sysA.id, framework_id="nist-800-53-r5",
                control_id="AC-1", title="Alpha finding", severity="HIGH", status="OPEN"),
        Finding(organization_id=orgB.id, system_id=sysB.id, framework_id="nist-800-53-r5",
                control_id="AC-1", title="Beta finding", severity="HIGH", status="OPEN"),
        # Company numbers count findings of active frameworks with a loaded catalog (R2DATA-6).
        FrameworkActivation(organization_id=orgA.id, framework_id="nist-800-53-r5", is_active=True),
        FrameworkActivation(organization_id=orgB.id, framework_id="nist-800-53-r5", is_active=True),
        Control(framework_id="nist-800-53-r5", control_id="AC-1", title="Policy and procedures"),
    ])
    db.commit()
    return {"orgA": orgA, "orgB": orgB, "operator": operator, "adminA": adminA,
            "sysA": sysA, "sysB": sysB}


def _titles(client):
    return {f["title"] for f in client.get("/api/findings").json()}


# 1. Isolation baseline
def test_non_operator_sees_only_own_company(client, multi):
    _login(client, "alphaadmin", "apass1234!")
    assert _titles(client) == {"Alpha finding"}


# 2. Operator switch happy path
def test_operator_switch_rescopes_everything(client, multi):
    csrf = _login(client, "op", "oppass1234!")
    assert _titles(client) == {"Alpha finding"}  # home = A
    r = client.post("/api/orgs/switch", json={"org_id": multi["orgB"].id}, headers=_h(csrf))
    assert r.status_code == 200
    assert r.json()["active_organization_id"] == multi["orgB"].id
    assert _titles(client) == {"Beta finding"}  # now B only
    me = client.get("/api/auth/me").json()
    assert me["organization_id"] == multi["orgB"].id
    assert me["organization_name"] == "Beta Co"


# 3. Operator write lands in the active company
def test_operator_write_lands_in_active_company(client, db, multi):
    csrf = _login(client, "op", "oppass1234!")
    client.post("/api/orgs/switch", json={"org_id": multi["orgB"].id}, headers=_h(csrf))
    r = client.post("/api/systems", json={"name": "New B System", "acronym": "NBS"}, headers=_h(csrf))
    assert r.status_code == 200
    new = db.query(System).filter(System.name == "New B System").first()
    assert new.organization_id == multi["orgB"].id


# 4. Non-operator cannot switch
def test_non_operator_switch_forbidden(client, multi):
    csrf = _login(client, "alphaadmin", "apass1234!")
    r = client.post("/api/orgs/switch", json={"org_id": multi["orgB"].id}, headers=_h(csrf))
    assert r.status_code == 403


# 5. Switch to a company that does not exist
def test_switch_unknown_company_404(client, multi):
    csrf = _login(client, "op", "oppass1234!")
    r = client.post("/api/orgs/switch", json={"org_id": 999999}, headers=_h(csrf))
    assert r.status_code == 404


# 6. Company deleted mid-session → fall back to home
def test_switch_then_company_deleted_falls_back_home(client, db, multi):
    csrf = _login(client, "op", "oppass1234!")
    client.post("/api/orgs/switch", json={"org_id": multi["orgB"].id}, headers=_h(csrf))
    db.delete(db.query(Organization).filter(Organization.id == multi["orgB"].id).first())
    db.commit()
    # No 500, and scoping reverts to the operator's home company.
    r = client.get("/api/findings")
    assert r.status_code == 200
    assert _titles(client) == {"Alpha finding"}


# 7. Operator demoted mid-session → active org ignored
def test_demoted_operator_ignores_active_org(client, db, multi):
    csrf = _login(client, "op", "oppass1234!")
    client.post("/api/orgs/switch", json={"org_id": multi["orgB"].id}, headers=_h(csrf))
    op = db.query(User).filter(User.username == "op").first()
    op.is_operator = False
    db.commit()
    me = client.get("/api/auth/me").json()
    assert me["organization_id"] == multi["orgA"].id  # home, not B


# 8. The override is never persisted to the operator's home org
def test_switch_does_not_persist_home_org(client, db, multi):
    csrf = _login(client, "op", "oppass1234!")
    client.post("/api/orgs/switch", json={"org_id": multi["orgB"].id}, headers=_h(csrf))
    client.get("/api/findings")  # a switched request
    # Expire the shared session's identity map so the operator row is re-read from
    # committed DB state (the in-memory override is never committed). Home org
    # must be unchanged. (Production uses a fresh session per request, so the
    # override is discarded at request end regardless.)
    db.expire_all()
    row = db.query(User).filter(User.username == "op").first()
    assert row.organization_id == multi["orgA"].id


# 8b. A commit-bearing write while switched must not move the operator's home org
def test_switched_write_does_not_move_home_org(client, db, multi):
    """Regression: the override was once a plain (dirty) assignment, so any
    endpoint that committed while switched flushed it and permanently re-homed
    the operator. set_committed_value keeps the override out of the flush plan."""
    csrf = _login(client, "op", "oppass1234!")
    client.post("/api/orgs/switch", json={"org_id": multi["orgB"].id}, headers=_h(csrf))
    r = client.post("/api/systems", json={"name": "Written While Switched", "acronym": "WWS"},
                    headers=_h(csrf))
    assert r.status_code == 200
    db.expire_all()
    row = db.query(User).filter(User.username == "op").first()
    assert row.organization_id == multi["orgA"].id  # home unchanged
    new = db.query(System).filter(System.name == "Written While Switched").first()
    assert new.organization_id == multi["orgB"].id  # write still lands in active company


# 9. API tokens ignore the session switch (scoped to the creator's home org)
def test_api_token_ignores_switch(client, multi):
    csrf = _login(client, "op", "oppass1234!")
    raw = client.post("/api/tokens", json={"name": "t"}, headers=_h(csrf)).json()["token"]
    client.post("/api/orgs/switch", json={"org_id": multi["orgB"].id}, headers=_h(csrf))
    # Bearer auth takes precedence over the session cookie and has no active-org.
    r = client.get("/api/findings", headers={"Authorization": f"Bearer {raw}"})
    assert r.status_code == 200
    assert {f["title"] for f in r.json()} == {"Alpha finding"}


# 10. The switch is audited under the target company
def test_switch_audited_under_target(client, multi):
    csrf = _login(client, "op", "oppass1234!")
    client.post("/api/orgs/switch", json={"org_id": multi["orgB"].id}, headers=_h(csrf))
    actions = {e["action"] for e in client.get("/api/audit").json()}  # now scoped to B
    assert "SWITCH_ORG" in actions


# 11. Create a company
def test_create_company(client, multi):
    csrf = _login(client, "op", "oppass1234!")
    r = client.post("/api/orgs", json={"name": "Gamma Co"}, headers=_h(csrf))
    assert r.status_code == 200 and r.json()["slug"] == "gamma-co"
    dup = client.post("/api/orgs", json={"name": "Gamma Co"}, headers=_h(csrf))
    assert dup.status_code == 409


def test_non_operator_cannot_create_company(client, multi):
    csrf = _login(client, "alphaadmin", "apass1234!")
    r = client.post("/api/orgs", json={"name": "Nope Inc"}, headers=_h(csrf))
    assert r.status_code == 403


# 12. Listing
def test_org_listing_scope(client, multi):
    _login(client, "op", "oppass1234!")
    op_list = client.get("/api/orgs").json()
    assert op_list["is_operator"] is True
    assert {o["slug"] for o in op_list["organizations"]} >= {"alpha", "beta"}

    _login(client, "alphaadmin", "apass1234!")
    reg = client.get("/api/orgs").json()
    assert reg["is_operator"] is False
    assert {o["slug"] for o in reg["organizations"]} == {"alpha"}


# 14. Setup bootstraps the first admin as an operator
def test_setup_makes_first_admin_operator(client, db, setup_token_value):
    r = client.post("/api/auth/setup", json={
        "org_name": "Bootstrap Co", "username": "root",
        "password": "bootstrap-pass-123", "setup_token": setup_token_value,
    })
    assert r.status_code == 200
    admin = db.query(User).filter(User.username == "root").first()
    assert admin.is_operator is True


# Operator portfolio (cross-company cockpit)
def test_portfolio_operator_only(client, multi):
    _login(client, "alphaadmin", "apass1234!")
    assert client.get("/api/orgs/portfolio").status_code == 403


def test_portfolio_covers_all_companies(client, multi):
    _login(client, "op", "oppass1234!")
    body = client.get("/api/orgs/portfolio").json()
    companies = {c["slug"]: c for c in body["companies"]}
    assert {"alpha", "beta"} <= set(companies)
    assert companies["alpha"]["open_findings"] == 1
    assert companies["beta"]["open_findings"] == 1
    assert companies["alpha"]["systems"] == 1

"""First-run "Explore with demo data" (POST /api/auth/setup/demo).

The Setup screen offers two choices: set up a real company (POST /auth/setup)
or load the demo. Loading the demo is a first-run setup too, so it needs the
same one-time setup token (else whoever reaches a fresh network server first
gets admin/admin), is refused unless the instance is completely empty (demo
data is never mixed into real data), is atomic (one of any concurrent setups
wins; a failed seed leaves an empty instance and a valid token), signs the
caller in as the demo admin, and is audit-logged."""
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from config import settings
from main import app
from models import AuditEntry, Organization, User
from services import rate_limit, setup_token
from services.demo_marker import DEMO_KEY

TOKEN = "test-setup-token"
REAL = {"setup_token": TOKEN, "org_name": "Real Co", "username": "founder",
        "password": "Blue-Kestrel-42-Orbit", "email": "founder@example.com"}


@pytest.fixture(autouse=True)
def _no_demo_files_left_behind():
    """The suite shares one data dir: start and end without demo files."""
    from services import demo_seed
    demo_seed.discard_demo_files()
    yield
    demo_seed.discard_demo_files()


@pytest.fixture(autouse=True)
def _fresh_limits():
    rate_limit.reset()
    yield
    rate_limit.reset()


def _demo(c, token=TOKEN):
    return c.post("/api/auth/setup/demo", json={"setup_token": token})


def _assert_empty(db):
    db.expire_all()
    assert db.query(Organization).count() == 0
    assert db.query(User).count() == 0


def test_demo_load_needs_the_setup_token(client, db, setup_token_value):
    r = client.post("/api/auth/setup/demo", json={})
    assert r.status_code == 403
    assert "setup token" in r.json()["detail"].lower()
    _assert_empty(db)
    assert setup_token.read_setup_token() == TOKEN


def test_wrong_setup_token_is_refused(client, db, setup_token_value):
    r = _demo(client, "not-the-token")
    assert r.status_code == 403
    _assert_empty(db)
    assert setup_token.read_setup_token() == TOKEN


def test_missing_token_file_fails_closed_like_setup(client, db, tmp_path, monkeypatch):
    token_file = tmp_path / "setup-token"
    monkeypatch.setattr(setup_token, "_TOKEN_PATH", token_file)
    r = _demo(client, "anything")
    assert r.status_code == 403
    assert token_file.exists() and token_file.read_text().strip()  # a fresh one for the operator
    _assert_empty(db)


def test_demo_load_seeds_marks_demo_signs_in_and_consumes_the_token(client, db, setup_token_value):
    r = _demo(client)
    assert r.status_code == 200, r.text
    body = r.json()
    assert "admin" in body["demo_logins"] and "manager" in body["demo_logins"]
    db.expire_all()
    orgs = db.query(Organization).all()
    assert {o.slug for o in orgs} == {"acme-industrial-corp", "northwind-health", "contoso-energy"}
    assert all((o.settings or {}).get(DEMO_KEY) for o in orgs)
    # signed in as the demo admin, and the instance says it is a demo
    me = client.get("/api/auth/me").json()
    assert me["username"] == "admin" and me["demo_instance"] is True
    # the token is consumed exactly as normal setup consumes it
    assert setup_token.read_setup_token() is None
    assert not list(setup_token._TOKEN_PATH.parent.glob("setup-token.claim-*"))
    assert client.get("/api/auth/status").json()["setup_complete"] is True
    # ...so neither choice can run again
    client.cookies.clear()
    assert _demo(client).status_code == 400
    assert client.post("/api/auth/setup", json=REAL).status_code == 400


def test_demo_logins_work_after_loading(client, db, setup_token_value):
    assert _demo(client).status_code == 200
    client.cookies.clear()
    for name in ("admin", "operator", "manager", "auditor", "northwind"):
        r = client.post("/api/auth/login", json={"username": name, "password": name})
        assert r.status_code == 200, (name, r.text)


def test_demo_load_is_audit_logged(client, db, setup_token_value):
    assert _demo(client).status_code == 200
    db.expire_all()
    acme = db.query(Organization).filter_by(slug="acme-industrial-corp").one()
    entry = db.query(AuditEntry).filter_by(organization_id=acme.id, action="DEMO_LOAD").one()
    assert "demo data" in entry.summary.lower()
    verify = client.get("/api/audit/verify").json()
    assert verify["valid"] is True, verify


@pytest.mark.parametrize("existing", ["company", "company+admin"])
def test_refused_unless_the_instance_is_empty(client, db, setup_token_value, existing):
    org = Organization(name="Real Co", slug="real-co")
    db.add(org)
    db.flush()
    if existing == "company+admin":
        db.add(User(organization_id=org.id, username="realadmin", password_hash="x", role="admin"))
    db.commit()
    r = _demo(client)
    assert r.status_code == 400
    assert "empty" in r.json()["detail"].lower() or "already" in r.json()["detail"].lower()
    db.expire_all()
    assert [o.slug for o in db.query(Organization)] == ["real-co"]
    assert not (settings.evidence_dir / "demo").exists()


def test_repeated_wrong_tokens_are_rate_limited_for_both_setup_choices(client, db, setup_token_value):
    for _ in range(rate_limit.ENDPOINT_MAX_ATTEMPTS):
        assert _demo(client, "guess").status_code == 403
    # locked out: even the right token is refused for a while, on both routes
    assert _demo(client).status_code == 429
    assert client.post("/api/auth/setup", json=REAL).status_code == 429
    _assert_empty(db)
    assert setup_token.read_setup_token() == TOKEN


def test_wrong_tokens_on_setup_count_too(client, db, setup_token_value):
    for _ in range(rate_limit.ENDPOINT_MAX_ATTEMPTS):
        assert client.post("/api/auth/setup", json={**REAL, "setup_token": "guess"}).status_code == 403
    assert _demo(client).status_code == 429


@pytest.mark.parametrize("mix", ["demo+demo", "demo+setup"])
def test_concurrent_first_runs_let_exactly_one_win(client, db, setup_token_value, mix):
    # Real per-request sessions (the conftest override shares ONE Session).
    app.dependency_overrides.clear()
    c = TestClient(app, raise_server_exceptions=False)

    def go(i):
        if mix == "demo+demo" or i % 2 == 0:
            return ("demo", c.post("/api/auth/setup/demo", json={"setup_token": TOKEN}).status_code)
        return ("setup", c.post("/api/auth/setup", json={**REAL, "username": f"founder{i}",
                                                         "org_name": f"Real {i}"}).status_code)

    with ThreadPoolExecutor(max_workers=4) as ex:
        results = list(ex.map(go, range(4)))
    codes = sorted(code for _, code in results)
    assert codes == [200, 400, 400, 400], results
    db.expire_all()
    winner = next(kind for kind, code in results if code == 200)
    if winner == "demo":
        assert db.query(Organization).count() == 3
        assert db.query(User).filter(User.username.like("founder%")).count() == 0
    else:
        assert db.query(Organization).count() == 1
        assert db.query(User).count() == 1
    assert setup_token.read_setup_token() is None


def test_seed_failure_leaves_an_empty_instance_and_a_valid_token(client, db, setup_token_value, monkeypatch):
    from services import demo_seed

    original = demo_seed.seed_extra_companies

    def boom(_db):
        raise RuntimeError("disk full")
    monkeypatch.setattr(demo_seed, "seed_extra_companies", boom)  # after Acme is half-written
    c = TestClient(app, raise_server_exceptions=False)
    assert _demo(c).status_code == 500
    _assert_empty(db)
    assert setup_token.read_setup_token() == TOKEN
    assert not (settings.evidence_dir / "demo").exists()
    assert not (settings.custom_frameworks_dir / demo_seed.CUSTOM_FW_ID).exists()
    # the same token then works (here for a real setup)
    monkeypatch.setattr(demo_seed, "seed_extra_companies", original)
    assert client.post("/api/auth/setup", json=REAL).status_code == 200

"""Settings -> "Start fresh" (POST /api/auth/start-fresh): wipe a DEMO
instance back to the first-run Setup screen.

Only on a demo instance (refused on real data, even by direct API call), only
for an instance operator (an admin who is an operator, or the admin of a
single-company install — the same people who may restore a backup, since this
replaces every company), only from a signed-in session, and only with the
admin's current password plus the typed confirmation "START FRESH". It deletes
every database row (companies, users, sessions, API tokens, audit log),
evidence files, custom frameworks and the backups made while the instance held
demo data, keeps the data folder, secrets.env and keys, and writes a NEW setup
token to the log and <DATA_DIR>/setup-token. Builds that auto-seed demo data
(ATHORIZE_DEMO_SEED=1 / DEMO_BUILD) get a clean demo again instead."""
import logging

import pytest
from fastapi.testclient import TestClient

from config import settings
from main import app
from models import ApiToken, AuditEntry, Organization, User
from models.session import UserSession
from services import backup as backup_svc
from services import demo_marker, rate_limit, setup_token

TOKEN = "test-setup-token"
CONFIRM = "START FRESH"
REAL = {"org_name": "Real Co", "username": "founder", "password": "Blue-Kestrel-42-Orbit",
        "email": "founder@example.com"}


@pytest.fixture(autouse=True)
def _clean():
    from services import demo_seed
    rate_limit.reset()
    demo_seed.discard_demo_files()
    demo_marker.clear_demo_backups()
    yield
    rate_limit.reset()
    demo_seed.discard_demo_files()
    demo_marker.clear_demo_backups()


def _csrf(c):
    return {"X-CSRF-Token": c.cookies.get("universal_csrf")}


def _login(c, username, password=None):
    c.cookies.clear()
    r = c.post("/api/auth/login", json={"username": username, "password": password or username})
    assert r.status_code == 200, r.text


def _start_fresh(c, password="admin", confirm=CONFIRM):
    return c.post("/api/auth/start-fresh", json={"password": password, "confirm": confirm}, headers=_csrf(c))


@pytest.fixture
def demo(client, db, setup_token_value):
    """A demo instance loaded through the Setup screen, signed in as admin."""
    r = client.post("/api/auth/setup/demo", json={"setup_token": TOKEN})
    assert r.status_code == 200, r.text
    return client


def _orgs(db):
    db.expire_all()
    return db.query(Organization).count()


def test_refused_on_a_real_instance_even_by_direct_api_call(auth_client, db):
    client, seeded, csrf = auth_client
    r = client.post("/api/auth/start-fresh", json={"password": "testpass1234!", "confirm": CONFIRM},
                    headers={"X-CSRF-Token": csrf})
    assert r.status_code == 409
    assert "demo" in r.json()["detail"].lower()
    assert _orgs(db) == 1 and db.query(User).count() == 1


def test_needs_the_current_password(demo, db):
    r = _start_fresh(demo, password="wrong-password")
    assert r.status_code == 400
    assert "password" in r.json()["detail"].lower()
    assert _orgs(db) == 3


@pytest.mark.parametrize("confirm", ["", "start fresh", "START", "yes"])
def test_needs_the_typed_confirmation(demo, db, confirm):
    r = _start_fresh(demo, confirm=confirm)
    assert r.status_code == 400
    assert CONFIRM in r.json()["detail"]
    assert _orgs(db) == 3


def test_wrong_passwords_are_throttled(demo, db):
    for _ in range(rate_limit.PAIR_MAX):
        assert _start_fresh(demo, password="nope-nope").status_code == 400
    assert _start_fresh(demo).status_code == 429
    assert _orgs(db) == 3


@pytest.mark.parametrize("username", ["manager", "analyst", "owner", "contributor", "auditor"])
def test_non_admins_are_refused(demo, db, username):
    _login(demo, username)
    assert _start_fresh(demo, password=username).status_code == 403
    assert _orgs(db) == 3


def test_a_one_company_admin_on_a_multi_company_instance_is_refused(demo, db):
    _login(demo, "northwind")  # admin of Northwind only (not an operator)
    assert _start_fresh(demo, password="northwind").status_code == 403
    assert _orgs(db) == 3


def test_the_cross_company_operator_may(demo, db):
    _login(demo, "operator")
    assert _start_fresh(demo, password="operator").status_code == 200
    assert _orgs(db) == 0


def test_api_tokens_cannot_start_fresh(demo, db):
    r = demo.post("/api/tokens", json={"name": "ci"}, headers=_csrf(demo))
    assert r.status_code in (200, 201), r.text
    bearer = r.json()["token"]
    c = TestClient(app)
    r = c.post("/api/auth/start-fresh", json={"password": "admin", "confirm": CONFIRM},
               headers={"Authorization": f"Bearer {bearer}"})
    assert r.status_code == 403
    assert _orgs(db) == 3


def test_wipes_everything_and_reopens_setup_with_a_new_token(demo, db, caplog):
    # things a demo user may have added: an upload, a custom framework, a backup,
    # an API token, other sessions
    (settings.evidence_dir / "99").mkdir(parents=True, exist_ok=True)
    (settings.evidence_dir / "99" / "upload.pdf").write_bytes(b"uploaded during the demo")
    demo_backup = backup_svc.create_backup().path
    real_backup = settings.backup_dir / "universal-backup-2020-01-01-000000.tar.gz"
    real_backup.write_bytes(b"made before the demo was loaded")  # not in the demo ledger -> kept
    assert demo.post("/api/tokens", json={"name": "ci"}, headers=_csrf(demo)).status_code in (200, 201)
    other = TestClient(app)
    assert other.post("/api/auth/login", json={"username": "manager", "password": "manager"}).status_code == 200
    keep = settings.data_dir / "keep-me.txt"
    keep.write_text("data folder and keys stay")
    old_cookie = demo.cookies.get("session_id")

    with caplog.at_level(logging.WARNING):
        r = _start_fresh(demo)
    assert r.status_code == 200, r.text
    assert r.json()["next"] == "setup"

    db.expire_all()
    for model in (Organization, User, UserSession, ApiToken, AuditEntry):
        assert db.query(model).count() == 0, model.__name__
    assert not any(settings.evidence_dir.iterdir())
    assert not settings.custom_frameworks_dir.exists() or not any(settings.custom_frameworks_dir.iterdir())
    assert not demo_backup.exists()
    assert real_backup.exists()
    assert keep.read_text() == "data folder and keys stay"
    # a NEW setup token, in the file and in the log, like first boot
    new_token = setup_token.read_setup_token()
    assert new_token and new_token != TOKEN
    assert new_token in caplog.text and "FIRST-RUN SETUP TOKEN" in caplog.text
    # everyone is signed out; the app is back at Setup
    demo.cookies.set("session_id", old_cookie)
    assert demo.get("/api/auth/me").status_code == 401
    assert other.get("/api/auth/me").status_code == 401
    status = demo.get("/api/auth/status").json()
    assert status["setup_complete"] is False and status["setup_token_required"] is True
    real_backup.unlink()


def test_real_setup_works_afterwards_and_is_not_a_demo(demo, db):
    assert _start_fresh(demo).status_code == 200
    token = setup_token.read_setup_token()
    demo.cookies.clear()
    assert demo.post("/api/auth/setup", json={**REAL, "setup_token": "old-or-wrong"}).status_code == 403
    r = demo.post("/api/auth/setup", json={**REAL, "setup_token": token})
    assert r.status_code == 200, r.text
    me = demo.get("/api/auth/me").json()
    assert me["username"] == "founder" and me["demo_instance"] is False
    assert setup_token.read_setup_token() is None
    # and a real instance never offers Start fresh
    assert demo.post("/api/auth/start-fresh", json={"password": REAL["password"], "confirm": CONFIRM},
                     headers=_csrf(demo)).status_code == 409
    assert _orgs(db) == 1


def test_demo_data_can_be_explored_again_afterwards(demo, db):
    assert _start_fresh(demo).status_code == 200
    token = setup_token.read_setup_token()
    demo.cookies.clear()
    assert demo.post("/api/auth/setup/demo", json={"setup_token": token}).status_code == 200
    assert _orgs(db) == 3
    db.expire_all()
    assert db.query(AuditEntry).filter_by(action="DEMO_LOAD").count() == 1


def test_auto_seeding_builds_get_a_clean_demo_instead(demo, db, monkeypatch):
    """ATHORIZE_DEMO_SEED=1 / DEMO_BUILD re-seed an empty database at every
    start, so going back to Setup would only last until the next restart.
    Start fresh there resets to a clean demo and signs everyone out."""
    monkeypatch.setattr(settings, "demo_seed", True)
    (settings.evidence_dir / "99").mkdir(parents=True, exist_ok=True)
    (settings.evidence_dir / "99" / "upload.pdf").write_bytes(b"uploaded during the demo")
    db.expire_all()
    marker = db.query(User).filter_by(username="admin").one()
    marker.display_name = "Changed during the demo"
    db.commit()
    r = _start_fresh(demo)
    assert r.status_code == 200, r.text
    assert r.json()["next"] == "login"
    db.expire_all()
    assert _orgs(db) == 3
    assert db.query(User).filter_by(username="admin").one().display_name == "Admin User"
    assert db.query(UserSession).count() == 0
    assert not (settings.evidence_dir / "99").exists()
    assert setup_token.read_setup_token() is None
    assert demo.get("/api/auth/me").status_code == 401


def test_refused_while_a_backup_or_restore_runs(demo, db):
    with backup_svc._OperationLock():
        r = _start_fresh(demo)
    assert r.status_code == 409
    assert _orgs(db) == 3


def test_backups_made_while_demo_are_recorded_and_real_ones_are_not(demo, db):
    made = backup_svc.create_backup().path
    assert made.name in demo_marker.demo_backups()
    assert _start_fresh(demo).status_code == 200
    token = setup_token.read_setup_token()
    demo.cookies.clear()
    assert demo.post("/api/auth/setup", json={**REAL, "setup_token": token}).status_code == 200
    real = backup_svc.create_backup().path
    assert real.name not in demo_marker.demo_backups()
    real.unlink()


def test_other_api_calls_wait_while_the_wipe_runs(demo):
    from services import start_fresh as svc
    svc._active.set()
    try:
        r = demo.get("/api/systems")
        assert r.status_code == 503
        assert "start" in r.json()["detail"].lower()
        assert demo.get("/api/health").status_code == 200
    finally:
        svc._active.clear()
    assert demo.get("/api/systems").status_code == 200


def test_me_says_whether_this_build_reseeds_the_demo(demo, monkeypatch):
    """The UI names the button after what it does: "Start fresh" (back to
    Setup) or, on auto-seeding builds, "Reset demo data"."""
    assert demo.get("/api/auth/me").json()["demo_autoseed"] is False
    monkeypatch.setattr(settings, "demo_seed", True)
    assert demo.get("/api/auth/me").json()["demo_autoseed"] is True


def test_a_restore_over_demo_data_keeps_its_rollback_copy_on_the_demo_list(demo, db):
    archive = backup_svc.create_backup().path
    out = backup_svc.restore_from_file(archive, actor={"username": "admin"}, source_name=archive.name)
    rollback = settings.backup_dir / out["rollback_path"]
    assert rollback.is_dir() and out["rollback_path"] in demo_marker.demo_backups()
    _login(demo, "admin")  # the restore signed everyone out
    assert _start_fresh(demo).status_code == 200
    assert not rollback.exists() and not archive.exists()

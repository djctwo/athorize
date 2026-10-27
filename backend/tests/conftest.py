import os
import sqlite3
import tempfile
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["SECRET_KEY"] = "test-secret-key"
# Starlette's TestClient sends Host: testserver (see the Host check in main.py).
os.environ["ATHORIZE_ALLOWED_HOSTS"] = "testserver"

# Hermetic data dir — the suite must NEVER touch a real ~/.athorize-universal
# install (the backup round-trip tests swap data.db and the evidence tree in
# place, and parallel checkouts would race on the shared real dir). Hard
# assignment, not setdefault: an inherited DATA_DIR pointing at a real install
# must never win. A real SQLite stub is created so backup archives round-trip.
_TEST_DATA_DIR = Path(tempfile.mkdtemp(prefix="athorize-test-data-"))
os.environ["DATA_DIR"] = str(_TEST_DATA_DIR)
os.environ["EVIDENCE_DIR"] = str(_TEST_DATA_DIR / "evidence")
os.environ["BACKUP_DIR"] = str(_TEST_DATA_DIR / "backups")
(_TEST_DATA_DIR / "evidence").mkdir(parents=True, exist_ok=True)
_conn = sqlite3.connect(_TEST_DATA_DIR / "data.db")
_conn.execute("CREATE TABLE IF NOT EXISTS _stub (id INTEGER)")
_conn.commit()
_conn.close()

from database import Base
from main import app
from database import get_db
from models import Organization, User
from services.auth import hash_password

test_engine = create_engine("sqlite:///./test.db", connect_args={"check_same_thread": False})


@event.listens_for(test_engine, "connect")
def set_sqlite_pragmas(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


TestSession = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)
    # Both engines (the app's own one is used directly by e.g. the login rate
    # limiter) point at the same file; drop their pooled connections before the
    # file is removed, or a later test reads a deleted file through a stale handle
    # while another connection creates a new, empty test.db.
    from database import engine as _app_engine
    _app_engine.dispose()
    test_engine.dispose()
    if os.path.exists("./test.db"):
        os.remove("./test.db")


@pytest.fixture
def db():
    session = TestSession()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(db):
    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def seeded(db):
    org = Organization(name="Test Org", slug="test-org")
    db.add(org)
    db.flush()

    admin = User(
        organization_id=org.id,
        username="testadmin",
        password_hash=hash_password("testpass1234!"),
        email="admin@test.com",
        display_name="Test Admin",
        role="admin",
    )
    db.add(admin)
    db.commit()
    return {"org": org, "admin": admin}


@pytest.fixture
def auth_client(client, seeded):
    resp = client.post("/api/auth/login", json={"username": "testadmin", "password": "testpass1234!"})
    assert resp.status_code == 200
    csrf_token = None
    for cookie_name, cookie_val in resp.cookies.items():
        if cookie_name == "universal_csrf":
            csrf_token = cookie_val
    return client, seeded, csrf_token


@pytest.fixture
def setup_token_value(tmp_path, monkeypatch):
    """A valid first-run setup token (setup fails closed without one)."""
    from services import setup_token
    path = tmp_path / "setup-token"
    path.write_text("test-setup-token")
    monkeypatch.setattr(setup_token, "_TOKEN_PATH", path)
    return "test-setup-token"


def activate_framework(db, org, framework_id: str, *control_ids: str) -> None:
    """Activate ``framework_id`` for ``org`` with a minimal loaded catalog.
    Findings can only be filed under an active framework whose catalog is
    loaded (R2DATA-6), and control ids must exist in it (R2USER-7)."""
    from models import Control, FrameworkActivation
    if not db.query(FrameworkActivation).filter_by(organization_id=org.id, framework_id=framework_id).first():
        db.add(FrameworkActivation(organization_id=org.id, framework_id=framework_id, is_active=True))
    have = {c for (c,) in db.query(Control.control_id).filter(Control.framework_id == framework_id)}
    for cid in (control_ids or ("AC-1",)):
        if cid not in have:
            db.add(Control(framework_id=framework_id, control_id=cid, family=cid.split("-")[0],
                           family_name=cid.split("-")[0], title=f"{cid} title"))
    db.commit()

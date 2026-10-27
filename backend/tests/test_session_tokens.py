"""SECCODE-12 (session part): session ids are stored hashed, never raw."""
from __future__ import annotations

import hashlib

from sqlalchemy import text

from models.session import UserSession


def test_db_never_holds_the_cookie_value(client, db, seeded):
    r = client.post("/api/auth/login", json={"username": "testadmin", "password": "testpass1234!"})
    assert r.status_code == 200
    cookie = client.cookies.get("session_id")
    ids = [i for (i,) in db.query(UserSession.id).all()]
    assert cookie and cookie not in ids
    assert hashlib.sha256(cookie.encode()).hexdigest() in ids
    assert len(cookie) >= 40  # >= 256 bits of entropy, url-safe


def test_stolen_db_row_id_is_not_a_usable_cookie(client, db, seeded):
    client.post("/api/auth/login", json={"username": "testadmin", "password": "testpass1234!"})
    row_id = db.query(UserSession.id).first()[0]
    client.cookies.clear()
    client.cookies.set("session_id", row_id)
    assert client.get("/api/auth/me").status_code == 401


def test_logout_deletes_the_hashed_row(client, db, seeded):
    r = client.post("/api/auth/login", json={"username": "testadmin", "password": "testpass1234!"})
    assert r.status_code == 200
    assert db.query(UserSession).count() == 1
    client.post("/api/auth/logout")
    db.expire_all()
    assert db.query(UserSession).count() == 0


def test_pre_hash_sessions_are_purged_on_upgrade(db, seeded):
    """Old rows stored the raw uuid cookie as the id; they are invalidated once."""
    from datetime import datetime, timedelta, timezone
    from services.sessions import purge_unhashed_sessions
    db.add(UserSession(id="0b5e1c55-6c1a-4f8e-9d3a-6f2a1c9e7b10", user_id=seeded["admin"].id,
                       expires_at=datetime.now(timezone.utc) + timedelta(days=1)))
    db.commit()
    assert purge_unhashed_sessions(db) == 1
    db.commit()
    assert db.execute(text("SELECT count(*) FROM user_sessions")).scalar() == 0

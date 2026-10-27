"""SECCODE-10: API tokens die with the account change that should kill them,
and expire by default."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from models import User
from services.auth import hash_password


@pytest.fixture
def worker(auth_client, db):
    client, seeded, csrf = auth_client
    u = User(organization_id=seeded["org"].id, username="ci-bot", password_hash=hash_password("Bot-pass-1234!"),
             role="assessor", email="bot@example.com")
    db.add(u)
    db.commit()
    # mint a token as that user
    client.cookies.clear()
    r = client.post("/api/auth/login", json={"username": "ci-bot", "password": "Bot-pass-1234!"})
    assert r.status_code == 200
    h = {"X-CSRF-Token": client.cookies.get("universal_csrf")}
    tok = client.post("/api/tokens", json={"name": "ci"}, headers=h).json()
    # back to the admin
    client.cookies.clear()
    client.post("/api/auth/login", json={"username": "testadmin", "password": "testpass1234!"})
    admin_h = {"X-CSRF-Token": client.cookies.get("universal_csrf")}
    return client, u, tok, admin_h


def _bearer_ok(client, tok):
    cookies = dict(client.cookies)
    client.cookies.clear()
    try:
        return client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok['token']}"}).status_code == 200
    finally:
        for k, v in cookies.items():
            client.cookies.set(k, v)


@pytest.mark.parametrize("change", [{"password": "Reset-pass-98765!"}, {"role": "auditor"}, {"is_active": False}])
def test_admin_account_change_revokes_tokens(worker, change):
    client, u, tok, h = worker
    assert _bearer_ok(client, tok)
    assert client.patch(f"/api/users/{u.id}", json=change, headers=h).status_code == 200
    assert not _bearer_ok(client, tok)


def test_reactivated_account_does_not_resurrect_tokens(worker):
    client, u, tok, h = worker
    assert client.delete(f"/api/users/{u.id}", headers=h).status_code == 200
    assert client.patch(f"/api/users/{u.id}", json={"is_active": True}, headers=h).status_code == 200
    assert not _bearer_ok(client, tok)


def test_unrelated_edit_keeps_tokens(worker):
    client, u, tok, h = worker
    assert client.patch(f"/api/users/{u.id}", json={"display_name": "CI Bot"}, headers=h).status_code == 200
    assert _bearer_ok(client, tok)


def test_tokens_expire_by_default(worker):
    _client, _u, tok, _h = worker
    exp = datetime.fromisoformat(tok["expires_at"].replace("Z", "+00:00"))
    assert timedelta(days=89) < exp - datetime.now(timezone.utc) <= timedelta(days=90)


def test_never_expiring_tokens_are_an_explicit_admin_choice(auth_client, db):
    client, seeded, csrf = auth_client
    h = {"X-CSRF-Token": csrf}
    r = client.post("/api/tokens", json={"name": "forever", "never_expires": True}, headers=h)
    assert r.status_code == 200 and r.json()["expires_at"] is None


def test_non_admin_cannot_mint_never_expiring(worker):
    client, u, _tok, _h = worker
    client.cookies.clear()
    client.post("/api/auth/login", json={"username": "ci-bot", "password": "Bot-pass-1234!"})
    h = {"X-CSRF-Token": client.cookies.get("universal_csrf")}
    r = client.post("/api/tokens", json={"name": "forever", "never_expires": True}, headers=h)
    assert r.status_code == 403

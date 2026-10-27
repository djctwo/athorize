"""R2SEC-1: an API token must not mint (or revoke) API tokens, and a
non-admin cannot pick a decade-long lifetime."""
from datetime import datetime, timedelta, timezone
from tests.test_api_token_lifecycle import worker  # noqa: F401


def test_bearer_token_cannot_mint_a_token(worker):
    client, _u, tok, _h = worker
    client.cookies.clear()
    r = client.post("/api/tokens", json={"name": "persist", "expires_in_days": 30},
                    headers={"Authorization": f"Bearer {tok['token']}"})
    assert r.status_code == 403, r.text


def test_bearer_token_cannot_revoke_tokens(worker):
    client, _u, tok, _h = worker
    client.cookies.clear()
    r = client.delete(f"/api/tokens/{tok['id']}", headers={"Authorization": f"Bearer {tok['token']}"})
    assert r.status_code == 403, r.text


def test_non_admin_cannot_pick_a_decade_token(worker):
    client, _u, _tok, _admin_h = worker
    client.cookies.clear()
    assert client.post("/api/auth/login", json={"username": "ci-bot", "password": "Bot-pass-1234!"}).status_code == 200
    h = {"X-CSRF-Token": client.cookies.get("universal_csrf")}
    r = client.post("/api/tokens", json={"name": "persist", "expires_in_days": 3650}, headers=h)
    assert r.status_code == 422, r.text
    r = client.post("/api/tokens", json={"name": "year", "expires_in_days": 365}, headers=h)
    assert r.status_code == 200, r.text
    exp = datetime.fromisoformat(r.json()["expires_at"].replace("Z", "+00:00"))
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    assert exp - datetime.now(timezone.utc) <= timedelta(days=366), exp


def test_admin_may_still_choose_a_long_lifetime(auth_client):
    client, _seeded, csrf = auth_client
    r = client.post("/api/tokens", json={"name": "long", "expires_in_days": 3650}, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200, r.text

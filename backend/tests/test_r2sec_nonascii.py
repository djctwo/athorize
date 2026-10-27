"""R2SEC-18: non-ASCII secrets (setup token, CSRF header/cookie, OIDC state,
a tampered audit anchor) are refused, never a 500."""
from fastapi.testclient import TestClient
from sqlalchemy import text

from main import app


def test_non_ascii_setup_token_is_refused_not_500(client, setup_token_value):
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/api/auth/setup", json={"setup_token": "é" * 10, "username": "admin1", "password": "Abcdefgh1234!!",
                                        "org_name": "Acme", "email": "a@example.com"})
    assert r.status_code == 403, (r.status_code, r.text[:200])


def test_non_ascii_csrf_header_is_refused_not_500(auth_client):
    client, _seeded, _csrf = auth_client
    c = TestClient(app, raise_server_exceptions=False, cookies=client.cookies)
    r = c.post("/api/views", json={"page": "findings", "name": "x", "params": {}},
               headers={"X-CSRF-Token": ("é" * 20).encode("latin-1")})
    assert r.status_code == 403, (r.status_code, r.text[:200])


def test_non_ascii_oidc_state_is_refused_not_500(client, monkeypatch):
    import routers.auth as auth_router
    monkeypatch.setattr(auth_router.oidc_svc, "is_enabled", lambda: True)
    c = TestClient(app, raise_server_exceptions=False)
    c.cookies.set("oidc_state", "abc")
    r = c.get("/api/auth/oidc/callback", params={"code": "c", "state": "é" * 5}, follow_redirects=False)
    assert r.status_code == 400, (r.status_code, r.text[:200])


def test_non_ascii_audit_anchor_reads_as_tampered_not_500(auth_client, db):
    client, seeded, _csrf = auth_client
    from tests.test_audit_chain import _rec
    _rec(db, seeded["org"].id, 2)
    db.execute(text("UPDATE audit_chain_heads SET head_mac = 'é'"))
    db.commit()
    c = TestClient(app, raise_server_exceptions=False, cookies=client.cookies)
    r = c.get("/api/audit/verify")
    assert r.status_code == 200, (r.status_code, r.text[:200])
    assert r.json()["valid"] is False

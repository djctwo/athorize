"""SECCODE-14 + review: OIDC deactivated users, allowed domains, PKCE, nonce."""
from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qs, urlparse

import pytest

import routers.auth as auth_router
from config import settings
from models.user import User
from services import oidc
from services.auth import hash_password

DOC = {"issuer": "https://idp.example.com", "authorization_endpoint": "https://idp.example.com/auth",
       "token_endpoint": "https://idp.example.com/token", "jwks_uri": "https://idp.example.com/jwks"}


@pytest.fixture
def sso(monkeypatch):
    """Enable SSO at the router boundary with a fake IdP; returns call records."""
    calls = {}
    monkeypatch.setattr(auth_router.oidc_svc, "is_enabled", lambda: True)
    monkeypatch.setattr(oidc, "discover", lambda: DOC)
    monkeypatch.setattr(settings, "oidc_client_id", "client-123")
    monkeypatch.setattr(settings, "oidc_redirect_uri", "https://app.example.com/api/auth/oidc/callback")
    if "oidc_allowed_domains" in type(settings).model_fields:  # absent before the fix
        monkeypatch.setattr(settings, "oidc_allowed_domains", [])

    def exchange(code, *args, **kw):
        calls["exchange"] = (code, args, kw)
        return {"id_token": "tok"}

    def verify(tok, nonce, **kw):
        calls["nonce"] = nonce
        email = calls.get("email", "pat@example.com")
        return {"iss": DOC["issuer"], "sub": calls.get("sub", f"sub-{email.lower()}"), "email": email,
                "email_verified": calls.get("email_verified", True), "nonce": nonce}

    monkeypatch.setattr(auth_router.oidc_svc, "exchange_code", exchange)
    monkeypatch.setattr(auth_router.oidc_svc, "verify_id_token", verify)
    return calls


def _begin(client):
    r = client.get("/api/auth/oidc/login", follow_redirects=False)
    assert r.status_code == 302
    return r, parse_qs(urlparse(r.headers["location"]).query)


def _callback(client, state):
    return client.get(f"/api/auth/oidc/callback?code=c&state={state}", follow_redirects=False)


def test_authorization_request_uses_pkce_s256(client, sso, seeded):
    r, q = _begin(client)
    assert q["code_challenge_method"] == ["S256"]
    verifier = client.cookies.get("oidc_pkce")
    assert verifier
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    assert q["code_challenge"] == [expected]
    assert _callback(client, q["state"][0]).status_code == 302
    code, args, kw = sso["exchange"]
    assert verifier in args or kw.get("code_verifier") == verifier


def test_callback_without_nonce_cookie_is_refused(client, sso):
    _r, q = _begin(client)
    client.cookies.delete("oidc_nonce")
    assert _callback(client, q["state"][0]).status_code == 400
    assert "exchange" not in sso


def test_verify_id_token_requires_a_nonce():
    with pytest.raises(oidc.OidcError):
        oidc.verify_id_token("a.b.c", "")


def test_deactivated_user_is_not_recreated_by_jit(client, sso, db, seeded):
    db.add(User(organization_id=seeded["org"].id, username="pat", email="pat@example.com",
                password_hash=hash_password("Abcd1234!!xy"), role="admin", is_active=False))
    db.commit()
    _r, q = _begin(client)
    assert _callback(client, q["state"][0]).status_code == 403
    assert db.query(User).filter(User.email == "pat@example.com").count() == 1


@pytest.mark.parametrize("email,ok", [("pat@example.com", True), ("pat@EXAMPLE.com", True),
                                      ("pat@evil.example.com", False), ("pat@example.com.evil.io", False)])
def test_allowed_domains_enforced_before_matching_or_provisioning(client, sso, db, seeded, monkeypatch, email, ok):
    monkeypatch.setattr(settings, "oidc_allowed_domains", ["Example.com"])
    sso["email"] = email
    _r, q = _begin(client)
    r = _callback(client, q["state"][0])
    assert (r.status_code == 302) is ok
    if not ok:
        assert r.status_code == 403
        assert db.query(User).filter(User.email == email.lower()).count() == 0

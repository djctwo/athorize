"""OIDC SSO: disabled-by-default, status flag, id_token guards, state CSRF."""
import base64
import json

import pytest

from services import oidc
import routers.auth as auth_router


def _b64url(d: bytes) -> str:
    return base64.urlsafe_b64encode(d).decode().rstrip("=")


class TestDisabledByDefault:
    def test_is_enabled_false(self):
        assert oidc.is_enabled() is False

    def test_status_exposes_flag(self, client):
        body = client.get("/api/auth/status").json()
        assert body["oidc_enabled"] is False

    def test_login_route_404_when_disabled(self, client):
        assert client.get("/api/auth/oidc/login", follow_redirects=False).status_code == 404

    def test_callback_404_when_disabled(self, client):
        assert client.get("/api/auth/oidc/callback?code=x&state=y", follow_redirects=False).status_code == 404


class TestIdTokenGuards:
    def test_malformed_token_rejected(self):
        with pytest.raises(oidc.OidcError):
            oidc.verify_id_token("not-a-jwt", "nonce")

    def test_non_rs256_rejected(self):
        # alg check happens before any network call
        header = _b64url(json.dumps({"alg": "HS256"}).encode())
        payload = _b64url(json.dumps({}).encode())
        with pytest.raises(oidc.OidcError):
            oidc.verify_id_token(f"{header}.{payload}.sig", "nonce")


class TestHttpsPinning:
    def test_http_issuer_rejected(self, monkeypatch):
        from config import settings
        monkeypatch.setattr(settings, "oidc_issuer", "http://evil.example.com")
        with pytest.raises(oidc.OidcError):
            oidc.discover()

    def test_https_required_helper(self):
        with pytest.raises(oidc.OidcError):
            oidc._require_https("http://idp.example.com/authorize", "authorization_endpoint")
        # localhost http is allowed for dev IdPs; https always allowed
        oidc._require_https("http://localhost:8080/authorize", "authorization_endpoint")
        oidc._require_https("https://idp.example.com/authorize", "authorization_endpoint")


class TestFullVerification:
    """Sign a real RS256 token and run the whole verify_id_token path."""

    @staticmethod
    def _setup(monkeypatch):
        import time as _t
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        nums = key.public_key().public_numbers()

        def _int_b64(n):
            return _b64url(n.to_bytes((n.bit_length() + 7) // 8, "big"))

        jwk = {"kty": "RSA", "kid": "test", "n": _int_b64(nums.n), "e": _int_b64(nums.e)}
        doc = {
            "issuer": "https://idp.example.com",
            "authorization_endpoint": "https://idp.example.com/auth",
            "token_endpoint": "https://idp.example.com/token",
            "jwks_uri": "https://idp.example.com/jwks",
        }
        monkeypatch.setattr(oidc, "discover", lambda: doc)
        monkeypatch.setattr(oidc, "_jwks", lambda uri: {"keys": [jwk]})
        from config import settings
        monkeypatch.setattr(settings, "oidc_client_id", "client-123")

        def sign(claims):
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            header = _b64url(json.dumps({"alg": "RS256", "kid": "test"}).encode())
            payload = _b64url(json.dumps(claims).encode())
            sig = key.sign(f"{header}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256())
            return f"{header}.{payload}.{_b64url(sig)}"

        base = {"iss": "https://idp.example.com", "aud": "client-123",
                "exp": int(_t.time()) + 300, "nonce": "N", "email": "a@b.com", "email_verified": True}
        return sign, base

    def test_valid_token_passes(self, monkeypatch):
        sign, base = self._setup(monkeypatch)
        claims = oidc.verify_id_token(sign(base), "N")
        assert claims["email"] == "a@b.com"

    def test_unverified_email_rejected(self, monkeypatch):
        sign, base = self._setup(monkeypatch)
        with pytest.raises(oidc.OidcError):
            oidc.verify_id_token(sign({**base, "email_verified": False}), "N")

    def test_string_false_email_verified_rejected(self, monkeypatch):
        # Parser differential: some IdPs send email_verified as a STRING.
        sign, base = self._setup(monkeypatch)
        with pytest.raises(oidc.OidcError):
            oidc.verify_id_token(sign({**base, "email_verified": "false"}), "N")

    def test_absent_email_verified_rejected(self, monkeypatch):
        sign, base = self._setup(monkeypatch)
        no_ev = {k: v for k, v in base.items() if k != "email_verified"}
        with pytest.raises(oidc.OidcError):
            oidc.verify_id_token(sign(no_ev), "N")

    def test_string_true_email_verified_accepted(self, monkeypatch):
        sign, base = self._setup(monkeypatch)
        claims = oidc.verify_id_token(sign({**base, "email_verified": "true"}), "N")
        assert claims["email"] == "a@b.com"

    def test_nonce_mismatch_rejected(self, monkeypatch):
        sign, base = self._setup(monkeypatch)
        with pytest.raises(oidc.OidcError):
            oidc.verify_id_token(sign(base), "WRONG")

    def test_wrong_audience_rejected(self, monkeypatch):
        sign, base = self._setup(monkeypatch)
        with pytest.raises(oidc.OidcError):
            oidc.verify_id_token(sign({**base, "aud": "someone-else"}), "N")

    def test_expired_rejected(self, monkeypatch):
        import time as _t
        sign, base = self._setup(monkeypatch)
        with pytest.raises(oidc.OidcError):
            oidc.verify_id_token(sign({**base, "exp": int(_t.time()) - 10}), "N")

    def test_kid_mismatch_rejected(self, monkeypatch):
        # Token header kid='test' but JWKS only serves a different kid → reject,
        # never fall back to "first RSA key".
        sign, base = self._setup(monkeypatch)
        monkeypatch.setattr(oidc, "_jwks", lambda uri: {"keys": [
            {"kty": "RSA", "kid": "rotated-away", "n": "AQAB", "e": "AQAB"}]})
        with pytest.raises(oidc.OidcError):
            oidc.verify_id_token(sign(base), "N")

    def test_tampered_signature_rejected(self, monkeypatch):
        sign, base = self._setup(monkeypatch)
        tok = sign(base)
        head, payload, _sig = tok.split(".")
        forged = json.dumps({**base, "email": "admin@b.com"}).encode()
        with pytest.raises(oidc.OidcError):
            oidc.verify_id_token(f"{head}.{_b64url(forged)}.{_sig}", "N")


class TestCallbackAccountBinding:
    def test_duplicate_email_rejected(self, auth_client, db, seeded, monkeypatch):
        """Two active users share an email → SSO must refuse, not bind arbitrarily."""
        from models.user import User
        from services.auth import hash_password
        org = seeded["org"]
        for uname in ("dupa", "dupb"):
            db.add(User(organization_id=org.id, username=uname, email="dup@x.com",
                        password_hash=hash_password("Abcd1234!!xy"), role="auditor", is_active=True))
        db.commit()

        client, _s, _csrf = auth_client
        monkeypatch.setattr(auth_router.oidc_svc, "is_enabled", lambda: True)
        monkeypatch.setattr(auth_router.oidc_svc, "exchange_code", lambda code: {"id_token": "x"})
        monkeypatch.setattr(auth_router.oidc_svc, "verify_id_token",
                            lambda tok, nonce: {"iss": "https://idp.example.com", "sub": "s-dup",
                                               "email": "dup@x.com", "email_verified": True})
        client.cookies.set("oidc_state", "S")
        client.cookies.set("oidc_nonce", "N")   # a real flow always has these (SECCODE-14)
        client.cookies.set("oidc_pkce", "V", path="/api/auth/oidc")
        monkeypatch.setattr(auth_router.oidc_svc, "exchange_code", lambda code, verifier: {"id_token": "x"})
        r = client.get("/api/auth/oidc/callback?code=c&state=S", follow_redirects=False)
        assert r.status_code == 409


class TestProvisionRoleCap:
    def test_admin_default_role_downgraded(self, monkeypatch):
        from config import settings
        monkeypatch.setattr(settings, "oidc_default_role", "admin")
        assert auth_router._safe_oidc_role() == "auditor"

    def test_bogus_role_downgraded(self, monkeypatch):
        from config import settings
        monkeypatch.setattr(settings, "oidc_default_role", "superuser")
        assert auth_router._safe_oidc_role() == "auditor"

    def test_valid_nonadmin_role_kept(self, monkeypatch):
        from config import settings
        monkeypatch.setattr(settings, "oidc_default_role", "compliance_manager")
        assert auth_router._safe_oidc_role() == "compliance_manager"


class TestStateCsrf:
    def test_callback_rejects_missing_state_cookie(self, client, monkeypatch):
        # Force-enable OIDC at the router boundary; no state cookie is set.
        monkeypatch.setattr(auth_router.oidc_svc, "is_enabled", lambda: True)
        r = client.get("/api/auth/oidc/callback?code=abc&state=def", follow_redirects=False)
        assert r.status_code == 400

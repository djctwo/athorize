"""Live integration: OIDC against a real Keycloak, SMTP against a real MailHog.

These exercise the one thing unit tests can't — talking to a real IdP and a real
mail server over the wire. They run ONLY when INTEGRATION=1 and the services
(from scripts/smoketest/docker-compose.yml) are up; otherwise they skip. The CI
`integration` workflow stands the containers up and sets INTEGRATION=1.
"""
import os

import httpx
import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("INTEGRATION") != "1",
    reason="integration test — needs Keycloak + MailHog (INTEGRATION=1)",
)

KEYCLOAK = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
ISSUER = f"{KEYCLOAK}/realms/athorize"
MAILHOG = os.getenv("MAILHOG_URL", "http://localhost:8025")
CLIENT_ID = "athorize-universal"
CLIENT_SECRET = "athorize-smoketest-secret"


def _configure_oidc(monkeypatch):
    from config import settings
    monkeypatch.setattr(settings, "oidc_enabled", True)
    monkeypatch.setattr(settings, "oidc_issuer", ISSUER)
    monkeypatch.setattr(settings, "oidc_client_id", CLIENT_ID)
    monkeypatch.setattr(settings, "oidc_client_secret", CLIENT_SECRET)
    monkeypatch.setattr(settings, "oidc_redirect_uri", "http://localhost:8001/api/auth/oidc/callback")


class TestLiveOidc:
    def test_discovery_and_jwks_reachable(self, monkeypatch):
        """Proves live discovery + JWKS fetch + issuer anchoring against Keycloak."""
        import services.oidc as oidc
        oidc._DISCOVERY_CACHE.clear(); oidc._JWKS_CACHE.clear()
        _configure_oidc(monkeypatch)
        doc = oidc.discover()
        assert doc["issuer"].rstrip("/") == ISSUER
        keys = oidc._jwks(doc["jwks_uri"]).get("keys", [])
        assert any(k.get("kty") == "RSA" for k in keys)

    def test_real_id_token_verifies(self, monkeypatch):
        """Mint a real id_token from Keycloak (password grant) and verify it end-to-end."""
        import services.oidc as oidc
        oidc._DISCOVERY_CACHE.clear(); oidc._JWKS_CACHE.clear()
        _configure_oidc(monkeypatch)
        token_endpoint = oidc.discover()["token_endpoint"]
        resp = httpx.post(token_endpoint, data={
            "grant_type": "password",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "username": "pilot",
            "password": "pilot-pass-12345",
            "scope": "openid email profile",
        }, timeout=30)
        resp.raise_for_status()
        id_token = resp.json()["id_token"]
        # No nonce in a password grant → explicitly opt out of the nonce check;
        # the signature, iss, aud, exp, and email_verified checks all run for real.
        claims = oidc.verify_id_token(id_token, "", require_nonce=False)
        assert claims["email"] == "pilot@athorize.local"
        assert claims.get("email_verified") in (True, "true")


class TestLiveSmtp:
    def test_digest_delivers_to_mailhog(self, monkeypatch):
        """Send through a real SMTP server and confirm the message arrived."""
        from config import settings
        from services import email as email_svc
        monkeypatch.setattr(settings, "smtp_host", "localhost")
        monkeypatch.setattr(settings, "smtp_port", 1025)
        monkeypatch.setattr(settings, "smtp_from", "digest@athorize.local")
        monkeypatch.setattr(settings, "smtp_user", "")
        monkeypatch.setattr(settings, "smtp_use_tls", False)

        # clear the inbox, send, then assert receipt
        httpx.delete(f"{MAILHOG}/api/v1/messages", timeout=10)
        subject = "Athorize integration test digest"
        email_svc.send_email(["pilot@athorize.local"], subject, "<p>hello</p>", "hello")

        msgs = httpx.get(f"{MAILHOG}/api/v2/messages", timeout=10).json()
        subjects = [m["Content"]["Headers"]["Subject"][0] for m in msgs.get("items", [])]
        assert subject in subjects

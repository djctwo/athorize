"""Login hardening: SECLIVE-4 (timing oracle), SECLIVE-5 + DOCKER-2 (rate limit
bypass / lockout DoS), SECCODE-11 (usernames), SECLIVE-6 (Secure cookies)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from main import app
from models import Organization, User
from services import rate_limit
from services.auth import hash_password

GOOD = {"username": "testadmin", "password": "testpass1234!"}


@pytest.fixture(autouse=True)
def fresh_limiter(db):
    def wipe():
        if hasattr(rate_limit, "reset"):
            rate_limit.reset()
        else:  # pre-fix module
            for name in ("_attempts", "_lockouts", "_user_attempts", "_endpoint_attempts"):
                getattr(rate_limit, name, {}).clear()
            db.execute(text("DELETE FROM rate_limit_state"))
            db.commit()
    wipe()
    yield
    wipe()


@pytest.fixture
def ipclient(client):
    """A client whose source address each request chooses via X-Forwarded-For —
    i.e. the worst case: an attacker who fully controls the address the app sees."""
    with TestClient(ProxyHeadersMiddleware(app, trusted_hosts="*")) as c:
        yield c


def login(c, ip, body=GOOD, password=None):
    b = dict(body)
    if password is not None:
        b["password"] = password
    c.cookies.clear()
    return c.post("/api/auth/login", json=b, headers={"X-Forwarded-For": ip}).status_code


class TestRateLimit:
    def test_single_source_brute_force_is_stopped(self, ipclient, seeded):
        for _ in range(5):
            assert login(ipclient, "198.51.100.7", password="wrong") == 401
        assert login(ipclient, "198.51.100.7") == 429  # even the right password, from the attacker

    def test_unknown_user_failures_do_not_lock_out_everyone_on_a_shared_ip(self, ipclient, seeded):
        """DOCKER-2: behind port publishing every client is 172.17.0.1."""
        for _ in range(6):
            login(ipclient, "172.17.0.1", {"username": "nosuchuser", "password": "x"})
        assert login(ipclient, "172.17.0.1") == 200

    def test_spoofed_ip_rotation_cannot_lock_the_admin_out(self, ipclient, seeded):
        """SECLIVE-5 DoS: failures from many (spoofed) addresses must not block
        the real user from the address they normally sign in from."""
        assert login(ipclient, "192.0.2.10") == 200          # admin's usual address
        for n in range(30):
            login(ipclient, f"203.0.113.{n}", password="wrong")
        assert login(ipclient, "192.0.2.10") == 200

    def test_spoofed_ip_rotation_cannot_brute_force(self, ipclient, seeded):
        """SECLIVE-5 bypass: rotating addresses gets at most a small, fixed number
        of guesses per account; a new address is refused while it's under attack."""
        for n in range(20):
            login(ipclient, f"203.0.113.{n}", password="wrong")
        assert login(ipclient, "203.0.113.200") == 429
        assert login(ipclient, "203.0.113.201", password="wrong") == 429

    def test_password_spraying_from_one_ip_is_stopped(self, ipclient, seeded):
        for n in range(30):
            login(ipclient, "198.51.100.9", {"username": f"user{n}", "password": "x"})
        assert login(ipclient, "198.51.100.9", {"username": "user99", "password": "x"}) == 429


class TestTimingOracle:
    def test_unknown_username_still_runs_the_password_hash(self, client, seeded, monkeypatch):
        """SECLIVE-4: the hash ran only for existing users (26 ms vs 1 ms)."""
        import routers.auth as auth_router
        calls = []
        real = auth_router.verify_password
        monkeypatch.setattr(auth_router, "verify_password", lambda p, h: calls.append(h) or real(p, h))
        assert client.post("/api/auth/login", json={"username": "nobody-here", "password": "x"}).status_code == 401
        assert len(calls) == 1


class TestUsernames:
    def _org2(self, db):
        org2 = Organization(name="Org Two", slug="org-two")
        db.add(org2)
        db.flush()
        return org2

    def test_username_taken_in_another_org_is_rejected(self, auth_client, db):
        """SECCODE-11: usernames were unique per org but login looks them up globally."""
        client, seeded, csrf = auth_client
        org2 = self._org2(db)
        db.add(User(organization_id=org2.id, username="shared", password_hash=hash_password("x" * 12),
                    role="admin"))
        db.commit()
        r = client.post("/api/users", json={"username": "shared", "password": "Another-pass-123!",
                                            "role": "auditor", "email": "s@example.com"},
                        headers={"X-CSRF-Token": csrf})
        assert r.status_code == 409

    def test_legacy_duplicate_usernames_can_both_sign_in(self, client, seeded, db):
        org2 = self._org2(db)
        db.add(User(organization_id=org2.id, username="testadmin",
                    password_hash=hash_password("org2-pass-1234!"), role="admin"))
        db.commit()
        r = client.post("/api/auth/login", json={"username": "testadmin", "password": "org2-pass-1234!"})
        assert r.status_code == 200 and r.json()["user_id"] != seeded["admin"].id
        client.cookies.clear()
        r = client.post("/api/auth/login", json=GOOD)
        assert r.status_code == 200 and r.json()["user_id"] == seeded["admin"].id


class TestSecureCookies:
    def test_trust_xff_from_env_file_marks_cookies_secure(self, client, seeded, monkeypatch):
        """SECLIVE-6: documented ATHORIZE_TRUST_XFF=1 (behind a TLS proxy)."""
        from config import settings
        monkeypatch.setattr(settings, "trust_xff", True)
        r = client.post("/api/auth/login", json=GOOD, headers={"X-Forwarded-Proto": "https"})
        assert r.status_code == 200
        cookies = r.headers.get_list("set-cookie")
        assert all("secure" in c.lower() for c in cookies if c.startswith(("session_id", "universal_csrf")))

    def test_plain_http_without_trust_is_not_secure(self, client, seeded):
        r = client.post("/api/auth/login", json=GOOD, headers={"X-Forwarded-Proto": "https"})
        assert r.status_code == 200
        assert "secure" not in r.headers.get("set-cookie", "").lower()


def test_familiar_addresses_and_locks_survive_a_restart(ipclient, seeded):
    assert login(ipclient, "192.0.2.10") == 200
    for _ in range(5):
        login(ipclient, "198.51.100.7", password="wrong")
    # simulate a process restart: in-memory state gone, reloaded from the DB
    rate_limit._failures.clear()
    rate_limit._lockouts.clear()
    rate_limit._familiar.clear()
    rate_limit._load()
    assert rate_limit.is_familiar("192.0.2.10", "testadmin")
    assert login(ipclient, "198.51.100.7") == 429

"""Hardening: password policy, setup token, idle session timeout."""
import pytest

from services.password_policy import validate_password


class TestPasswordPolicy:
    def test_too_short(self):
        assert validate_password("Ab1!xyz") is not None

    def test_insufficient_classes(self):
        # 12 chars but only lowercase
        assert validate_password("abcdefghijkl") is not None

    def test_three_classes_ok(self):
        assert validate_password("abcdEFGH1234") is None

    def test_common_rejected(self):
        assert validate_password("changeme") is not None

    def test_contains_username(self):
        assert validate_password("Jsmith12345!", username="jsmith") is not None

    def test_repeated_run_rejected(self):
        assert validate_password("Baaaa1234567!") is not None  # five a-run

    def test_strong_passphrase_ok(self):
        assert validate_password("Tr0ub4dor&3xtra") is None


class TestSetupToken:
    def test_verify_and_clear(self, tmp_path, monkeypatch):
        from services import setup_token
        token_file = tmp_path / "setup-token"
        monkeypatch.setattr(setup_token, "_TOKEN_PATH", token_file)
        token_file.write_text("secret-token")
        assert setup_token.verify_setup_token("secret-token") is True
        assert setup_token.verify_setup_token("nope") is False
        assert setup_token.verify_setup_token(None) is False
        setup_token.clear_setup_token()
        assert setup_token.read_setup_token() is None
        # No token present → verify always False
        assert setup_token.verify_setup_token("secret-token") is False


class TestIdleTimeout:
    def test_idle_session_revoked(self, client, db, seeded, monkeypatch):
        from datetime import datetime, timedelta, timezone
        from config import settings
        from models.session import UserSession

        monkeypatch.setattr(settings, "idle_timeout_minutes", 30)

        login = client.post("/api/auth/login", json={"username": "testadmin", "password": "testpass1234!"})
        assert login.status_code == 200

        # Backdate last_activity beyond the idle window (same session the
        # client uses via the get_db override).
        sess = db.query(UserSession).order_by(UserSession.created_at.desc()).first()
        sess.last_activity = datetime.now(timezone.utc) - timedelta(minutes=45)
        db.commit()

        me = client.get("/api/auth/me")
        assert me.status_code == 401

    def test_active_session_survives(self, auth_client, monkeypatch):
        from config import settings
        monkeypatch.setattr(settings, "idle_timeout_minutes", 30)
        client, seeded, _ = auth_client
        assert client.get("/api/auth/me").status_code == 200

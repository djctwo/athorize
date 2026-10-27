"""R2SEC-5: starting the app a second way on the same data folder silently
switched the audit key; the real audit log then reported "tampered".

Scenario from the finding: the instance ran (and wrote audit entries) with the
key in <DATA_DIR>/secrets.env; it is then started with a different key — from
backend/.env / the environment, or from another start path's secrets file.
"""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

import config
import models  # noqa: F401
from database import Base
from models import Organization
from services import audit as audit_svc

KEY_A = "a" * 64   # signed the log
KEY_B = "b" * 64   # the second start path's key


@pytest.fixture
def instance(tmp_path, monkeypatch):
    from config import settings
    d = tmp_path / "data"
    d.mkdir()
    monkeypatch.setattr(settings, "data_dir", d)
    monkeypatch.setattr(settings, "audit_hmac_key", KEY_A)
    monkeypatch.setattr(settings, "demo_seed", False)
    eng = create_engine(f"sqlite:///{d / 'data.db'}")
    Base.metadata.create_all(eng)
    with Session(eng) as db:
        org = Organization(name="Acme Industrial Corp", slug="acme")
        db.add(org)
        db.flush()
        for i in range(3):
            audit_svc.record(db, organization_id=org.id, actor_id=None, actor_username="admin",
                             action="CREATE", entity_type="system", summary=f"system {i}")
        db.commit()
        org_id = org.id
    yield d, eng, org_id
    eng.dispose()


def _verify(eng, org_id):
    with Session(eng) as db:
        return audit_svc.verify(db, org_id)


def test_matching_key_is_left_alone(instance, monkeypatch):
    from services.audit_key_check import reconcile_audit_key
    d, eng, org_id = instance
    monkeypatch.setattr(config, "AUDIT_KEY_SOURCE", "file:secrets.env")
    assert reconcile_audit_key(eng) == "ok"
    assert _verify(eng, org_id)["valid"]


def test_key_from_a_second_secrets_file_is_replaced_by_the_one_that_signed_the_log(instance, monkeypatch):
    """Both files present (a run-eval eval-secrets.env and a secrets.env written
    by a second start path): use the key that provably signed the log."""
    from config import settings
    from services.audit_key_check import reconcile_audit_key
    d, eng, org_id = instance
    (d / "secrets.env").write_text(f"SECRET_KEY={'s' * 64}\nATHORIZE_AUDIT_HMAC_KEY={KEY_B}\n")
    (d / "eval-secrets.env").write_text(f"SECRET_KEY={'s' * 64}\nATHORIZE_AUDIT_HMAC_KEY={KEY_A}\n")
    monkeypatch.setattr(settings, "audit_hmac_key", KEY_B)
    monkeypatch.setattr(config, "AUDIT_KEY_SOURCE", "file:secrets.env")
    assert not _verify(eng, org_id)["valid"]                 # the finding: "tampered"
    assert reconcile_audit_key(eng) == "switched"
    assert settings.audit_hmac_key == KEY_A
    assert _verify(eng, org_id)["valid"]


def test_explicit_key_that_did_not_sign_the_log_refuses_to_start(instance, monkeypatch):
    """INSTALL.md way first (secrets.env generated), then keys added to
    backend/.env / the environment: refuse instead of forking the log."""
    from config import ConfigError, settings
    from services.audit_key_check import reconcile_audit_key
    d, eng, org_id = instance
    (d / "secrets.env").write_text(f"SECRET_KEY={'s' * 64}\nATHORIZE_AUDIT_HMAC_KEY={KEY_A}\n")
    monkeypatch.setattr(settings, "audit_hmac_key", KEY_B)
    monkeypatch.setattr(config, "AUDIT_KEY_SOURCE", "environment")
    with pytest.raises(ConfigError, match="secrets.env"):
        reconcile_audit_key(eng)
    assert settings.audit_hmac_key == KEY_B   # nothing silently changed


def test_explicit_mismatch_only_warns_in_demo_mode(instance, monkeypatch):
    from config import settings
    from services.audit_key_check import reconcile_audit_key
    d, eng, org_id = instance
    (d / "secrets.env").write_text(f"ATHORIZE_AUDIT_HMAC_KEY={KEY_A}\n")
    monkeypatch.setattr(settings, "audit_hmac_key", KEY_B)
    monkeypatch.setattr(settings, "demo_seed", True)
    monkeypatch.setattr(config, "AUDIT_KEY_SOURCE", "environment")
    assert reconcile_audit_key(eng) == "switched"


def test_no_saved_key_signed_it_only_warns(instance, monkeypatch, caplog):
    """Data restored from another instance (or altered): nothing to switch to."""
    from config import settings
    from services.audit_key_check import reconcile_audit_key
    d, eng, org_id = instance
    monkeypatch.setattr(settings, "audit_hmac_key", KEY_B)
    monkeypatch.setattr(config, "AUDIT_KEY_SOURCE", "environment")
    assert reconcile_audit_key(eng) == "unknown"
    assert settings.audit_hmac_key == KEY_B
    assert "do not verify" in caplog.text


def test_empty_log_is_fine(tmp_path):
    from services.audit_key_check import reconcile_audit_key
    eng = create_engine(f"sqlite:///{tmp_path / 'x.db'}")
    Base.metadata.create_all(eng)
    assert reconcile_audit_key(eng) == "empty"
    eng.dispose()

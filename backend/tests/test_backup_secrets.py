"""Team C hand-offs into backup/restore: key material never travels in an
archive, restores run the audit-chain upgrade, and restored DBs keep no
sessions under the hashed-session model."""
from __future__ import annotations

import gzip
import sqlite3

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from models import AuditEntry
from services import audit as audit_svc
from services import backup as backup_svc
from tests.test_backup_safety import FIXTURES, archive_members, datadir, make_instance_db, manual_archive  # noqa: F401

SECRET_FILES = ("secrets.env", "eval-secrets.env", "desktop-secrets.env", "setup-token")


def _plant(d):
    for name in SECRET_FILES:
        (d / name).write_text("ATHORIZE_AUDIT_HMAC_KEY=" + "k" * 64 + "\n")


def test_secrets_are_never_archived_even_if_evidence_dir_is_the_data_dir(datadir, monkeypatch):
    """With a sane layout the secrets sit next to (not under) the evidence dir;
    with EVIDENCE_DIR misconfigured to DATA_DIR itself they would be walked —
    they must still be skipped."""
    from config import settings
    make_instance_db(datadir / "data.db")
    _plant(datadir)
    (datadir / "evidence" / "1").mkdir(parents=True)
    (datadir / "evidence" / "1" / "e.txt").write_text("evidence")
    blob, _name = backup_svc.create_backup_bytes()
    names = set(archive_members(blob))
    assert "evidence/1/e.txt" in names
    assert not any(n.rsplit("/", 1)[-1] in SECRET_FILES for n in names), names

    monkeypatch.setattr(settings, "evidence_dir", datadir)  # misconfiguration
    # R2SEC-6 (fix wave 2): that layout is now refused outright (startup and
    # backup), so no archive - and so no key material - is produced at all.
    with pytest.raises(backup_svc.BackupError, match="folder of its own"):
        backup_svc.create_backup_bytes()


@pytest.mark.parametrize("name", ["evidence/secrets.env", "evidence/1/setup-token", "custom_frameworks/x/eval-secrets.env"])
def test_restore_refuses_archives_carrying_key_material(datadir, name):
    make_instance_db(datadir / "data.db")
    db = (datadir / "data.db").read_bytes()
    blob = manual_archive({"data.db": db, name: b"ATHORIZE_AUDIT_HMAC_KEY=attacker\n"})
    with pytest.raises(backup_svc.BackupError):
        backup_svc.restore_from_bytes(blob)


def test_restored_pre_v2_database_is_upgraded_and_sessionless(datadir):
    """A June-2026 archive: restore must add hash_version, anchor the legacy
    chain (so Verify passes) and leave no sessions behind."""
    make_instance_db(datadir / "data.db")
    old = gzip.decompress((FIXTURES / "athorize-2026-06-13-schema.db.gz").read_bytes())
    tmp = datadir / "old.db"
    tmp.write_bytes(old)
    con = sqlite3.connect(tmp)
    n_sessions = con.execute("SELECT count(*) FROM user_sessions").fetchone()[0]
    con.close()
    blob = manual_archive({"data.db": tmp.read_bytes()})
    tmp.unlink()
    backup_svc.restore_from_bytes(blob)
    eng = create_engine(f"sqlite:///{datadir / 'data.db'}")
    try:
        with eng.connect() as c:
            from sqlalchemy import text
            cols = {r[1] for r in c.execute(text("PRAGMA table_info(audit_entries)"))}
            assert "hash_version" in cols
            assert c.execute(text("SELECT count(*) FROM user_sessions")).scalar() == 0
        with Session(eng) as s:
            orgs = [o for (o,) in s.query(AuditEntry.organization_id).distinct()]
            results = [audit_svc.verify(s, o) for o in orgs]
        assert results and all(r["valid"] for r in results), results
    finally:
        eng.dispose()
    assert n_sessions >= 0

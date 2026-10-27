"""Backup & restore safety (fix wave, Team A).

Covers DOCKER-1 / SECCODE-5 / E2E-1 / INTEGRITY-12 (consistent snapshot),
INTEGRITY-13/14/15 (crash safety), INTEGRITY-16 / IMPORTS-24 (custom
frameworks), INTEGRITY-17 / SECCODE-12 (sessions + API tokens + audit trail),
INTEGRITY-23 (audit-key mismatch), IMPORTS-21/22/23/26, SECCODE-1 (operator
only) and SECCODE-19 (expanded-size cap).

Service-level tests run against a private throw-away data dir holding a REAL
Athorize schema; API-level tests use the normal test app (live DB = ./test.db
via DATABASE_URL, exactly like an install with a custom DATABASE_URL).
All data is synthetic (Acme / example.com).
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import sqlite3
import tarfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

import models  # noqa: F401  (register every table on Base.metadata)
from database import Base
from models import ApiToken, AuditEntry, Organization, System, User, UserSession
from services import audit as audit_svc
from services.api_token import hash_token
from services.auth import hash_password

FIXTURES = Path(__file__).resolve().parent / "hunts" / "fixtures"


# --------------------------------------------------------------------------- helpers

def settings_obj():
    """The audit key is a setting (config.settings.audit_hmac_key)."""
    from config import settings
    return settings


@pytest.fixture
def datadir(tmp_path, monkeypatch):
    """Private data dir; DATABASE_URL cleared so the live DB is DATA_DIR/data.db."""
    from config import settings
    d = tmp_path / "data"
    (d / "evidence").mkdir(parents=True)
    monkeypatch.setattr(settings, "data_dir", d)
    monkeypatch.setattr(settings, "database_url", "")
    monkeypatch.setattr(settings, "evidence_dir", d / "evidence")
    monkeypatch.setattr(settings, "backup_dir", d / "backups")
    return d


def make_instance_db(path: Path, systems=("ERP",), *, sessions=1, tokens=1, wal=True) -> None:
    """A real Athorize database: one org, an admin, some systems, live sessions
    and API tokens, and a signed audit chain."""
    eng = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(eng)
    with Session(eng) as db:
        org = Organization(name="Acme Industrial Corp", slug="acme")
        db.add(org)
        db.flush()
        admin = User(organization_id=org.id, username="admin", password_hash=hash_password("admin-pass-123!"),
                     email="admin@example.com", display_name="Admin", role="admin", is_operator=True)
        db.add(admin)
        db.flush()
        for name in systems:
            db.add(System(organization_id=org.id, name=name, acronym=name))
            audit_svc.record(db, organization_id=org.id, actor_id=admin.id, actor_username="admin",
                             action="CREATE", entity_type="system", summary=f"created {name}")
        now = datetime.now(timezone.utc)
        for i in range(sessions):
            # ids are SHA-256 of the cookie token (services/sessions.py)
            db.add(UserSession(id=hashlib.sha256(f"tok-{path.name}-{i}".encode()).hexdigest(),
                               user_id=admin.id, expires_at=now + timedelta(days=1), csrf_token=f"c{i}"))
        for i in range(tokens):
            db.add(ApiToken(organization_id=org.id, user_id=admin.id, name=f"ci-{i}",
                            token_prefix="athu_test", token_hash=hash_token(f"athu_raw-{path.name}-{i}")))
        db.commit()
    eng.dispose()
    if wal:
        con = sqlite3.connect(path)
        con.execute("PRAGMA journal_mode=WAL")
        con.close()


def system_names(path: Path) -> list[str]:
    con = sqlite3.connect(path)
    try:
        return [r[0] for r in con.execute("SELECT name FROM systems ORDER BY id")]
    finally:
        con.close()


def scalar(path: Path, sql: str):
    con = sqlite3.connect(path)
    try:
        return con.execute(sql).fetchone()[0]
    finally:
        con.close()


def archive_members(blob: bytes) -> dict[str, bytes]:
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as t:
        return {m.name: t.extractfile(m).read() for m in t.getmembers() if m.isfile()}


def manual_archive(files: dict[str, bytes], manifest: dict | None = None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        m = json.dumps(manifest if manifest is not None else {"version": 1}).encode()
        ti = tarfile.TarInfo("manifest.json")
        ti.size = len(m)
        tar.addfile(ti, io.BytesIO(m))
        for name, data in files.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


# =========================================================================== backup

class TestBackupSnapshot:
    def test_archive_holds_every_committed_row_and_a_v2_manifest(self, datadir):
        from services import backup
        live = datadir / "data.db"
        make_instance_db(live, ["ERP", "SCADA"])
        con = sqlite3.connect(live)
        con.execute("PRAGMA wal_autocheckpoint=0")
        con.execute("INSERT INTO systems (organization_id, name, acronym) VALUES (1, 'DEV', 'DEV')")
        con.commit()
        try:
            assert (datadir / "data.db-wal").stat().st_size > 0
            blob, name = backup.create_backup_bytes(None)
        finally:
            con.close()
        files = archive_members(blob)
        manifest = json.loads(files["manifest.json"])
        assert manifest["version"] == 2
        assert manifest["db"]["sha256"] == hashlib.sha256(files["data.db"]).hexdigest()
        assert manifest["db"]["tables"]["systems"] == 3
        assert manifest["audit_key_fingerprint"] == audit_svc.key_fingerprint()
        out = datadir.parent / "out.db"
        out.write_bytes(files["data.db"])
        assert system_names(out) == ["ERP", "SCADA", "DEV"]
        assert scalar(out, "PRAGMA journal_mode") == "delete"  # self-contained file, no WAL needed

    def test_backup_of_a_database_without_athorize_schema_fails_loudly(self, datadir):
        """DOCKER-1: a fresh instance produced a 462-byte 'successful' backup
        with zero tables. The archive is validated before success is reported."""
        from services import backup
        sqlite3.connect(datadir / "data.db").close()  # 0 tables
        with pytest.raises(backup.BackupError):
            backup.create_backup_bytes(None)
        assert backup.backup_info()["last_backup_name"] is None

    def test_info_lists_encrypted_backups_too(self, datadir):
        from services import backup
        make_instance_db(datadir / "data.db")
        _blob, name = backup.create_backup_bytes("correct horse battery")
        assert name.endswith(".tar.gz.enc")
        assert backup.backup_info()["last_backup_name"] == name

    def test_interrupted_backup_is_never_published(self, datadir, monkeypatch):
        """INTEGRITY-15: a kill while the archive is written must not leave a
        file under a real backup name (and the partial is cleaned up later)."""
        from services import backup
        make_instance_db(datadir / "data.db")

        def kill(step):
            if step == "backup_before_publish":
                raise SystemExit("killed")
        monkeypatch.setattr(backup, "_crash_point", kill)
        with pytest.raises(SystemExit):
            backup.create_backup_bytes(None)
        assert backup.backup_info()["last_backup_name"] is None
        leftovers = [p for p in (datadir / "backups").iterdir() if not p.name.startswith(".")]  # skip the lock file
        assert leftovers and all(p.name.endswith(".partial") for p in leftovers)
        for p in leftovers:
            assert p.stat().st_mode & 0o077 == 0  # never world/group readable, even mid-write
        monkeypatch.setattr(backup, "_crash_point", lambda step: None)
        _blob, name = backup.create_backup_bytes(None)
        assert [p.name for p in (datadir / "backups").iterdir() if not p.name.startswith(".")] == [name]

    def test_custom_frameworks_are_archived(self, datadir):
        from services import backup
        make_instance_db(datadir / "data.db")
        cf = datadir / "custom_frameworks" / "custom-acme"
        cf.mkdir(parents=True)
        (cf / "metadata.json").write_text(json.dumps({"id": "custom-acme", "name": "Acme policy"}))
        (cf / "catalog.json").write_text(json.dumps({"controls": [{"id": "AP-1", "title": "Policy"}]}))
        blob, _ = backup.create_backup_bytes(None)
        files = archive_members(blob)
        assert "custom_frameworks/custom-acme/metadata.json" in files
        assert json.loads(files["manifest.json"])["custom_framework_count"] == 1


class TestNonSqlite:
    def test_postgres_install_is_told_backup_is_unsupported(self, datadir, monkeypatch):
        """IMPORTS-26: never produce an empty 'successful' backup for a DB we can't read."""
        from config import settings
        from services import backup
        monkeypatch.setattr(settings, "database_url", "postgresql://athorize@db.example.com/athorize")
        info = backup.backup_info()
        assert info["supported"] is False
        assert "PostgreSQL" in info["unsupported_reason"] or "postgresql" in info["unsupported_reason"]
        with pytest.raises(backup.BackupUnsupported):
            backup.create_backup_bytes(None)
        with pytest.raises(backup.BackupUnsupported):
            backup.restore_from_bytes(manual_archive({"data.db": b"x"}))

    def test_custom_sqlite_path_is_backed_up(self, datadir, monkeypatch):
        from config import settings
        from services import backup
        elsewhere = datadir.parent / "elsewhere.db"
        make_instance_db(elsewhere, ["CUSTOM-PATH"])
        monkeypatch.setattr(settings, "database_url", f"sqlite:///{elsewhere}")
        blob, _ = backup.create_backup_bytes(None)
        out = datadir.parent / "out.db"
        out.write_bytes(archive_members(blob)["data.db"])
        assert system_names(out) == ["CUSTOM-PATH"]


# =========================================================================== restore

class TestRestoreValidation:
    def test_archive_with_an_empty_database_is_refused(self, datadir):
        """DOCKER-1: restoring the 0-table archive used to report success and
        then every login returned 500 (no such table: users)."""
        from services import backup
        make_instance_db(datadir / "data.db", ["LIVE"])
        empty = datadir.parent / "empty.db"
        sqlite3.connect(empty).close()
        with pytest.raises(backup.BackupError):
            backup.restore_from_bytes(manual_archive({"data.db": empty.read_bytes()}))
        assert system_names(datadir / "data.db") == ["LIVE"]

    def test_db_that_does_not_match_the_manifest_checksum_is_refused(self, datadir):
        from services import backup
        make_instance_db(datadir / "data.db", ["LIVE"])
        blob, _ = backup.create_backup_bytes(None)
        files = archive_members(blob)
        other = datadir.parent / "other.db"
        make_instance_db(other, ["SWAPPED"], wal=False)
        files["data.db"] = other.read_bytes()
        manifest = json.loads(files.pop("manifest.json"))
        with pytest.raises(backup.BackupError, match="checksum"):
            backup.restore_from_bytes(manual_archive(files, manifest))
        assert system_names(datadir / "data.db") == ["LIVE"]

    def test_gzip_bomb_is_refused_before_anything_is_written(self, datadir, monkeypatch):
        """SECCODE-19 / IMPORTS-23 with a VALID database in the archive, so the cap
        (not the missing-DB check) is what stops it."""
        from services import backup
        make_instance_db(datadir / "data.db", ["LIVE"])
        src = datadir.parent / "src.db"
        make_instance_db(src, ["NEW"], wal=False)
        monkeypatch.setattr(backup, "_MAX_RESTORE_EXPANDED_BYTES", 4 * 1024 * 1024)
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=9) as t:
            m = b'{"version": 1}'
            ti = tarfile.TarInfo("manifest.json"); ti.size = len(m); t.addfile(ti, io.BytesIO(m))
            t.add(str(src), arcname="data.db")
            zeros = b"\x00" * (16 * 1024 * 1024)
            ti = tarfile.TarInfo("evidence/1/zeros.bin"); ti.size = len(zeros); t.addfile(ti, io.BytesIO(zeros))
        with pytest.raises(backup.BackupError, match="(?i)expand|size|large"):
            backup.restore_from_bytes(buf.getvalue())
        assert system_names(datadir / "data.db") == ["LIVE"]
        assert not list((datadir / "evidence").rglob("zeros.bin"))
        assert not [p for p in datadir.rglob("*") if ".athorize-restore" in p.name]

    def test_duplicate_member_names_are_refused(self, datadir):
        from services import backup
        make_instance_db(datadir / "data.db", ["LIVE"])
        src = datadir.parent / "src.db"
        make_instance_db(src, ["NEW"], wal=False)
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as t:
            m = b'{"version": 1}'
            ti = tarfile.TarInfo("manifest.json"); ti.size = len(m); t.addfile(ti, io.BytesIO(m))
            t.add(str(src), arcname="data.db")
            ti = tarfile.TarInfo("data.db"); ti.size = 4; t.addfile(ti, io.BytesIO(b"junk"))
        with pytest.raises(backup.BackupError, match="(?i)duplicate"):
            backup.restore_from_bytes(buf.getvalue())


class TestRestoreEffects:
    def test_sessions_purged_tokens_revoked_and_restore_audited(self, datadir):
        """INTEGRITY-17 / SECCODE-12: the restored DB must not resurrect sessions
        or API tokens, and its own audit trail must record the restore."""
        from services import backup
        live = datadir / "data.db"
        make_instance_db(live, ["ERP"], sessions=3, tokens=2)
        blob, _ = backup.create_backup_bytes(None)
        result = backup.restore_from_bytes(blob, actor={"username": "operator-x", "user_id": None})
        assert scalar(live, "SELECT count(*) FROM user_sessions") == 0
        assert scalar(live, "SELECT count(*) FROM api_tokens WHERE revoked_at IS NULL") == 0
        assert scalar(live, "SELECT count(*) FROM api_tokens") == 2  # revoked, not deleted (audit trail)
        assert result["sessions_revoked"] == 3
        assert result["api_tokens_revoked"] == 2
        con = sqlite3.connect(live)
        rows = con.execute("SELECT actor_username, summary FROM audit_entries WHERE action='RESTORE'").fetchall()
        con.close()
        assert len(rows) == 1 and rows[0][0] == "operator-x"
        assert "restored" in rows[0][1].lower()
        # the restored chain (incl. the new RESTORE entry) still verifies with this key
        eng = create_engine(f"sqlite:///{live}")
        with Session(eng) as db:
            assert audit_svc.verify_chain(db, 1)["valid"] is True
        eng.dispose()
        assert result["warnings"] == []

    def test_audit_key_mismatch_is_reported(self, datadir, monkeypatch):
        """INTEGRITY-23: restoring into an instance with a different audit key
        must say so instead of looking like tampering later."""
        from services import backup
        make_instance_db(datadir / "data.db", ["ERP"])
        blob, _ = backup.create_backup_bytes(None)
        monkeypatch.setattr(settings_obj(), "audit_hmac_key", "a-completely-different-key-0123456789")
        result = backup.restore_from_bytes(blob)
        assert any("audit key" in w.lower() for w in result["warnings"]), result["warnings"]
        assert result["audit_key_matches"] is False

    def test_v1_archive_signed_with_another_key_is_reported(self, datadir, monkeypatch):
        """Old (v1) archives carry no key fingerprint: the restore verifies the
        chain itself and warns when it does not verify under this key."""
        from services import backup
        src = datadir.parent / "src.db"
        make_instance_db(src, ["OLD"], wal=False)
        make_instance_db(datadir / "data.db", ["LIVE"])
        monkeypatch.setattr(settings_obj(), "audit_hmac_key", "a-completely-different-key-0123456789")
        result = backup.restore_from_bytes(manual_archive({"data.db": src.read_bytes()}))
        assert any("audit key" in w.lower() for w in result["warnings"]), result["warnings"]

    def test_restore_into_a_fresh_instance_brings_back_custom_frameworks_and_evidence(self, datadir, tmp_path, monkeypatch):
        from config import settings
        from services import backup
        make_instance_db(datadir / "data.db", ["ERP"])
        (datadir / "evidence" / "1").mkdir()
        (datadir / "evidence" / "1" / "scan.pdf").write_bytes(b"%PDF-acme")
        cf = datadir / "custom_frameworks" / "custom-acme"
        cf.mkdir(parents=True)
        (cf / "metadata.json").write_text(json.dumps({"id": "custom-acme", "name": "Acme policy"}))
        blob, _ = backup.create_backup_bytes(None)

        fresh = tmp_path / "fresh"
        (fresh / "evidence").mkdir(parents=True)
        monkeypatch.setattr(settings, "data_dir", fresh)
        monkeypatch.setattr(settings, "evidence_dir", fresh / "evidence")
        monkeypatch.setattr(settings, "backup_dir", fresh / "backups")
        eng = create_engine(f"sqlite:///{fresh / 'data.db'}")
        Base.metadata.create_all(eng)  # a blank instance
        eng.dispose()
        result = backup.restore_from_bytes(blob)
        assert system_names(fresh / "data.db") == ["ERP"]
        assert (fresh / "evidence" / "1" / "scan.pdf").read_bytes() == b"%PDF-acme"
        assert json.loads((fresh / "custom_frameworks" / "custom-acme" / "metadata.json").read_text())["name"] == "Acme policy"
        assert result["restored_custom_frameworks"] == 1
        assert result["restored_evidence_files"] == 1
        assert not [p for p in fresh.rglob("*") if ".athorize-restore" in p.name]

    def test_v1_archive_leaves_live_custom_frameworks_alone(self, datadir):
        """v1 archives never contained custom frameworks; restoring one must not
        wipe the ones this instance has."""
        from services import backup
        src = datadir.parent / "src.db"
        make_instance_db(src, ["OLD"], wal=False)
        make_instance_db(datadir / "data.db", ["LIVE"])
        cf = datadir / "custom_frameworks" / "custom-keep"
        cf.mkdir(parents=True)
        (cf / "metadata.json").write_text("{}")
        backup.restore_from_bytes(manual_archive({"data.db": src.read_bytes()}))
        assert (cf / "metadata.json").exists()

    def test_restoring_an_old_schema_backup_migrates_it(self, datadir):
        """An archive from the 2026-06-13 build must come back with today's schema
        (inline migrations run on the staged copy), not 500 until a restart."""
        from services import backup
        make_instance_db(datadir / "data.db", ["LIVE"])
        old_db = gzip.decompress((FIXTURES / "athorize-2026-06-13-schema.db.gz").read_bytes())
        backup.restore_from_bytes(manual_archive({"data.db": old_db}))
        live = datadir / "data.db"
        con = sqlite3.connect(live)
        cols = {r[1] for r in con.execute("PRAGMA table_info(users)")}
        sess_cols = {r[1] for r in con.execute("PRAGMA table_info(user_sessions)")}
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        con.close()
        assert "is_operator" in cols and "active_organization_id" in sess_cols
        assert "comments" in tables

    def test_stale_wal_of_the_replaced_db_cannot_override_the_restore(self, datadir):
        from services import backup
        live = datadir / "data.db"
        make_instance_db(live, ["OLD"])
        src = datadir.parent / "src.db"
        make_instance_db(src, ["RESTORED"], wal=False)
        other = sqlite3.connect(live)  # e.g. a concurrent request or scheduler thread
        other.execute("PRAGMA wal_autocheckpoint=0")
        for i in range(30):
            other.execute("INSERT INTO systems (organization_id, name) VALUES (1, ?)", (f"OLD-{i}",))
        other.commit()
        try:
            backup.restore_from_bytes(manual_archive({"data.db": src.read_bytes()}))
            assert [r[0] for r in other.execute("SELECT name FROM systems")] == ["RESTORED"]
        finally:
            other.close()
        assert system_names(live) == ["RESTORED"]


# =========================================================================== crash safety

CRASH_STEPS = ["restore_staged", "restore_rollback_saved", "restore_dirs_swapped", "restore_db_installed",
               "restore_committed"]


@pytest.mark.parametrize("step", CRASH_STEPS)
def test_kill_during_restore_leaves_old_or_new_instance_never_a_mix(datadir, monkeypatch, step):
    """INTEGRITY-14: simulate SIGKILL / power loss at every step of a restore,
    then a restart. The instance must come back as exactly the old OR exactly
    the new data (database AND evidence AND custom frameworks agree)."""
    from services import backup
    live = datadir / "data.db"
    make_instance_db(live, ["OLD"])
    (datadir / "evidence" / "1").mkdir()
    (datadir / "evidence" / "1" / "old.txt").write_bytes(b"old")
    # build the "new" archive from a separate instance
    src = datadir.parent / "src.db"
    make_instance_db(src, ["NEW"], wal=False)
    blob_new = manual_archive({"data.db": src.read_bytes(), "evidence/1/new.txt": b"new"})

    def kill(s):
        if s == step:
            raise SystemExit(f"killed at {s}")
    monkeypatch.setattr(backup, "_crash_point", kill)
    with pytest.raises(SystemExit):
        backup.restore_from_bytes(blob_new)
    monkeypatch.setattr(backup, "_crash_point", lambda s: None)
    backup._RESTORE_LOCK = __import__("threading").Lock()  # a restart gets a fresh process
    backup.recover_interrupted_restore()  # what startup runs

    assert live.is_file()
    names = system_names(live)
    evidence = sorted(p.name for p in (datadir / "evidence").rglob("*") if p.is_file())
    assert (names, evidence) in ((["OLD"], ["old.txt"]), (["NEW"], ["new.txt"])), (names, evidence)
    assert scalar(live, "PRAGMA integrity_check") == "ok"
    assert not [p for p in datadir.rglob("*") if ".athorize-restore" in p.name]
    assert not (datadir / ".athorize-restore-journal.json").exists()


def test_failed_restore_rolls_back_in_process(datadir, monkeypatch):
    from services import backup
    live = datadir / "data.db"
    make_instance_db(live, ["OLD"])
    (datadir / "evidence" / "1").mkdir()
    (datadir / "evidence" / "1" / "old.txt").write_bytes(b"old")
    src = datadir.parent / "src.db"
    make_instance_db(src, ["NEW"], wal=False)

    def boom(s):
        if s == "restore_db_installed":
            raise OSError("disk full")
    monkeypatch.setattr(backup, "_crash_point", boom)
    with pytest.raises(backup.BackupError, match="rolled back"):
        backup.restore_from_bytes(manual_archive({"data.db": src.read_bytes(), "evidence/1/new.txt": b"new"}))
    assert system_names(live) == ["OLD"]
    assert sorted(p.name for p in (datadir / "evidence").rglob("*") if p.is_file()) == ["old.txt"]


# =========================================================================== API

def _login(client, username, password):
    client.cookies.clear()
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"X-CSRF-Token": client.cookies.get("universal_csrf")}


def _restore(client, headers, blob, passphrase=""):
    nonce = client.get("/api/backup/info").json()["restore_nonce"]
    return client.post("/api/backup/restore", data={"nonce": nonce, "passphrase": passphrase},
                       files={"file": ("b.tar.gz", io.BytesIO(blob), "application/gzip")}, headers=headers)


class TestApi:
    def test_company_admin_cannot_back_up_a_multi_company_instance(self, client, db, seeded):
        """SECCODE-1: a backup holds EVERY company's data (and password hashes),
        and a restore replaces every company — instance operator only."""
        other = Organization(name="Globex", slug="globex")
        db.add(other)
        db.flush()
        db.add(User(organization_id=other.id, username="globex-admin", password_hash=hash_password("Globex-pass-123!"),
                    email="g@example.com", display_name="G", role="admin"))
        db.add(User(organization_id=seeded["org"].id, username="op", password_hash=hash_password("Operator-pass-123!"),
                    email="op@example.com", display_name="Op", role="admin", is_operator=True))
        db.commit()
        h = _login(client, "globex-admin", "Globex-pass-123!")
        assert client.get("/api/backup/info").status_code == 403
        assert client.post("/api/backup/download", data={"passphrase": ""}, headers=h).status_code == 403
        r = client.post("/api/backup/restore", data={"nonce": "x", "passphrase": ""},
                        files={"file": ("b.tar.gz", io.BytesIO(b"x"), "application/gzip")}, headers=h)
        assert r.status_code == 403
        h = _login(client, "op", "Operator-pass-123!")
        assert client.get("/api/backup/info").status_code == 200
        r = client.post("/api/backup/download", data={"passphrase": ""}, headers=h)
        assert r.status_code == 200, r.text

    def test_single_company_admin_can_back_up(self, auth_client):
        client, _seeded, csrf = auth_client
        assert client.get("/api/backup/info").status_code == 200
        assert client.post("/api/backup/download", data={"passphrase": ""},
                           headers={"X-CSRF-Token": csrf}).status_code == 200

    def test_restore_end_to_end_signs_everyone_out_and_is_truthful(self, client, db, seeded):
        h = _login(client, "testadmin", "testpass1234!")
        tok = client.post("/api/tokens", json={"name": "ci"}, headers=h).json()["token"]
        old_cookie = client.cookies.get("session_id")
        assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 200
        dl = client.post("/api/backup/download", data={"passphrase": ""}, headers=h)
        assert dl.status_code == 200
        r = _restore(client, h, dl.content)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["restored_db"] is True
        assert body["sessions_revoked"] >= 1 and body["api_tokens_revoked"] >= 1
        assert "sign in again" in body["note"].lower() and "api token" in body["note"].lower()
        client.cookies.clear()
        client.cookies.set("session_id", old_cookie)
        assert client.get("/api/auth/me").status_code == 401
        assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 401
        _login(client, "testadmin", "testpass1234!")
        actions = [e["action"] for e in client.get("/api/audit").json()]
        assert "RESTORE" in actions

    def test_unsupported_database_is_explained_by_the_api(self, auth_client, monkeypatch):
        from config import settings
        client, _seeded, csrf = auth_client
        monkeypatch.setattr(settings, "database_url", "postgresql://athorize@db.example.com/athorize")
        info = client.get("/api/backup/info").json()
        assert info["supported"] is False
        r = client.post("/api/backup/download", data={"passphrase": ""}, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 400
        assert "postgresql" in r.json()["detail"].lower()


# =========================================================================== retention (decision #8)

def _old_backup(bdir: Path, stamp: str, age_s: int, ext: str = ".tar.gz") -> Path:
    import os
    import time
    bdir.mkdir(parents=True, exist_ok=True)
    p = bdir / f"universal-backup-{stamp}{ext}"
    p.write_bytes(b"old")
    t = time.time() - age_s
    os.utime(p, (t, t))
    return p


class TestRetention:
    def test_backup_prunes_oldest_beyond_the_limit(self, datadir, monkeypatch):
        from config import settings
        from services import backup
        monkeypatch.setattr(settings, "backup_keep", 3)
        make_instance_db(datadir / "data.db")
        b = datadir / "backups"
        olds = [_old_backup(b, f"2026-01-0{i}-000000", age_s=1000 * (6 - i), ext=".tar.gz.enc" if i == 2 else ".tar.gz")
                for i in range(1, 6)]  # olds[4] is the newest old one
        _blob, name = backup.create_backup_bytes(None)
        left = sorted(p.name for p in b.iterdir() if not p.name.startswith("."))  # skip the lock file
        assert left == sorted([name, olds[4].name, olds[3].name])

    def test_never_deletes_the_backup_just_written(self, datadir, monkeypatch):
        from config import settings
        from services import backup
        monkeypatch.setattr(settings, "backup_keep", 1)
        make_instance_db(datadir / "data.db")
        future = _old_backup(datadir / "backups", "2099-01-01-000000", age_s=-10_000)  # clock skew: "newer" mtime
        _blob, name = backup.create_backup_bytes(None)
        assert (datadir / "backups" / name).is_file()
        assert not future.exists()

    def test_zero_keeps_everything(self, datadir, monkeypatch):
        from config import settings
        from services import backup
        monkeypatch.setattr(settings, "backup_keep", 0)
        monkeypatch.setattr(settings, "backup_keep_rollbacks", 0)
        make_instance_db(datadir / "data.db")
        olds = [_old_backup(datadir / "backups", f"2026-01-0{i}-000000", age_s=100 * i) for i in range(1, 8)]
        backup.create_backup_bytes(None)
        assert all(p.exists() for p in olds)

    def test_foreign_files_are_never_touched(self, datadir, monkeypatch, tmp_path):
        from config import settings
        from services import backup
        monkeypatch.setattr(settings, "backup_keep", 1)
        monkeypatch.setattr(settings, "backup_keep_rollbacks", 1)
        make_instance_db(datadir / "data.db")
        b = datadir / "backups"
        b.mkdir(parents=True, exist_ok=True)
        outside = tmp_path / "outside.tar.gz"
        outside.write_bytes(b"not ours")
        foreign = [b / "data-2026-01-01.db", b / "notes.txt", b / "someone-elses-upload.partial",
                   b / "universal-backup-notes.partial", b / "my-universal-backup-2020-01-01-000000.tar.gz"]
        for p in foreign:
            p.write_bytes(b"keep me")
        (b / "universal-backup-2020-01-02-000000.tar.gz").symlink_to(outside)
        (b / "universal-backup-2020-01-03-000000.tar.gz").mkdir()
        (b / "rollback-manual-copy").mkdir()
        _old_backup(b, "2020-01-04-000000", age_s=50_000)  # a real old backup: this one goes
        backup.create_backup_bytes(None)
        assert all(p.exists() for p in foreign)
        assert outside.read_bytes() == b"not ours"
        assert (b / "universal-backup-2020-01-02-000000.tar.gz").is_symlink()
        assert (b / "universal-backup-2020-01-03-000000.tar.gz").is_dir()
        assert (b / "rollback-manual-copy").is_dir()
        assert not (b / "universal-backup-2020-01-04-000000.tar.gz").exists()

    def test_restore_keeps_only_the_newest_rollback_copies(self, datadir, monkeypatch):
        import os
        import time
        from config import settings
        from services import backup
        monkeypatch.setattr(settings, "backup_keep_rollbacks", 3)
        make_instance_db(datadir / "data.db", ["LIVE"])
        b = datadir / "backups"
        b.mkdir(parents=True, exist_ok=True)
        old = []
        for i in range(1, 5):
            d = b / f"rollback-2026-01-0{i}-000000"
            d.mkdir()
            (d / "data.db").write_bytes(b"old")
            t = time.time() - 1000 * (5 - i)
            os.utime(d, (t, t))
            old.append(d)
        src = datadir.parent / "src.db"
        make_instance_db(src, ["NEW"], wal=False)
        result = backup.restore_from_bytes(manual_archive({"data.db": src.read_bytes()}))
        left = sorted(p.name for p in b.iterdir() if p.name.startswith("rollback-"))
        assert left == sorted([result["rollback_path"], old[3].name, old[2].name])

    def test_info_reports_the_retention(self, datadir, monkeypatch):
        from config import settings
        from services import backup
        monkeypatch.setattr(settings, "backup_keep", 7)
        monkeypatch.setattr(settings, "backup_keep_rollbacks", 2)
        make_instance_db(datadir / "data.db")
        info = backup.backup_info()
        assert info["keep_backups"] == 7 and info["keep_rollbacks"] == 2

    def test_partial_of_a_backup_in_progress_elsewhere_is_never_deleted(self, datadir):
        """The offline CLI (another process) may be writing a backup right now:
        its lock makes this process refuse instead of deleting its *.partial."""
        import fcntl
        from services import backup
        make_instance_db(datadir / "data.db")
        b = datadir / "backups"
        b.mkdir(parents=True, exist_ok=True)
        in_use = b / "universal-backup-2026-10-22-010101.tar.gz.partial"
        in_use.write_bytes(b"being written by the CLI")
        with open(b / ".athorize-backup.lock", "a") as other_process:
            fcntl.flock(other_process.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with pytest.raises(backup.BackupBusy):
                backup.create_backup_bytes(None)
        assert in_use.read_bytes() == b"being written by the CLI"
        backup.create_backup_bytes(None)  # lock released: the stale partial is now cleaned up
        assert not in_use.exists()

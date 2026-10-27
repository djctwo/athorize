"""Round-2 data-path hunt (team r2data): backup/evidence. FAIL on main @ 32fe7d0."""
from __future__ import annotations

import io
import sqlite3
import tarfile

import pytest

from services import backup as backup_svc
from tests.test_backup_safety import datadir, make_instance_db  # noqa: F401


# R2DATA-8 -------------------------------------------------------------------
# AES-GCM in `cryptography` refuses plaintexts >= 2 GiB (OverflowError), and
# _encrypt() hands it the whole tar at once: any install whose archive reaches
# 2 GiB (e.g. ~25 large evidence PDFs/pcaps at the 100 MiB cap) can never make
# an encrypted backup — in-app or with the CLI that INSTALL.md §10 recommends
# for large installs. OverflowError is not a BackupError, so the API answers 500.
# (Allocates 2 GiB; ~5 s.)
def test_encrypting_a_2gib_archive_works():
    blob = backup_svc._encrypt(bytes(2 ** 31), "correct horse battery staple")
    assert backup_svc.is_encrypted(blob)


# R2DATA-9 -------------------------------------------------------------------
# The DB is snapshotted first and the evidence tree is walked afterwards. An
# evidence file deleted in between is skipped ("its DB row went with it" — but
# the row is IN the snapshot), so the archive holds an evidence row whose file
# is missing, and the backup reports success with no warning. After restore
# that evidence 404s on download and breaks the audit binder.
def test_backup_never_holds_an_evidence_row_without_its_file(datadir, monkeypatch):
    db = datadir / "data.db"
    make_instance_db(db)
    con = sqlite3.connect(db)
    con.execute("INSERT INTO evidence_artifacts (organization_id, system_id, filename, file_path, control_ids, framework_ids)"
                " VALUES (1, 1, 'policy.pdf', '1/abc.pdf', '[]', '[]')")
    con.commit()
    con.close()
    (datadir / "evidence" / "1").mkdir(parents=True)
    f = datadir / "evidence" / "1" / "abc.pdf"
    f.write_bytes(b"%PDF-1.4 policy")

    real = backup_svc._snapshot_db

    def snapshot_then_user_deletes(src, dest):
        real(src, dest)
        # DELETE /api/evidence/{id} lands right after the snapshot
        f.unlink()
        c = sqlite3.connect(db)
        c.execute("DELETE FROM evidence_artifacts")
        c.commit()
        c.close()

    monkeypatch.setattr(backup_svc, "_snapshot_db", snapshot_then_user_deletes)
    res = backup_svc.create_backup()
    with tarfile.open(res.path, "r:gz") as t:
        names = set(t.getnames())
        t.extract("data.db", datadir / "x", filter="data")
    rows = [r[0] for r in sqlite3.connect(datadir / "x" / "data.db").execute("SELECT file_path FROM evidence_artifacts")]
    missing = [p for p in rows if f"evidence/{p}" not in names]
    assert not missing, f"archive has evidence rows without files: {missing} (no warning given)"


# R2DATA-10 ------------------------------------------------------------------
# DELETE /api/evidence/{id} unlinks the file BEFORE the DB commit. If the
# commit fails (SQLite busy past busy_timeout under a long write, disk full,
# audit-chain error) the row survives and its file is gone for good.
def test_failed_evidence_delete_keeps_the_file(H, monkeypatch):  # noqa: F811
    from routers import evidence as ev_router
    r = H.c.post("/api/evidence/upload", data={"system_id": str(H.system.id)},
                 files={"file": ("p.txt", io.BytesIO(b"proof"), "text/plain")})
    assert r.status_code == 200, r.text
    eid = r.json()["id"]

    def boom(*a, **kw):
        import sqlalchemy.exc
        raise sqlalchemy.exc.OperationalError("INSERT", {}, Exception("database is locked"))

    monkeypatch.setattr(ev_router.audit_svc, "record", boom)
    assert H.c.delete(f"/api/evidence/{eid}").status_code == 500
    monkeypatch.undo()
    assert H.c.get(f"/api/evidence/{eid}").status_code == 200  # row survived
    assert H.c.get(f"/api/evidence/{eid}/download").status_code == 200, "file deleted although the delete failed"


from tests.hunts.test_import_hunt import H  # noqa: E402,F401


# R2DATA-15 ------------------------------------------------------------------
# `python -m services.backup restore` must only run with the server stopped
# (its own docstring), but nothing enforces it: the file lock is held by the
# server only DURING an in-app backup/restore. Live on :8068 with a writer
# running: the CLI restore succeeded while the server answered 200 to 2,441
# finding creations that were then silently discarded (1 survived).
def test_cli_restore_refuses_while_a_server_is_running(datadir):
    from fastapi.testclient import TestClient
    from main import app
    make_instance_db(datadir / "data.db")
    archive = backup_svc.create_backup().path
    with TestClient(app):  # a running server (lifespan started)
        rc = backup_svc._cli(["restore", str(archive)])
    assert rc != 0, "CLI restore ran against a live server"


# R2DATA-16 ------------------------------------------------------------------
# Archives made before the fix (v1) copied data.db without its WAL, so they
# can lack recent rows (live check: a pre-fix archive held 3,000 evidence
# files but only 2,966 evidence rows; 46 uploads were simply gone after the
# restore). The restore reports success with no warning, although the
# archive itself shows the symptom: evidence files that no row refers to.
def test_restore_warns_about_evidence_files_without_records(datadir, tmp_path):
    src = tmp_path / "src.db"
    make_instance_db(src)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in (("manifest.json", b'{"version": 1}'), ("data.db", src.read_bytes()),
                           ("evidence/1/orphan.pdf", b"%PDF uploaded but its row was still in the WAL")):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
    make_instance_db(datadir / "data.db")
    out = backup_svc.restore_from_bytes(buf.getvalue())
    assert out["warnings"], "restored an archive with unreferenced evidence files without any warning"


# --------------------------------------------------------------------------- W2-DATA additions
# R2DATA-8: the chunked format round-trips, is tamper-evident, and archives
# written in the old single-message format (UNIV1) still restore.

def _old_univ1(plain: bytes, passphrase: str) -> bytes:
    """Byte-for-byte what _encrypt() wrote before chunked encryption."""
    import secrets as _s
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt, nonce = _s.token_bytes(16), _s.token_bytes(12)
    return b"UNIV1" + salt + nonce + AESGCM(backup_svc._derive_key(passphrase, salt)).encrypt(nonce, plain, None)


@pytest.mark.parametrize("size", [0, 1, 4096, 4096 * 3, 4096 * 3 + 7])
def test_chunked_encryption_round_trips_at_chunk_boundaries(size):
    plain = bytes((i * 7) % 251 for i in range(size))
    out = io.BytesIO()
    backup_svc._encrypt_stream(io.BytesIO(plain), out, "pw", chunk_size=4096)
    blob = out.getvalue()
    assert backup_svc.is_encrypted(blob) and blob.startswith(b"UNIV2")
    assert backup_svc._decrypt(blob, "pw") == plain


def test_chunked_encryption_detects_tampering():
    plain = bytes(range(256)) * 64  # 16 KiB = 4 chunks of 4 KiB + an empty final chunk
    out = io.BytesIO()
    backup_svc._encrypt_stream(io.BytesIO(plain), out, "pw", chunk_size=4096)
    blob = out.getvalue()
    hdr, sealed = 33, 4096 + 16
    chunks = [blob[hdr + i * sealed: hdr + (i + 1) * sealed] for i in range(4)]
    bad = {
        "wrong passphrase": (blob, "nope"),
        "cut at a chunk boundary": (blob[:hdr + 2 * sealed], "pw"),
        "final chunk dropped": (blob[:-16], "pw"),
        "chunks swapped": (blob[:hdr] + chunks[1] + chunks[0] + blob[hdr + 2 * sealed:], "pw"),
        "bit flipped": (blob[:100] + bytes([blob[100] ^ 1]) + blob[101:], "pw"),
        "trailing data": (blob + b"x", "pw"),
        "header altered": (blob[:21] + (8192).to_bytes(4, "big") + blob[25:], "pw"),
    }
    for what, (data, pw) in bad.items():
        with pytest.raises(backup_svc.BackupError):
            backup_svc._decrypt(data, pw)
            pytest.fail(what)


def test_encrypted_backup_restores_from_file_and_old_univ1_archives_still_restore(datadir, tmp_path):
    from tests.test_backup_safety import system_names
    live = datadir / "data.db"
    make_instance_db(live, ["V2"])
    (datadir / "evidence" / "1").mkdir()
    (datadir / "evidence" / "1" / "scan.pdf").write_bytes(b"%PDF scan")
    res = backup_svc.create_backup("s3cret pass")
    assert res.path.name.endswith(".tar.gz.enc") and res.path.read_bytes().startswith(b"UNIV2")
    assert res.manifest["encryption_format"] == "UNIV2"

    make_instance_db(tmp_path / "old.db", ["OLDFORMAT"])
    old_plain = io.BytesIO()
    with tarfile.open(fileobj=old_plain, mode="w:gz") as t:
        for name, data in (("manifest.json", b'{"version": 1}'), ("data.db", (tmp_path / "old.db").read_bytes())):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    old_enc = tmp_path / "universal-backup-2026-01-01-000000.tar.gz.enc"
    old_enc.write_bytes(_old_univ1(old_plain.getvalue(), "old pass"))

    backup_svc.restore_from_bytes(old_enc.read_bytes(), "old pass")      # in-app upload path
    assert system_names(live) == ["OLDFORMAT"]
    backup_svc.restore_from_file(res.path, "s3cret pass")                # CLI path, streamed
    assert system_names(live) == ["V2"]
    assert (datadir / "evidence" / "1" / "scan.pdf").read_bytes() == b"%PDF scan"
    backup_svc.restore_from_file(old_enc, "old pass")
    assert system_names(live) == ["OLDFORMAT"]
    with pytest.raises(backup_svc.BackupError, match="wrong passphrase"):
        backup_svc.restore_from_file(res.path, "bad")
    assert system_names(live) == ["OLDFORMAT"]
    assert not list((datadir / "backups").glob(".athorize-restore-decrypted-*"))  # temp plaintext removed


def test_cli_restore_streams_an_encrypted_archive(datadir, monkeypatch, capsys):
    from tests.test_backup_safety import system_names
    live = datadir / "data.db"
    make_instance_db(live, ["CLI"])
    archive = backup_svc.create_backup("pw").path
    make_instance_db(datadir / "other.db", ["CHANGED"])
    import shutil as _sh
    _sh.copy(datadir / "other.db", live)
    monkeypatch.setenv("ATHORIZE_TEST_PASS", "pw")
    assert backup_svc._cli(["restore", str(archive), "--passphrase-env", "ATHORIZE_TEST_PASS"]) == 0
    assert system_names(live) == ["CLI"]


# R2DATA-9: the backup reports evidence rows whose file is gone (not hidden).
def test_backup_reports_an_evidence_row_whose_file_was_already_missing(datadir):
    db = datadir / "data.db"
    make_instance_db(db)
    con = sqlite3.connect(db)
    con.execute("INSERT INTO evidence_artifacts (organization_id, system_id, filename, file_path, control_ids, framework_ids)"
                " VALUES (1, 1, 'lost.pdf', '1/lost.pdf', '[]', '[]')")
    con.commit()
    con.close()
    res = backup_svc.create_backup()
    assert res.manifest["missing_evidence_files"] == 1 and res.manifest["missing_evidence_sample"] == ["1/lost.pdf"]
    assert res.warnings and "1/lost.pdf" in res.warnings[0]
    assert not [p for p in (datadir / "evidence").iterdir() if p.name.startswith(".athorize-restore-pin-")]


# R2DATA-16 (other direction): records without files are reported on restore too.
def test_restore_warns_about_evidence_records_without_files(datadir, tmp_path):
    src = tmp_path / "src.db"
    make_instance_db(src)
    con = sqlite3.connect(src)
    con.execute("INSERT INTO evidence_artifacts (organization_id, system_id, filename, file_path, control_ids, framework_ids)"
                " VALUES (1, 1, 'x.pdf', '1/x.pdf', '[]', '[]')")
    con.commit()
    con.close()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in (("manifest.json", b'{"version": 2}'), ("data.db", src.read_bytes())):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
    make_instance_db(datadir / "data.db")
    out = backup_svc.restore_from_bytes(buf.getvalue())
    assert any("no file" in w and "1/x.pdf" in w for w in out["warnings"]), out["warnings"]


# R2DATA-15: once the server has stopped, the CLI restore works.
def test_cli_restore_works_once_the_server_has_stopped(datadir):
    from fastapi.testclient import TestClient
    from main import app
    make_instance_db(datadir / "data.db")
    archive = backup_svc.create_backup().path
    with TestClient(app):
        assert backup_svc._cli(["restore", str(archive)]) == 1
    assert backup_svc._cli(["restore", str(archive)]) == 0


# R2DATA-17: the startup log names a rollback folder only when it exists.
def test_recovery_log_does_not_point_at_a_deleted_rollback_folder(datadir, monkeypatch, caplog):
    import logging
    from tests.test_backup_safety import manual_archive
    make_instance_db(datadir / "data.db", ["OLD"])
    src = datadir.parent / "new.db"
    make_instance_db(src, ["NEW"], wal=False)

    def kill(step):
        if step == "restore_staged":
            raise SystemExit("killed while staging")
    monkeypatch.setattr(backup_svc, "_crash_point", kill)
    with pytest.raises(SystemExit):
        backup_svc.restore_from_bytes(manual_archive({"data.db": src.read_bytes()}))
    monkeypatch.setattr(backup_svc, "_crash_point", lambda s: None)
    backup_svc._RESTORE_LOCK = __import__("threading").Lock()  # type(lock)() fails on Python 3.11
    with caplog.at_level(logging.ERROR, logger="services.backup"):
        assert backup_svc.recover_interrupted_restore() == "rolled_back"
    text = caplog.text
    assert "nothing had been changed" in text and "rollback copy kept" not in text, text

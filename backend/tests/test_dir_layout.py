"""R2SEC-6: EVIDENCE_DIR == DATA_DIR (or BACKUP_DIR inside EVIDENCE_DIR).

Hunter's test (r2sec cloneC test_r2sec_backup.py::test_evidence_dir_equal_to_data_dir)
asserted that backup + restore "work" in that layout and keep secrets.env. The
fix refuses the layout instead (at startup — see test_settings_config.py — and
here, because settings can change at runtime), so the test is corrected to
expect the refusal; its two outcome assertions (secrets.env stays, the live DB
is unchanged) are kept as they were.
"""
import pytest

from tests.test_backup_safety import datadir, make_instance_db, system_names  # noqa: F401


def test_evidence_dir_equal_to_data_dir(datadir, monkeypatch):
    from config import settings
    from services import backup
    make_instance_db(datadir / "data.db", ["LIVE"])
    good_archive = backup.create_backup_bytes(None)[0]        # taken with a sane layout
    monkeypatch.setattr(settings, "evidence_dir", datadir)
    (datadir / "secrets.env").write_text("ATHORIZE_AUDIT_HMAC_KEY=x\n")
    with pytest.raises(backup.BackupError, match="folder of its own"):
        backup.create_backup()
    with pytest.raises(backup.BackupError, match="folder of its own"):
        backup.restore_from_bytes(good_archive)
    assert (datadir / "secrets.env").exists(), "secrets.env moved out of DATA_DIR by the restore swap"
    assert system_names(datadir / "data.db") == ["LIVE"]


def test_backup_dir_inside_evidence_dir_is_refused(datadir, monkeypatch):
    from config import settings
    from services import backup
    make_instance_db(datadir / "data.db", ["LIVE"])
    monkeypatch.setattr(settings, "backup_dir", datadir / "evidence" / "backups")
    with pytest.raises(backup.BackupError, match="BACKUP_DIR"):
        backup.create_backup()


def test_offline_file_restore_refuses_the_layout_too(datadir, monkeypatch, tmp_path):
    """restore_from_file (the CLI path, added by W2-DATA) gets the same refusal."""
    from config import settings
    from services import backup
    make_instance_db(datadir / "data.db", ["LIVE"])
    archive = tmp_path / "a.tar.gz"
    archive.write_bytes(backup.create_backup_bytes(None)[0])
    monkeypatch.setattr(settings, "evidence_dir", datadir)
    (datadir / "secrets.env").write_text("ATHORIZE_AUDIT_HMAC_KEY=x\n")
    with pytest.raises(backup.BackupError, match="folder of its own"):
        backup.restore_from_file(archive)
    assert (datadir / "secrets.env").exists()
    assert system_names(datadir / "data.db") == ["LIVE"]

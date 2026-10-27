"""R2SEC-8: on a non-Docker start (umask 022) the database, evidence and data
folders were world-readable. They must be owner-only like secrets.env."""
import os
import sqlite3
import stat

import database  # noqa: F401  (import = server start path)


def _mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


def test_server_process_creates_owner_only_files(tmp_path):
    current = os.umask(0o077)
    os.umask(current)
    assert current & 0o077 == 0o077, oct(current)
    db = tmp_path / "data.db"
    sqlite3.connect(db).execute("CREATE TABLE t (x)").connection.commit()
    assert _mode(db) & 0o077 == 0


def test_existing_world_readable_dirs_are_restricted(tmp_path):
    from services.data_perms import secure_data_dirs
    data, ev = tmp_path / "data", tmp_path / "data" / "evidence"
    ev.mkdir(parents=True)
    os.chmod(data, 0o755)
    os.chmod(ev, 0o755)
    secure_data_dirs(data, ev, data / "backups")
    assert _mode(data) == 0o700 and _mode(ev) == 0o700 and _mode(data / "backups") == 0o700

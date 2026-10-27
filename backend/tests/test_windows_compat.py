"""Windows-only behaviours found by running the e2e suite against the built
.exe on GitHub's Windows runner (.github/workflows/build-windows-desktop.yml).
They cannot fail on macOS/Linux by themselves, so each test emulates the
Windows semantics that broke."""
import errno
import logging
import os

import pytest

fcntl = pytest.importorskip("fcntl")  # the emulation needs POSIX fd flags


def _windows_fsync(real_fsync):
    """Windows' os.fsync is _commit(), which refuses a descriptor opened
    read-only with EBADF ("[Errno 9] Bad file descriptor")."""
    def fsync(fd):
        if fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY:
            raise OSError(errno.EBADF, "Bad file descriptor")
        return real_fsync(fd)
    return fsync


def test_fsync_file_works_with_windows_fsync_semantics(tmp_path, monkeypatch):
    # WIN-1: every restore of a backup failed on Windows with
    # "Restore failed; nothing was changed: [Errno 9] Bad file descriptor"
    # because the rollback copy of data.db was fsynced through a read-only fd.
    from services import backup
    f = tmp_path / "data.db.partial"
    f.write_bytes(b"x" * 100)
    monkeypatch.setattr(os, "fsync", _windows_fsync(os.fsync))
    backup._fsync_file(f)  # must not raise
    assert f.read_bytes() == b"x" * 100


def test_data_dirs_do_not_claim_a_restriction_windows_cannot_make(tmp_path, monkeypatch, caplog):
    # WIN-2: Windows reports every folder as mode 777 and chmod cannot change
    # that, so each start of the .exe logged "data: restricted <dir> to its
    # owner (was 777)" three times — a protection that never happened.
    from services import data_perms
    monkeypatch.setattr(data_perms, "_POSIX_MODES", False)
    chmods = []
    monkeypatch.setattr(os, "chmod", lambda *a, **k: chmods.append(a))
    d = tmp_path / "data"
    d.mkdir()
    with caplog.at_level(logging.WARNING, logger="services.data_perms"):
        data_perms.secure_data_dirs(d, d / "evidence")
    assert (d / "evidence").is_dir()
    assert chmods == []
    assert "restricted" not in caplog.text

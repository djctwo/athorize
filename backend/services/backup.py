"""Backup & restore of a whole Athorize instance.

Archive layout (``.tar.gz``, optionally AES-GCM encrypted):
    data.db                 - consistent SQLite snapshot (online-backup API,
                              so commits still in the WAL are included)
    evidence/...            - evidence tree, preserves {system_id}/ layout
    custom_frameworks/...   - customer-authored framework plugins (v2+)
    manifest.json           - written last: version, created_at, db checksum
                              and per-table row counts, file counts, audit-key
                              fingerprint

Only the built-in SQLite database is supported. For any other DATABASE_URL the
operations refuse with an explanation instead of producing an archive that
silently holds no data.

The audit-chain HMAC key is INTENTIONALLY excluded from backup archives
(operators escrow it separately). The manifest carries a short fingerprint of
it so a restore can warn when the archive was signed with a different key.

Passphrase encryption (AES-GCM) is optional but recommended. Layout when
``passphrase`` is supplied: ``UNIV1 | salt(16) | nonce(12) | ciphertext+tag``.
PBKDF2-HMAC-SHA256 / 200k iterations derives the 32-byte AES key.

Backup is crash-safe: everything is written to ``*.partial`` files (mode 0600)
and only renamed to the real backup name after the archive has been re-read
and verified.

Restore never leaves the instance without a database, or with a mix of old and
new data:
  1. validate the archive (allow-list, no links/duplicates, expanded-size and
     disk-space caps) and stage it next to the live data;
  2. validate the staged database (SQLite integrity, Athorize tables, manifest
     checksum), migrate it to the current schema, purge every session, revoke
     every API token and append a RESTORE entry to each company's audit chain;
  3. save a rollback copy of the live database, then swap the evidence and
     custom-framework trees and install the database through SQLite's backup
     API (one atomic transaction - concurrent connections and the old WAL
     cannot resurrect old rows).
A journal file records progress; ``recover_interrupted_restore()`` (run at
startup) rolls an interrupted restore back, or finishes one that committed.
"""

from __future__ import annotations

import errno
import hashlib
import io
import json
import logging
import os
import re
import secrets
import shutil
import sqlite3
import sys
import tarfile
import threading
import time
import zlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from sqlalchemy.engine import make_url

from config import settings
from database import engine

logger = logging.getLogger(__name__)

BACKUP_VERSION = 2
_SUPPORTED_VERSIONS = (1, 2)
MANIFEST_NAME = "manifest.json"
DB_MEMBER = "data.db"
EVIDENCE_PREFIX = "evidence/"
CUSTOM_FW_PREFIX = "custom_frameworks/"

# A database without these is not an Athorize database (restoring it would
# leave every request failing with "no such table").
_REQUIRED_TABLES = ("organizations", "users", "user_sessions", "audit_entries", "systems")

MAX_RESTORE_UPLOAD_BYTES = 512 * 1024 * 1024        # in-app upload ceiling
_MAX_RESTORE_EXPANDED_BYTES = 8 * 1024 * 1024 * 1024  # gzip-bomb ceiling
_MAX_RESTORE_MEMBERS = 250_000
_MAX_MANIFEST_BYTES = 1024 * 1024
_DISK_HEADROOM_BYTES = 64 * 1024 * 1024

# Encrypted archive formats (both restorable):
#   UNIV1 | salt(16) | nonce(12) | ciphertext+tag         - one AES-GCM message (< 2 GiB)
#   UNIV2 | salt(16) | chunk_size(4) | nonce_prefix(8) | sealed chunks
#         each chunk: AES-GCM(nonce = prefix || index(4), aad = header || index(8) || final(1))
_ENC_MAGIC = b"UNIV1"
_ENC_MAGIC_V2 = b"UNIV2"
_ENC_CHUNK = 4 * 1024 * 1024
_MAX_ENC_CHUNK = 64 * 1024 * 1024
_TAG_LEN = 16
_NONCE_PREFIX_LEN = 8
_SALT_LEN = 16
_NONCE_LEN = 12
_KEY_LEN = 32
_PBKDF2_ITERATIONS = 200_000

# Work areas created during a restore. Anything with this prefix is never
# counted, archived or served.
_WORK_PREFIX = ".athorize-restore-"
_PIN_PREFIX = _WORK_PREFIX + "pin-"   # hard-link pins of a running backup
_JOURNAL_NAME = ".athorize-restore-journal.json"

_restore_nonces: dict[str, float] = {}
_NONCE_TTL = 300
_MAX_ACTIVE_NONCES = 10

# One backup/restore at a time per process (the app runs a single worker).
_RESTORE_LOCK = threading.Lock()
_restore_active = threading.Event()


class BackupError(Exception):
    pass


class BackupUnsupported(BackupError):
    """This instance's database cannot be backed up or restored in-app."""


class BackupBusy(BackupError):
    """Another backup or restore is already running."""


def _crash_point(step: str) -> None:
    """No-op. Tests replace it to simulate a kill / power loss at ``step``."""


def restore_in_progress() -> bool:
    return _restore_active.is_set()


# --------------------------------------------------------------------------- paths

def _data_dir() -> Path:
    return settings.data_dir


def _evidence_dir() -> Path:
    return settings.evidence_dir


def _custom_frameworks_dir() -> Path:
    return settings.custom_frameworks_dir


def _backups_dir() -> Path:
    d = settings.backup_dir
    d.mkdir(parents=True, exist_ok=True)
    return d


_DIALECT_NAMES = {"postgresql": "PostgreSQL", "mysql": "MySQL", "mariadb": "MariaDB", "mssql": "SQL Server",
                  "oracle": "Oracle"}


def _db_path() -> Path:
    """The live SQLite file, derived from the same URL the engine uses
    (DATABASE_URL, else DATA_DIR/data.db). Raises BackupUnsupported otherwise."""
    url = make_url(settings.db_url)
    backend = url.get_backend_name()
    if backend != "sqlite":
        name = _DIALECT_NAMES.get(backend, backend)
        raise BackupUnsupported(
            f"In-app backup and restore work with the built-in SQLite database only. This instance "
            f"stores its data in {name} (DATABASE_URL), so an in-app backup would not contain it. "
            f"Back up the {name} database with its own tools (for PostgreSQL: pg_dump), together "
            f"with the evidence and custom_frameworks folders - see docs/INSTALL.md, section 10."
        )
    db = url.database or ""
    if not db or db == ":memory:" or "mode=memory" in db:
        raise BackupUnsupported("This instance runs on an in-memory SQLite database; there is nothing to back up.")
    return Path(db).expanduser().resolve()


def _check_layout() -> None:
    """R2SEC-6: refuse when EVIDENCE_DIR / custom frameworks overlap DATA_DIR or
    BACKUP_DIR (startup refuses it too; settings can also be changed at runtime)."""
    from config import ConfigError, check_dir_layout
    try:
        check_dir_layout(settings)
    except ConfigError as exc:
        raise BackupError(str(exc)) from exc


def unsupported_reason() -> str | None:
    try:
        _db_path()
    except BackupUnsupported as exc:
        return str(exc)
    return None


# --------------------------------------------------------------------------- small fs helpers

def _new_private_file(path: Path) -> None:
    """Create an empty file readable by the owner only (before any content lands)."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def _fsync_file(path: Path) -> None:
    # Read-write, not read-only: on Windows os.fsync is _commit(), which fails
    # with EBADF on a read-only descriptor (every restore failed there).
    fd = os.open(str(path), os.O_RDWR)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(str(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass  # not supported on every platform/filesystem
    finally:
        os.close(fd)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# Key material lives in DATA_DIR and must never travel in an archive (backups
# are often copied off-host; the audit key in particular must be stored
# separately). Skipped when archiving even if EVIDENCE_DIR is misconfigured to
# DATA_DIR itself, and refused on restore so an archive can't plant one.
KEY_MATERIAL_NAMES = frozenset({"secrets.env", "eval-secrets.env", "desktop-secrets.env", "setup-token"})


def _iter_tree(root: Path):
    """(relative posix path, absolute path) for every regular file under root,
    skipping restore work areas. Symlinks are never followed or archived."""
    if not root.is_dir():
        return
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if any(part.startswith(_WORK_PREFIX) for part in rel.parts):
            continue
        if path.name in KEY_MATERIAL_NAMES or path.name in (SERVER_LOCK_NAME, _LOCK_FILE_NAME):
            continue
        if path.is_file() and not path.is_symlink():
            yield rel.as_posix(), path


def _count_evidence_files() -> int:
    return sum(1 for _ in _iter_tree(_evidence_dir()))


def _db_size(db_path: Path) -> int:
    total = 0
    for p in (db_path, db_path.with_name(db_path.name + "-wal")):
        if p.is_file():
            total += p.stat().st_size
    return total


# --------------------------------------------------------------------------- crypto

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_LEN,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _read_full(src: BinaryIO, n: int) -> bytes:
    """Read exactly ``n`` bytes unless the stream ends first."""
    buf = bytearray()
    while len(buf) < n:
        chunk = src.read(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def _v2_header(salt: bytes, nonce_prefix: bytes, chunk_size: int) -> bytes:
    return _ENC_MAGIC_V2 + salt + chunk_size.to_bytes(4, "big") + nonce_prefix


def _chunk_nonce(prefix: bytes, index: int) -> bytes:
    return prefix + index.to_bytes(4, "big")


def _chunk_aad(header: bytes, index: int, final: bool) -> bytes:
    # The header (salt, chunk size, nonce prefix), the chunk's position and the
    # final-chunk flag are all authenticated: chunks can't be reordered,
    # dropped, duplicated or cut off without the tag check failing.
    return header + index.to_bytes(8, "big") + (b"\x01" if final else b"\x00")


def _encrypt_stream(src: BinaryIO, dst: BinaryIO, passphrase: str, chunk_size: int = _ENC_CHUNK) -> int:
    """UNIV2: AES-256-GCM over fixed-size chunks, constant memory, any size
    (AES-GCM refuses a single message of 2 GiB or more). The last chunk is
    always shorter than ``chunk_size`` (possibly empty) and flagged final.
    Returns the number of ciphertext bytes written."""
    salt = secrets.token_bytes(_SALT_LEN)
    prefix = secrets.token_bytes(_NONCE_PREFIX_LEN)
    header = _v2_header(salt, prefix, chunk_size)
    aes = AESGCM(_derive_key(passphrase, salt))
    dst.write(header)
    written = len(header)
    index = 0
    while True:
        plain = _read_full(src, chunk_size)
        final = len(plain) < chunk_size
        sealed = aes.encrypt(_chunk_nonce(prefix, index), plain, _chunk_aad(header, index, final))
        dst.write(sealed)
        written += len(sealed)
        if final:
            return written
        index += 1


def _decrypt_stream(src: BinaryIO, dst: BinaryIO, passphrase: str) -> None:
    """Inverse of _encrypt_stream (``src`` positioned at the UNIV2 magic)."""
    header = _read_full(src, len(_ENC_MAGIC_V2) + _SALT_LEN + 4 + _NONCE_PREFIX_LEN)
    if len(header) < len(_ENC_MAGIC_V2) + _SALT_LEN + 4 + _NONCE_PREFIX_LEN or not header.startswith(_ENC_MAGIC_V2):
        raise BackupError("Encrypted archive is truncated")
    salt = header[len(_ENC_MAGIC_V2):len(_ENC_MAGIC_V2) + _SALT_LEN]
    chunk_size = int.from_bytes(header[len(_ENC_MAGIC_V2) + _SALT_LEN:len(_ENC_MAGIC_V2) + _SALT_LEN + 4], "big")
    prefix = header[-_NONCE_PREFIX_LEN:]
    if not 0 < chunk_size <= _MAX_ENC_CHUNK:
        raise BackupError("Encrypted archive header is damaged")
    aes = AESGCM(_derive_key(passphrase, salt))
    index = 0
    while True:
        sealed = _read_full(src, chunk_size + _TAG_LEN)
        if len(sealed) < _TAG_LEN:
            raise BackupError("Encrypted archive is truncated")
        final = len(sealed) < chunk_size + _TAG_LEN
        try:
            plain = aes.decrypt(_chunk_nonce(prefix, index), sealed, _chunk_aad(header, index, final))
        except Exception as e:
            raise BackupError("Decryption failed — wrong passphrase or corrupted archive") from e
        dst.write(plain)
        if final:
            if src.read(1):
                raise BackupError("Encrypted archive has trailing data — it is damaged or was altered")
            return
        index += 1


def _encrypt(tar_bytes: bytes, passphrase: str) -> memoryview:
    """Encrypt an in-memory archive (UNIV2, chunked; works past 2 GiB).
    Returns a bytes-like view (no extra copy of a multi-GB result)."""
    out = io.BytesIO()
    _encrypt_stream(io.BytesIO(tar_bytes), out, passphrase)
    return out.getbuffer()


def _decrypt_v1(blob: bytes, passphrase: str) -> bytes:
    """UNIV1 (archives written before chunked encryption): one AES-GCM message."""
    header_len = len(_ENC_MAGIC) + _SALT_LEN + _NONCE_LEN
    if len(blob) <= header_len:
        raise BackupError("Encrypted archive is truncated")
    salt = blob[len(_ENC_MAGIC) : len(_ENC_MAGIC) + _SALT_LEN]
    nonce = blob[len(_ENC_MAGIC) + _SALT_LEN : header_len]
    ciphertext = blob[header_len:]
    key = _derive_key(passphrase, salt)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, associated_data=None)
    except Exception as e:
        raise BackupError("Decryption failed — wrong passphrase or corrupted archive") from e


def _decrypt(blob: bytes, passphrase: str) -> bytes:
    if bytes(blob[:len(_ENC_MAGIC_V2)]) == _ENC_MAGIC_V2:
        out = io.BytesIO()
        _decrypt_stream(io.BytesIO(blob), out, passphrase)
        return out.getvalue()
    return _decrypt_v1(bytes(blob), passphrase)


def is_encrypted(blob: bytes) -> bool:
    head = bytes(blob[:len(_ENC_MAGIC)])
    return head in (_ENC_MAGIC, _ENC_MAGIC_V2)


def _decrypt_file(src_path: Path, dst_path: Path, passphrase: str) -> None:
    """Decrypt an archive file into ``dst_path`` (private, fsynced). UNIV2 is
    streamed in constant memory; a UNIV1 file can't exceed 2 GiB (the old
    format's limit), so it is decrypted in memory as before."""
    with open(src_path, "rb") as src:
        magic = src.read(len(_ENC_MAGIC))
        src.seek(0)
        if magic == _ENC_MAGIC_V2:
            fd = os.open(str(dst_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as dst:
                _decrypt_stream(src, dst, passphrase)
                dst.flush()
                os.fsync(dst.fileno())
            return
        data = _decrypt_v1(src.read(), passphrase)
    _write_private(dst_path, data)


# --------------------------------------------------------------------------- nonces

def _issue_restore_nonce() -> str:
    now = time.monotonic()
    expired = [k for k, v in _restore_nonces.items() if now - v > _NONCE_TTL]
    for k in expired:
        del _restore_nonces[k]
    while len(_restore_nonces) >= _MAX_ACTIVE_NONCES:
        oldest_key = min(_restore_nonces, key=_restore_nonces.get)  # type: ignore[arg-type]
        del _restore_nonces[oldest_key]
    nonce = secrets.token_urlsafe(32)
    _restore_nonces[nonce] = now
    return nonce


def consume_restore_nonce(nonce: str) -> bool:
    ts = _restore_nonces.pop(nonce, None)
    if ts is None:
        return False
    return (time.monotonic() - ts) <= _NONCE_TTL


# --------------------------------------------------------------------------- sqlite

def _snapshot_db(src_path: Path, dest: Path) -> None:
    """Consistent copy of a live (possibly WAL-mode) database into ``dest``
    (an existing, empty file). Includes every committed transaction."""
    if not src_path.is_file():
        raise BackupError(f"The database file {src_path.name} does not exist.")
    src = sqlite3.connect(str(src_path), timeout=30)
    try:
        dst = sqlite3.connect(str(dest))
        try:
            src.backup(dst)
            dst.execute("PRAGMA journal_mode=DELETE")  # a self-contained file, no -wal needed
        finally:
            dst.close()
    finally:
        src.close()


def _inspect_db(path: Path) -> dict[str, int]:
    """Prove ``path`` is an intact Athorize database; return per-table row counts."""
    try:
        con = sqlite3.connect(str(path))
    except sqlite3.Error as e:
        raise BackupError(f"data.db cannot be opened: {e}") from e
    try:
        try:
            check = con.execute("PRAGMA integrity_check").fetchall()
        except sqlite3.DatabaseError as e:
            raise BackupError(f"data.db is not a valid SQLite database ({e}).") from e
        if check != [("ok",)]:
            raise BackupError(f"data.db failed the SQLite integrity check: {check[0][0]}")
        tables = [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        missing = [t for t in _REQUIRED_TABLES if t not in tables]
        if missing:
            raise BackupError(
                "data.db is not an Athorize database (missing tables: " + ", ".join(missing) + ")."
            )
        return {t: con.execute(f'SELECT count(*) FROM "{t}"').fetchone()[0] for t in tables}
    finally:
        con.close()


def _install_db(src_path: Path, dst_path: Path) -> None:
    """Replace the live database's content with ``src_path`` in ONE SQLite
    transaction (online-backup API). Other connections stay valid and see the
    new content on their next transaction; a kill mid-copy leaves the old
    database intact (the uncommitted pages are discarded on next open)."""
    src = sqlite3.connect(str(src_path))
    dst = sqlite3.connect(str(dst_path), timeout=60)
    try:
        dst_page = dst.execute("PRAGMA page_size").fetchone()[0]
        dst_mode = dst.execute("PRAGMA journal_mode").fetchone()[0]
        if dst_mode == "wal" and src.execute("PRAGMA page_size").fetchone()[0] != dst_page:
            # SQLite can't change the page size of a WAL database; align the source.
            src.execute("PRAGMA journal_mode=DELETE")
            src.execute(f"PRAGMA page_size={int(dst_page)}")
            src.execute("VACUUM")
        src.backup(dst)
        try:
            dst.execute("PRAGMA wal_checkpoint(PASSIVE)")
        except sqlite3.Error:
            pass
    finally:
        src.close()
        dst.close()


def _holds_demo_data(db_file: Path) -> bool:
    from services.demo_marker import sqlite_file_is_demo
    return sqlite_file_is_demo(db_file)


def _record_demo_backup(name: str) -> None:
    """Remember a backup/rollback copy of DEMO data, so Settings -> Start fresh
    deletes it with the rest of the demo (services/demo_marker)."""
    from services.demo_marker import record_demo_backup
    try:
        record_demo_backup(name)
    except OSError as e:  # never fail a backup over the ledger
        logger.warning("could not record %s as a demo backup: %s", name, e)


def _schema_migrator():
    """main.run_schema_migrations when the app is loaded (never import main
    from here: that would execute the whole app module a second time)."""
    main_mod = sys.modules.get("main")
    return getattr(main_mod, "run_schema_migrations", None)


# --------------------------------------------------------------------------- backup

@dataclass
class BackupResult:
    path: Path
    filename: str
    manifest: dict
    size: int
    warnings: list[str] = field(default_factory=list)


def _pin_evidence(tag: str) -> tuple[Path | None, dict[str, Path]]:
    """Hard-link every evidence file into a private work folder inside the
    evidence tree (same filesystem). A file deleted after this still has its
    content under the pin. Filesystems without hard links fall back to reading
    the live tree (a concurrent delete is then reported, not hidden)."""
    root = _evidence_dir()
    pinned: dict[str, Path] = {}
    if not root.is_dir():
        return None, pinned
    pin_root = root / f"{_PIN_PREFIX}{tag}"
    try:
        pin_root.mkdir(mode=0o700)
    except OSError as e:
        logger.warning("backup: could not create %s (%s); archiving evidence from the live folder", pin_root, e)
        return None, pinned
    for rel, path in _iter_tree(root):
        target = pin_root / rel
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            os.link(path, target)
        except FileNotFoundError:
            continue
        except OSError as e:
            logger.warning("backup: hard links unavailable in %s (%s); archiving evidence from the live folder",
                           root, e)
            break
        pinned[rel] = target
    return pin_root, pinned


def _evidence_rel(file_path: str) -> str:
    """An evidence_artifacts.file_path as an archive-relative posix path."""
    return (file_path or "").replace("\\", "/").lstrip("/")


def _rows_without_files(db_file: Path, archived: set[str]) -> list[str]:
    """evidence_artifacts rows of ``db_file`` whose file is not in ``archived``
    (archive member names)."""
    con = sqlite3.connect(str(db_file))
    try:
        if not con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='evidence_artifacts'").fetchone():
            return []
        rows = con.execute("SELECT file_path FROM evidence_artifacts WHERE file_path IS NOT NULL AND file_path != ''")
        return sorted({_evidence_rel(p) for (p,) in rows} - {n[len(EVIDENCE_PREFIX):] for n in archived
                                                             if n.startswith(EVIDENCE_PREFIX)})
    finally:
        con.close()


def _verify_archive(path: Path, expected_names: set[str], db_sha: str) -> None:
    """Re-read the finished archive before it is published."""
    seen: set[str] = set()
    try:
        with tarfile.open(str(path), mode="r:gz") as tar:
            for member in tar:
                seen.add(member.name)
                if member.name == DB_MEMBER:
                    f = tar.extractfile(member)
                    h = hashlib.sha256()
                    for chunk in iter(lambda: f.read(1024 * 1024), b""):
                        h.update(chunk)
                    if h.hexdigest() != db_sha:
                        raise BackupError("Backup verification failed: the archived database does not match its snapshot.")
    except (tarfile.TarError, OSError, EOFError, zlib.error) as e:
        raise BackupError(f"Backup verification failed: the archive cannot be read back ({e}).") from e
    if seen != expected_names:
        raise BackupError("Backup verification failed: the archive is missing files.")


_LOCK_FILE_NAME = ".athorize-backup.lock"


class _OperationLock:
    """One backup/restore at a time: a thread lock for this process plus an
    advisory file lock in BACKUP_DIR, so the offline CLI and a running server
    can't touch each other's work (POSIX; elsewhere the thread lock only)."""

    def __enter__(self):
        if not _RESTORE_LOCK.acquire(blocking=False):
            raise BackupBusy("Another backup or restore is running. Try again when it has finished.")
        self._fh = None
        try:
            import fcntl
        except ImportError:  # Windows desktop: single process
            return self
        try:
            self._fh = open(_backups_dir() / _LOCK_FILE_NAME, "a")
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            if self._fh:
                self._fh.close()
            _RESTORE_LOCK.release()
            raise BackupBusy("Another backup or restore (possibly the command-line tool) is running. "
                             "Try again when it has finished.")
        return self

    def __exit__(self, *exc):
        if self._fh:
            self._fh.close()  # releases the flock
        _RESTORE_LOCK.release()
        return False


def _operation_lock_held() -> bool:
    """True when a backup/restore holds the operation lock (this process or
    another one, e.g. the CLI)."""
    if _RESTORE_LOCK.locked():
        return True
    try:
        import fcntl
    except ImportError:
        return False
    path = settings.backup_dir / _LOCK_FILE_NAME
    if not path.exists():
        return False
    try:
        with open(path, "a") as fh:
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                return True
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    except OSError:
        return False
    return False


# --------------------------------------------------------------------------- server presence lock
#
# Every server process holds a SHARED lock on DATA_DIR/.athorize-server.lock
# for as long as it runs; the offline restore (python -m services.backup
# restore) needs it EXCLUSIVELY. So the CLI refuses while a server is running
# on the data dir (its writes would be silently discarded — R2DATA-15), and a
# server starting during an offline restore waits for it instead of "recovering"
# the restore half-way.

SERVER_LOCK_NAME = ".athorize-server.lock"
_server_locks: dict[str, object] = {}


def _server_lock_path() -> Path:
    d = _data_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d / SERVER_LOCK_NAME


def _lock_file(fh, *, exclusive: bool, blocking: bool) -> bool:
    try:
        import fcntl
    except ImportError:  # Windows: msvcrt byte-range locks are exclusive and never waited on here
        import msvcrt
        try:
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False
    flags = (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | (0 if blocking else fcntl.LOCK_NB)
    try:
        fcntl.flock(fh.fileno(), flags)
        return True
    except OSError:
        return False


def acquire_server_lock() -> str | None:
    """Mark this process as a server running on DATA_DIR (shared lock, held
    until release_server_lock or process exit). Waits while an offline restore
    runs. Returns a key for release_server_lock, or None if already held."""
    path = _server_lock_path()
    key = str(path.resolve())
    if key in _server_locks:
        return None
    try:
        fh = open(path, "a+")
    except OSError as e:
        logger.warning("could not open the server lock %s (%s); offline restores can't detect this server", path, e)
        return None
    if not _lock_file(fh, exclusive=False, blocking=False):
        logger.warning("An offline restore (python -m services.backup restore) or another process holds %s; "
                       "waiting for it to finish before starting.", path)
        if not _lock_file(fh, exclusive=False, blocking=True):  # Windows: can't share — run without it
            logger.warning("Another Athorize process is using %s; offline restores can't detect this server.",
                           _data_dir())
            fh.close()
            return None
    _server_locks[key] = fh
    return key


def release_server_lock(key: str | None) -> None:
    fh = _server_locks.pop(key, None) if key else None
    if fh is not None:
        fh.close()  # releases the lock


class _OfflineLock:
    """Exclusive server lock for the offline CLI restore: refuses while any
    server process runs on this data dir."""

    def __enter__(self):
        path = _server_lock_path()
        self._fh = open(path, "a+")
        if not _lock_file(self._fh, exclusive=True, blocking=False):
            self._fh.close()
            raise BackupBusy(
                f"An Athorize server is running on this data directory ({_data_dir()}). Stop it first "
                "(e.g. systemctl stop athorize, or close the desktop app), then run the restore again — "
                "changes made through a running server during an offline restore would be lost."
            )
        return self

    def __exit__(self, *exc):
        self._fh.close()
        return False


def create_backup(passphrase: str | None = None) -> BackupResult:
    db_path = _db_path()
    _check_layout()
    with _OperationLock():
        return _create_backup_locked(db_path, passphrase)


def _create_backup_locked(db_path: Path, passphrase: str | None) -> BackupResult:
    bdir = _backups_dir()
    # Our own leftovers from a killed backup. Nothing else can be writing them:
    # we hold the operation lock (thread + file lock). Foreign files are left alone.
    for stale in bdir.glob("universal-backup-*.partial"):
        if _PARTIAL_NAME_RE.match(stale.name) and stale.is_file() and not stale.is_symlink():
            stale.unlink(missing_ok=True)

    stamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
    base = f"universal-backup-{stamp}"
    n = 1
    while any(bdir.glob(f"{base}.tar.gz*")):
        n += 1
        base = f"universal-backup-{stamp}-{n}"
    filename = f"{base}.tar.gz.enc" if passphrase is not None else f"{base}.tar.gz"

    db_partial = bdir / f"{base}.db.partial"
    tar_partial = bdir / f"{base}.tar.gz.partial"
    enc_partial = bdir / f"{base}.tar.gz.enc.partial"
    pin_root: Path | None = None
    try:
        # Pin every evidence file (a hard link) BEFORE the snapshot, so a row in
        # the snapshot always finds its file even if it is deleted meanwhile.
        pin_root, pinned = _pin_evidence(base)
        _new_private_file(db_partial)
        _snapshot_db(db_path, db_partial)
        tables = _inspect_db(db_partial)
        holds_demo = _holds_demo_data(db_partial)
        db_sha = _sha256_file(db_partial)
        db_bytes = db_partial.stat().st_size

        names = {MANIFEST_NAME, DB_MEMBER}
        evidence_files = 0
        evidence_bytes = 0
        custom_fw: set[str] = set()
        _new_private_file(tar_partial)
        with open(tar_partial, "wb") as raw:
            with tarfile.open(fileobj=raw, mode="w:gz") as tar:
                tar.add(str(db_partial), arcname=DB_MEMBER)
                for prefix, root in ((EVIDENCE_PREFIX, _evidence_dir()), (CUSTOM_FW_PREFIX, _custom_frameworks_dir())):
                    sources = dict(_iter_tree(root))
                    if prefix == EVIDENCE_PREFIX:
                        # Files pinned before the snapshot win: one deleted after it
                        # is still archived from its pin (R2DATA-9).
                        sources.update(pinned)
                    for rel in sorted(sources):
                        try:
                            with open(sources[rel], "rb") as f:
                                info = tar.gettarinfo(arcname=prefix + rel, fileobj=f)
                                tar.addfile(info, f)
                        except FileNotFoundError:
                            continue  # gone before it could be archived; reported below if a row needs it
                        names.add(prefix + rel)
                        if prefix == EVIDENCE_PREFIX:
                            evidence_files += 1
                            evidence_bytes += info.size
                        elif rel.endswith("/metadata.json") and rel.count("/") == 1:
                            custom_fw.add(rel.split("/", 1)[0])
                missing = _rows_without_files(db_partial, names)

                from services import audit as audit_svc
                manifest = {
                    "version": BACKUP_VERSION,
                    "format": "athorize-backup",
                    "created_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "db": {"sha256": db_sha, "size_bytes": db_bytes, "tables": tables},
                    "db_size_bytes": db_bytes,
                    "evidence_file_count": evidence_files,
                    "evidence_bytes": evidence_bytes,
                    "custom_framework_count": len(custom_fw),
                    "audit_key_fingerprint": audit_svc.key_fingerprint(),
                    "encrypted": passphrase is not None,
                    "encryption_format": "UNIV2" if passphrase is not None else None,
                    "missing_evidence_files": len(missing),
                    "missing_evidence_sample": missing[:50],
                }
                manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
                info = tarfile.TarInfo(name=MANIFEST_NAME)
                info.size = len(manifest_bytes)
                info.mtime = int(time.time())
                tar.addfile(info, io.BytesIO(manifest_bytes))
            raw.flush()
            os.fsync(raw.fileno())
        db_partial.unlink()

        _verify_archive(tar_partial, names, db_sha)

        if passphrase is not None:
            # Streamed in fixed-size chunks: constant memory, no 2 GiB limit (R2DATA-8).
            _new_private_file(enc_partial)
            with open(tar_partial, "rb") as src, open(enc_partial, "wb") as dst:
                _encrypt_stream(src, dst, passphrase)
                dst.flush()
                os.fsync(dst.fileno())
            tar_partial.unlink()
            ready = enc_partial
        else:
            ready = tar_partial

        _crash_point("backup_before_publish")
        final = bdir / filename
        os.replace(ready, final)
        _fsync_dir(bdir)
        if holds_demo:
            _record_demo_backup(final.name)
        prune_backups(protect=final)
        warnings = []
        if missing:
            warnings.append(
                f"{len(missing)} evidence record(s) in this backup have no file on disk "
                f"({', '.join(missing[:5])}{'…' if len(missing) > 5 else ''}). Their downloads will fail after "
                "a restore; re-upload them, or delete the records."
            )
        return BackupResult(path=final, filename=filename, manifest=manifest, size=final.stat().st_size,
                            warnings=warnings)
    except BaseException as exc:
        if isinstance(exc, Exception):  # a real kill can't clean up either; the next run does
            for p in (db_partial, tar_partial, enc_partial):
                p.unlink(missing_ok=True)
        if isinstance(exc, sqlite3.Error):
            raise BackupError(f"Could not snapshot the database: {exc}") from exc
        if isinstance(exc, (OSError, tarfile.TarError)):
            raise BackupError(f"Backup failed: {exc}") from exc
        raise
    finally:
        if pin_root is not None:
            shutil.rmtree(pin_root, ignore_errors=True)


def create_backup_bytes(passphrase: str | None = None) -> tuple[bytes, str]:
    result = create_backup(passphrase)
    return result.path.read_bytes(), result.filename


def backup_info() -> dict:
    reason = unsupported_reason()
    db_size = _db_size(_db_path()) if reason is None else 0
    bdir = _backups_dir()
    backups = [p for pattern in ("universal-backup-*.tar.gz", "universal-backup-*.tar.gz.enc")
               for p in bdir.glob(pattern) if p.is_file()]
    last = max(backups, key=lambda p: (p.stat().st_mtime, p.name)) if backups else None
    return {
        "version": BACKUP_VERSION,
        "supported": reason is None,
        "unsupported_reason": reason,
        "db_size_bytes": db_size,
        "evidence_file_count": _count_evidence_files(),
        "custom_framework_count": sum(
            1 for p in _custom_frameworks_dir().glob("*/metadata.json")
            if not p.parent.name.startswith(_WORK_PREFIX)
        ) if _custom_frameworks_dir().is_dir() else 0,
        "last_backup_name": last.name if last else None,
        "last_backup_bytes": last.stat().st_size if last else None,
        "last_backup_at": (
            datetime.fromtimestamp(last.stat().st_mtime, UTC).isoformat(timespec="seconds")
            if last
            else None
        ),
        "max_restore_upload_bytes": MAX_RESTORE_UPLOAD_BYTES,
        "keep_backups": _retention(settings.backup_keep),
        "keep_rollbacks": _retention(settings.backup_keep_rollbacks),
        "restore_nonce": _issue_restore_nonce(),
        "download_nonce": _issue_restore_nonce(),
    }


# --------------------------------------------------------------------------- retention

_BACKUP_NAME_RE = re.compile(r"^universal-backup-\d{4}-\d{2}-\d{2}-\d{6}(-\d+)?\.tar\.gz(\.enc)?$")
_PARTIAL_NAME_RE = re.compile(
    r"^universal-backup-\d{4}-\d{2}-\d{2}-\d{6}(-\d+)?\.(db|tar\.gz|tar\.gz\.enc)\.partial$")
_ROLLBACK_NAME_RE = re.compile(r"^rollback-\d{4}-\d{2}-\d{2}-\d{6}(-[0-9a-f]{6})?$")


def _retention(value) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return 0
    return n if n > 0 else 0  # 0 / negative / garbage = keep everything


def _prune(keep: int, pattern: re.Pattern, want_dir: bool, protect: Path | None) -> list[str]:
    """Delete the oldest of OUR items in BACKUP_DIR beyond ``keep``. Only names
    this code writes are considered (never *.partial, never foreign files),
    symlinks are ignored, and ``protect`` (the item just written) always stays."""
    if keep <= 0:
        return []
    bdir = _backups_dir()
    root = bdir.resolve()
    items = []
    for p in bdir.iterdir():
        if not pattern.match(p.name) or p.is_symlink():
            continue
        if (p.is_dir() if want_dir else p.is_file()) and p.resolve().parent == root:
            items.append(p)
    items.sort(key=lambda p: (p.stat().st_mtime, p.name), reverse=True)  # newest first
    keep_set = set()
    if protect is not None and protect in items:
        keep_set.add(protect)
    for p in items:
        if len(keep_set) >= keep:
            break
        keep_set.add(p)
    removed = []
    for p in items:
        if p in keep_set:
            continue
        try:
            if want_dir:
                shutil.rmtree(p)
            else:
                p.unlink()
            removed.append(p.name)
        except OSError as e:  # retention must never fail a backup/restore
            logger.warning("backup retention: could not remove %s: %s", p, e)
    if removed:
        logger.info("backup retention: removed %s", ", ".join(removed))
    return removed


def prune_backups(protect: Path | None = None) -> list[str]:
    return _prune(_retention(settings.backup_keep), _BACKUP_NAME_RE, False, protect)


def prune_rollbacks(protect: Path | None = None) -> list[str]:
    if _journal_path().exists():
        return []  # an unfinished restore may still need its rollback copy
    return _prune(_retention(settings.backup_keep_rollbacks), _ROLLBACK_NAME_RE, True, protect)


# --------------------------------------------------------------------------- restore: archive checks

def _validate_archive(tar: tarfile.TarFile) -> tuple[list[tarfile.TarInfo], dict]:
    """Walk the archive once (lazily, so a gzip bomb is stopped at the cap, not
    after expanding it) and enforce the allow-list. Returns (members, manifest)."""
    members: list[tarfile.TarInfo] = []
    seen: set[str] = set()
    manifest = None
    has_db = False
    total = 0
    try:
        for member in tar:
            name = member.name
            parts = Path(name).parts
            if not name or name.startswith("/") or "\\" in name or ".." in parts:
                raise BackupError(f"Archive contains unsafe path: {name}")
            if any(p.startswith(_WORK_PREFIX) for p in parts):
                raise BackupError(f"Archive contains a reserved name: {name}")
            if name in seen:
                raise BackupError(f"Archive contains a duplicate entry: {name}")
            if parts and parts[-1] in KEY_MATERIAL_NAMES:
                raise BackupError(f"Archive contains key material ({parts[-1]}); refusing to restore it.")
            seen.add(name)
            if not (member.isfile() or member.isdir()):
                raise BackupError(f"Archive contains non-regular entry (symlink/device/etc): {name}")
            if name == MANIFEST_NAME:
                if not member.isfile() or member.size > _MAX_MANIFEST_BYTES:
                    raise BackupError("Archive manifest is unreadable")
                f = tar.extractfile(member)
                try:
                    manifest = json.loads(f.read().decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    raise BackupError(f"Archive manifest is not valid JSON: {e}") from e
            elif name == DB_MEMBER:
                if not member.isfile():
                    raise BackupError("Archive data.db is not a file")
                has_db = True
            elif not (name.startswith(EVIDENCE_PREFIX) or name.startswith(CUSTOM_FW_PREFIX)
                      or name in ("evidence", "custom_frameworks")):
                raise BackupError(f"Archive contains unexpected entry: {name}")
            total += max(member.size, 0)
            if total > _MAX_RESTORE_EXPANDED_BYTES:
                raise BackupError(
                    f"Archive expands to more than {_MAX_RESTORE_EXPANDED_BYTES // (1024 ** 3)} GB — "
                    "too large to restore in-app (or not a genuine Athorize backup)."
                )
            members.append(member)
            if len(members) > _MAX_RESTORE_MEMBERS:
                raise BackupError("Archive contains too many files to restore in-app.")
    except (tarfile.TarError, EOFError, zlib.error, OSError) as e:
        raise BackupError(f"Archive is corrupt or truncated: {e}") from e

    if manifest is None:
        raise BackupError("Archive is missing manifest.json")
    if not isinstance(manifest, dict) or manifest.get("version") not in _SUPPORTED_VERSIONS:
        raise BackupError(
            f"Archive manifest version mismatch (supported: {', '.join(map(str, _SUPPORTED_VERSIONS))})"
        )
    if not has_db:
        raise BackupError("Archive does not contain a database (data.db). Nothing was changed.")
    return members, manifest


def _check_free_space(needs: dict[Path, int]) -> None:
    by_device: dict[int, list] = {}
    for path, size in needs.items():
        probe = path
        while not probe.exists():
            probe = probe.parent
        dev = probe.stat().st_dev
        entry = by_device.setdefault(dev, [probe, 0])
        entry[1] += size
    for probe, size in by_device.values():
        free = shutil.disk_usage(probe).free
        if size + _DISK_HEADROOM_BYTES > free:
            raise BackupError(
                f"Not enough free disk space to restore safely: about {(size + _DISK_HEADROOM_BYTES) // (1024 ** 2)} MB "
                f"needed on the volume holding {probe}, {free // (1024 ** 2)} MB free. Nothing was changed."
            )


def _extract(tar: tarfile.TarFile, members, route) -> int:
    """Write member bytes to vetted paths. ``route(name)`` returns (root, rel)
    or None to skip. Member names never reach tarfile's extractor; every target
    is resolved and containment-checked against its root. Returns bytes written."""
    written = 0
    for member in members:
        dest = route(member.name)
        if dest is None:
            continue
        root, rel = dest
        root_resolved = root.resolve()
        target = (root / rel).resolve()
        if target != root_resolved and root_resolved not in target.parents:
            raise BackupError(f"Archive entry escapes extraction root: {member.name}")
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if not member.isfile():
            raise BackupError(f"Archive contains non-regular entry: {member.name}")
        src = tar.extractfile(member)
        if src is None:
            raise BackupError(f"Archive entry is unreadable: {member.name}")
        target.parent.mkdir(parents=True, exist_ok=True)
        with src, open(target, "wb") as out:
            while chunk := src.read(1024 * 1024):
                written += len(chunk)
                if written > _MAX_RESTORE_EXPANDED_BYTES:
                    raise BackupError("Archive expands beyond the restore size limit.")
                out.write(chunk)
    return written


def _safe_extract(tar: tarfile.TarFile, dest: Path) -> None:
    """Extract every member under ``dest`` with containment checks."""
    _extract(tar, tar.getmembers(), lambda name: (dest, name))


# --------------------------------------------------------------------------- restore: journal + trees

def _journal_path() -> Path:
    return _data_dir() / _JOURNAL_NAME


def _write_journal(state: dict) -> None:
    path = _journal_path()
    tmp = path.with_name(path.name + ".tmp")
    _write_private(tmp, json.dumps(state, indent=2).encode("utf-8"))
    os.replace(tmp, path)
    _fsync_dir(path.parent)


def _children(d: Path) -> list[Path]:
    if not d.is_dir():
        return []
    return [p for p in sorted(d.iterdir()) if not p.name.startswith(_WORK_PREFIX)]


def _move_children(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for child in _children(src):
        os.rename(child, dst / child.name)  # same filesystem by construction: atomic per entry


def _swap_tree(state: dict, tree: dict) -> None:
    """Live children -> work/old, then work/new children -> live. Each phase
    is recorded so recovery knows exactly which side every entry belongs to."""
    live, work = Path(tree["live"]), Path(tree["work"])
    live.mkdir(parents=True, exist_ok=True)
    if tree["state"] == "live":
        _move_children(live, work / "old")
        tree["state"] = "old_moved"
        _write_journal(state)
    _move_children(work / "new", live)
    tree["state"] = "new_in"
    _write_journal(state)


def _unswap_tree(state: dict, tree: dict) -> None:
    live, work = Path(tree["live"]), Path(tree["work"])
    if tree["state"] in ("old_moved", "new_in"):
        # Every non-work entry in live came from the archive: set it aside.
        _move_children(live, work / "discard")
        tree["state"] = "rolling_back"
        _write_journal(state)
    _move_children(work / "old", live)
    tree["state"] = "live"
    _write_journal(state)


def _move_dir_durably(src: Path, dst: Path) -> None:
    """Move a directory to ``dst`` (maybe another filesystem) so a crash at any
    point leaves at least one complete copy."""
    if dst.exists():
        if src.exists():
            shutil.rmtree(dst)
        else:
            return
    if not src.exists():
        return
    try:
        os.rename(src, dst)
        return
    except OSError as e:
        if e.errno != errno.EXDEV:
            raise
    partial = dst.with_name(dst.name + ".partial")
    if partial.exists():
        shutil.rmtree(partial)
    shutil.copytree(src, partial)
    os.rename(partial, dst)
    shutil.rmtree(src)


def _remove_work(state: dict) -> None:
    for tree in state["trees"]:
        shutil.rmtree(tree["work"], ignore_errors=True)
    shutil.rmtree(state["stage_root"], ignore_errors=True)


def _finalize(state: dict) -> list[str]:
    """After commit: keep the replaced evidence/custom frameworks in the
    rollback folder, remove work areas, drop the journal."""
    problems: list[str] = []
    rollback_dir = Path(state["rollback_dir"])
    for tree in state["trees"]:
        old = Path(tree["work"]) / "old"
        if old.exists():
            try:
                if any(old.iterdir()):
                    _move_dir_durably(old, rollback_dir / tree["name"])
            except OSError as e:
                problems.append(f"The replaced {tree['name']} files are still in {old} ({e}).")
                continue
    if problems:
        return problems
    _remove_work(state)
    _journal_path().unlink(missing_ok=True)
    _fsync_dir(_data_dir())
    return problems


def _rollback(state: dict) -> None:
    """Put the pre-restore database and trees back."""
    rollback_db = Path(state["rollback_dir"]) / DB_MEMBER
    if state["phase"] in ("swapping", "rolling_back") and rollback_db.is_file():
        state["phase"] = "rolling_back"
        _write_journal(state)
        _install_db(rollback_db, Path(state["db"]))
    for tree in reversed(state["trees"]):
        if tree.get("swap"):
            _unswap_tree(state, tree)
    if state["phase"] == "staging":
        # The rollback copy was made for this restore only.
        shutil.rmtree(state["rollback_dir"], ignore_errors=True)
    _remove_work(state)
    _journal_path().unlink(missing_ok=True)
    _fsync_dir(_data_dir())


def _sweep_orphan_work() -> None:
    """Work areas with no journal can only be leftovers of a restore that never
    got past staging (or finished cleaning up) — safe to delete. Evidence pins
    are left alone while a backup holds the operation lock (e.g. the CLI)."""
    pins_in_use = _operation_lock_held()
    for parent in {_data_dir(), _evidence_dir(), _custom_frameworks_dir()}:
        if parent.is_dir():
            for p in parent.iterdir():
                if p.name.startswith(_PIN_PREFIX) and pins_in_use:
                    continue
                if p.name.startswith(_WORK_PREFIX) and p.name != _JOURNAL_NAME and p.is_dir():
                    shutil.rmtree(p, ignore_errors=True)


def recover_interrupted_restore() -> str | None:
    """Run at startup, before the database is used. Returns what was done."""
    path = _journal_path()
    if not path.exists():
        _sweep_orphan_work()
        return None
    try:
        state = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        logger.error("restore: unreadable journal %s — leaving it for manual inspection", path)
        return "unreadable"
    if state.get("phase") == "committed":
        problems = _finalize(state)
        for p in problems:
            logger.error("restore: %s", p)
        logger.warning("restore: finished cleaning up a restore that had completed before the restart")
        return "completed"
    phase = state.get("phase")
    _rollback(state)
    rollback_dir = Path(state.get("rollback_dir") or "")
    if phase == "staging":
        logger.error("restore: a restore was interrupted while its archive was being checked; nothing had been "
                     "changed yet, and its work files were removed")
    elif state.get("rollback_dir") and rollback_dir.is_dir():
        logger.error("restore: a restore was interrupted before it completed; the previous data was put back "
                     "(rollback copy kept in %s)", rollback_dir)
    else:
        logger.error("restore: a restore was interrupted before it completed; the previous data was put back")
    _sweep_orphan_work()
    return "rolled_back"


# --------------------------------------------------------------------------- restore: staged database

def _prepare_staged_db(staged: Path, manifest: dict, actor: dict | None, source_name: str | None) -> dict:
    """Validate, migrate and sanitize the staged database. Returns facts for the response."""
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import Session as _Session
    from models import Organization
    from services import audit as audit_svc

    expected_sha = (manifest.get("db") or {}).get("sha256") if isinstance(manifest.get("db"), dict) else None
    if expected_sha and _sha256_file(staged) != expected_sha:
        raise BackupError("data.db does not match the checksum in the manifest — the archive is damaged or was altered.")
    _inspect_db(staged)

    con = sqlite3.connect(str(staged))
    try:
        con.execute("PRAGMA journal_mode=DELETE")
    finally:
        con.close()

    warnings: list[str] = []
    eng = create_engine(f"sqlite:///{staged}")
    try:
        migrate = _schema_migrator()
        if migrate is not None:
            migrate(eng)
        else:
            from database import Base
            import models  # noqa: F401
            Base.metadata.create_all(bind=eng)

        with _Session(eng) as db:
            org_ids = [o.id for o in db.query(Organization).order_by(Organization.id)]
            user_count = db.execute(text("SELECT count(*) FROM users")).scalar_one()

            archive_fp = manifest.get("audit_key_fingerprint")
            if archive_fp:
                key_matches = archive_fp == audit_svc.key_fingerprint()
            else:  # v1 archive: check the chains themselves
                key_matches = all(audit_svc.verify_chain(db, oid)["valid"] for oid in org_ids)
            if not key_matches:
                warnings.append(
                    "This backup's audit log was signed with a different audit key than this instance uses "
                    "(ATHORIZE_AUDIT_HMAC_KEY). The data is restored, but Audit Log → Verify will report the "
                    "history as broken until this instance runs with the key that was in use when the backup "
                    "was taken."
                    if archive_fp else
                    "The restored audit log does not verify with this instance's audit key "
                    "(ATHORIZE_AUDIT_HMAC_KEY) — the backup was probably taken with a different key. Run this "
                    "instance with the original key to verify the history."
                )

            sessions = db.execute(text("DELETE FROM user_sessions")).rowcount
            now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")  # naive-UTC, as UTCDateTime stores it
            tokens = db.execute(
                text("UPDATE api_tokens SET revoked_at = :now WHERE revoked_at IS NULL"), {"now": now}
            ).rowcount if "api_tokens" in _table_names(db) else 0

            who = (actor or {}).get("username") or "system"
            created = manifest.get("created_at") or "unknown date"
            summary = (
                f"Instance restored from backup {source_name or '(archive)'} taken {created}, by {who}. "
                f"{sessions} session(s) signed out, {tokens} API token(s) revoked."
                + ("" if key_matches else " The archive's audit chain was signed with a different audit key.")
            )
            for oid in org_ids:
                audit_svc.record(
                    db, organization_id=oid, actor_id=None, actor_username=who,
                    action="RESTORE", entity_type="system", summary=summary,
                )
            db.commit()
    finally:
        eng.dispose()
    _inspect_db(staged)
    return {
        "sessions_revoked": sessions,
        "api_tokens_revoked": tokens,
        "audit_entries_written": len(org_ids),
        "audit_key_matches": key_matches,
        "user_count": user_count,
        "warnings": warnings,
    }


def _table_names(db) -> set[str]:
    from sqlalchemy import text
    return {r[0] for r in db.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))}


def _reload_frameworks() -> None:
    for modname, attr in (("routers.frameworks", "loader"), ("services.conmon_cadence", "_loader")):
        loader = getattr(sys.modules.get(modname), attr, None)
        if loader is not None:
            try:
                loader.discover()
            except Exception as e:  # never fail a committed restore over a registry refresh
                logger.warning("restore: framework registry refresh failed: %s", e)


def _refresh_restored_catalogs(db_path: Path, warnings: list[str]) -> tuple[list[str], list[str]]:
    """R2INSTALL-5/-6: an archive from an older version carries that version's
    catalogs (and frameworks since retired). Bring them to the installed
    release now, as a restart would. Never fails a committed restore."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session as _Session
    from services.catalog_maintenance import refresh_catalogs

    eng = create_engine(f"sqlite:///{db_path}")
    try:
        with _Session(eng) as db:
            return refresh_catalogs(db)
    except Exception as e:
        logger.exception("restore: catalog refresh failed")
        warnings.append(f"The restored framework catalogs could not be refreshed ({e}); restart the server "
                        "to refresh them.")
        return [], []
    finally:
        eng.dispose()


# --------------------------------------------------------------------------- restore

def restore_from_bytes(
    tar_bytes: bytes,
    passphrase: str | None = None,
    *,
    actor: dict | None = None,
    source_name: str | None = None,
) -> dict:
    db_path = _db_path()
    _check_layout()
    with _OperationLock():
        _restore_active.set()
        try:
            if _journal_path().exists():
                recover_interrupted_restore()
            if is_encrypted(tar_bytes):
                if not passphrase:
                    raise BackupError("Encrypted archive requires a passphrase")
                tar_bytes = _decrypt(tar_bytes, passphrase)
            return _restore_locked(db_path, io.BytesIO(tar_bytes), actor, source_name)
        finally:
            _restore_active.clear()


def restore_from_file(
    archive: Path,
    passphrase: str | None = None,
    *,
    actor: dict | None = None,
    source_name: str | None = None,
) -> dict:
    """Restore from an archive on disk without reading it into memory (the
    offline CLI path for archives of any size). An encrypted archive is
    decrypted, streamed, into a private temporary file in BACKUP_DIR first."""
    db_path = _db_path()
    _check_layout()
    with _OperationLock():
        _restore_active.set()
        plain: Path | None = None
        try:
            if _journal_path().exists():
                recover_interrupted_restore()
            with open(archive, "rb") as f:
                encrypted = is_encrypted(f.read(len(_ENC_MAGIC)))
            if encrypted:
                if not passphrase:
                    raise BackupError("Encrypted archive requires a passphrase")
                _check_free_space({_backups_dir(): archive.stat().st_size})
                plain = _backups_dir() / f"{_WORK_PREFIX}decrypted-{secrets.token_hex(4)}.tar.gz.partial"
                _new_private_file(plain)
                _decrypt_file(archive, plain, passphrase)
            with open(plain or archive, "rb") as fileobj:
                return _restore_locked(db_path, fileobj, actor, source_name)
        finally:
            if plain is not None:
                plain.unlink(missing_ok=True)
            _restore_active.clear()


def _evidence_consistency(staged_db: Path, ev_root: Path, manifest: dict) -> list[str]:
    """Warn when the archive's evidence files and evidence records disagree
    (R2DATA-16). Archives made before the WAL fix (v1) can lack the newest rows:
    their files are there, their records are not."""
    files = {rel for rel, _ in _iter_tree(ev_root)}
    con = sqlite3.connect(str(staged_db))
    try:
        if not con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='evidence_artifacts'").fetchone():
            return []
        rows = {_evidence_rel(p) for (p,) in con.execute(
            "SELECT file_path FROM evidence_artifacts WHERE file_path IS NOT NULL AND file_path != ''")}
    finally:
        con.close()
    warnings = []
    orphans = sorted(files - rows)
    if orphans:
        old = "" if manifest.get("version", 1) >= 2 else (
            " This backup was made by an older version that could miss the most recent changes "
            "(uploads and edits made shortly before it was taken).")
        warnings.append(
            f"{len(orphans)} evidence file(s) in this backup have no evidence record "
            f"(e.g. {', '.join(orphans[:3])}).{old} Those uploads are not listed in the app; check the "
            "Evidence page and re-upload anything that is missing."
        )
    lost = sorted(rows - files)
    if lost:
        warnings.append(
            f"{len(lost)} evidence record(s) in this backup have no file (e.g. {', '.join(lost[:3])}); "
            "their downloads will fail. Re-upload them or delete the records."
        )
    return warnings


def _restore_locked(db_path, archive: BinaryIO, actor, source_name) -> dict:
    try:
        tar = tarfile.open(fileobj=archive, mode="r:gz")
    except (tarfile.TarError, EOFError, zlib.error, OSError) as e:
        raise BackupError(f"Not a valid .tar.gz archive: {e}") from e

    with tar:
        members, manifest = _validate_archive(tar)
        has_cf = any(m.name.startswith(CUSTOM_FW_PREFIX) for m in members)
        swap_cf = has_cf or manifest.get("version", 1) >= 2  # v1 archives never carried them

        evidence = _evidence_dir()
        custom = _custom_frameworks_dir()
        sizes = {DB_MEMBER: 0, EVIDENCE_PREFIX: 0, CUSTOM_FW_PREFIX: 0}
        for m in members:
            for key in sizes:
                if m.isfile() and (m.name == key or m.name.startswith(key)):
                    sizes[key] += m.size
        _check_free_space({
            _data_dir(): sizes[DB_MEMBER],
            evidence: sizes[EVIDENCE_PREFIX],
            custom: sizes[CUSTOM_FW_PREFIX],
            _backups_dir(): _db_size(db_path),
        })

        stamp = datetime.now().strftime("%Y-%m-%d-%H%M%S") + "-" + secrets.token_hex(3)
        rollback_dir = _backups_dir() / f"rollback-{stamp}"
        state = {
            "stamp": stamp,
            "phase": "staging",
            "db": str(db_path),
            "stage_root": str(_data_dir() / f"{_WORK_PREFIX}{stamp}"),
            "rollback_dir": str(rollback_dir),
            "trees": [
                {"name": "evidence", "live": str(evidence), "work": str(evidence / f"{_WORK_PREFIX}{stamp}"),
                 "swap": True, "state": "live"},
                {"name": "custom_frameworks", "live": str(custom), "work": str(custom / f"{_WORK_PREFIX}{stamp}"),
                 "swap": swap_cf, "state": "live"},
            ],
        }
        _data_dir().mkdir(parents=True, exist_ok=True)
        _write_journal(state)

        try:
            stage_root = Path(state["stage_root"])
            stage_root.mkdir(mode=0o700, parents=True)
            ev_new = Path(state["trees"][0]["work"]) / "new"
            cf_new = Path(state["trees"][1]["work"]) / "new"
            ev_new.mkdir(parents=True)
            if swap_cf:
                cf_new.mkdir(parents=True)
            os.chmod(ev_new.parent, 0o700)

            def route(name: str):
                if name == DB_MEMBER:
                    return stage_root, DB_MEMBER
                if name.startswith(EVIDENCE_PREFIX):
                    return ev_new, name[len(EVIDENCE_PREFIX):]
                if name.startswith(CUSTOM_FW_PREFIX) and swap_cf:
                    return cf_new, name[len(CUSTOM_FW_PREFIX):]
                return None  # manifest, bare dir entries

            _extract(tar, members, route)
            staged = stage_root / DB_MEMBER
            facts = _prepare_staged_db(staged, manifest, actor, source_name)
            facts["warnings"].extend(_evidence_consistency(staged, ev_new, manifest))
            restored_files = sum(1 for _ in _iter_tree(ev_new))
            restored_cf = sum(1 for p in cf_new.glob("*/metadata.json")) if swap_cf else 0
            _crash_point("restore_staged")

            # Rollback copy of what we are about to replace.
            rollback_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(rollback_dir, 0o700)
            if db_path.is_file():
                partial = rollback_dir / f"{DB_MEMBER}.partial"
                partial.unlink(missing_ok=True)
                _new_private_file(partial)
                _snapshot_db(db_path, partial)
                _fsync_file(partial)
                os.replace(partial, rollback_dir / DB_MEMBER)
                _fsync_dir(rollback_dir)
                if _holds_demo_data(rollback_dir / DB_MEMBER):
                    _record_demo_backup(rollback_dir.name)
            _crash_point("restore_rollback_saved")
        except BaseException as exc:
            if isinstance(exc, Exception):
                _rollback(state)
                if isinstance(exc, BackupError):
                    raise
                raise BackupError(f"Restore failed; nothing was changed: {exc}") from exc
            raise

        try:
            state["phase"] = "swapping"
            _write_journal(state)
            for tree in state["trees"]:
                if tree["swap"]:
                    _swap_tree(state, tree)
            _crash_point("restore_dirs_swapped")
            _install_db(staged, db_path)
            _crash_point("restore_db_installed")
            state["phase"] = "committed"
            _write_journal(state)
            _crash_point("restore_committed")
        except BaseException as exc:
            if isinstance(exc, Exception):
                try:
                    _rollback(state)
                except Exception as rb_exc:  # leave the journal: startup recovery retries
                    logger.exception("restore: in-process rollback failed")
                    raise BackupError(
                        f"Restore failed ({exc}) and the automatic rollback did not finish ({rb_exc}). "
                        "Restart the server: it completes the rollback on startup."
                    ) from exc
                raise BackupError(f"Restore failed and was rolled back; nothing was changed: {exc}") from exc
            raise

    # Committed. Nothing below may undo it.
    warnings = list(facts["warnings"])
    for problem in _finalize(state):
        warnings.append(problem)
    prune_rollbacks(protect=rollback_dir)
    try:
        engine.dispose()  # fresh connections (and PRAGMAs) for the restored file
    except Exception:
        pass
    _reload_frameworks()
    refreshed, catalog_notices = _refresh_restored_catalogs(db_path, warnings)
    warnings.extend(catalog_notices)
    if facts["user_count"] == 0:
        from services.setup_token import ensure_setup_token
        ensure_setup_token()  # a restored blank instance must not leave Setup open

    return {
        "restored_db": True,
        "restored_evidence_files": restored_files,
        "restored_custom_frameworks": restored_cf,
        "rollback_path": rollback_dir.name,
        "sessions_revoked": facts["sessions_revoked"],
        "api_tokens_revoked": facts["api_tokens_revoked"],
        "audit_entries_written": facts["audit_entries_written"],
        "audit_key_matches": facts["audit_key_matches"],
        "catalogs_refreshed": refreshed,
        "warnings": warnings,
        "manifest": manifest,
    }


# --------------------------------------------------------------------------- CLI

def _cli(argv: list[str]) -> int:
    """Offline backup/restore — for archives above the in-app upload limit.

    From the backend directory, with the same environment variables as the
    server. A backup can run while the server is up; a restore refuses until
    every server process using this data directory is stopped:
        python -m services.backup backup  [--passphrase-env VAR]
        python -m services.backup restore ARCHIVE [--passphrase-env VAR]
    """
    import argparse

    parser = argparse.ArgumentParser(prog="python -m services.backup", description=_cli.__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("backup")
    b.add_argument("--passphrase-env", help="environment variable holding the passphrase")
    r = sub.add_parser("restore")
    r.add_argument("archive", type=Path)
    r.add_argument("--passphrase-env", help="environment variable holding the passphrase")
    args = parser.parse_args(argv)
    passphrase = os.environ.get(args.passphrase_env) if args.passphrase_env else None
    from config import ConfigError
    from services.audit_key_check import reconcile_audit_key
    try:
        reconcile_audit_key(engine)  # sign RESTORE entries with the key the server uses
    except ConfigError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    try:
        if args.cmd == "backup":
            result = create_backup(passphrase)
            print(f"Backup written: {result.path} ({result.size} bytes)")
            for w in result.warnings:
                print(f"WARNING: {w}")
        else:
            with _OfflineLock():  # refuses while a server runs on this data dir (R2DATA-15)
                recover_interrupted_restore()
                out = restore_from_file(args.archive, passphrase,
                                        actor={"username": "cli"}, source_name=args.archive.name)
            print(f"Restored {args.archive.name}: {out['restored_evidence_files']} evidence files, "
                  f"{out['restored_custom_frameworks']} custom frameworks; rollback copy in {out['rollback_path']}.")
            for w in out["warnings"]:
                print(f"WARNING: {w}")
    except BackupError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))

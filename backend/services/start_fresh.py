"""Settings -> "Start fresh": return a DEMO instance to the first-run Setup screen.

Someone who explored the demo data and now wants to use Athorize for real
deletes the demo here instead of reinstalling. It deletes:
  * every database row — all companies (including any added during the demo),
    users, sessions, API tokens and the audit log. Rows are deleted in one
    transaction on the live schema (the schema the startup migrations already
    built), so it is atomic on SQLite and PostgreSQL alike, needs no DDL and
    deletes no files under a running server (Windows file locking);
  * the evidence files and custom frameworks (EVIDENCE_DIR and the custom
    frameworks folder are the app's own folders: backup/restore replace them
    wholesale too);
  * the backups and restore rollback copies made while the instance held demo
    data (recorded when written, services/demo_marker) — never other backups;
  * login throttling state.
It keeps the data folder itself, secrets.env and the session/audit keys: the
audit log they sign is gone, so nothing needs rotating, and other start paths
(desktop, Docker, run-eval) keep sharing one key file (R2SEC-5).

Then a NEW first-run setup token is written to <DATA_DIR>/setup-token and the
log, exactly as at first boot. Builds that auto-seed demo data
(ATHORIZE_DEMO_SEED=1 / DEMO_BUILD) would re-seed an empty database at the
next start anyway, so there Start fresh loads a clean demo instead.

Refused unless the instance is a demo (services/demo_marker) — checked by the
endpoint, so a direct API call on real data is refused too.
"""
from __future__ import annotations

import logging
import shutil
import threading
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.orm import Session

from config import is_demo_mode, settings

CONFIRM_PHRASE = "START FRESH"

_logger = logging.getLogger(__name__)
_active = threading.Event()


def in_progress() -> bool:
    return _active.is_set()


def _wipe_database(db: Session) -> None:
    import models  # noqa: F401  (registers every table on Base.metadata)
    from database import Base

    tables = list(reversed(Base.metadata.sorted_tables))  # children before parents
    bind = db.get_bind()
    if bind.dialect.name == "postgresql":
        quote = bind.dialect.identifier_preparer.quote
        db.execute(text("TRUNCATE " + ", ".join(quote(t.name) for t in tables) + " RESTART IDENTITY CASCADE"))
    else:
        for table in tables:
            db.execute(table.delete())


def _empty_dir(root: Path) -> list[str]:
    problems: list[str] = []
    if not root.is_dir():
        return problems
    for child in root.iterdir():
        try:
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
        except OSError as e:
            problems.append(f"{child}: {e}")
    return problems


def _delete_demo_backups() -> list[str]:
    from services.backup import _BACKUP_NAME_RE, _ROLLBACK_NAME_RE
    from services.demo_marker import clear_demo_backups, demo_backups

    problems: list[str] = []
    bdir = settings.backup_dir
    root = bdir.resolve() if bdir.is_dir() else None
    for name in demo_backups():
        if root is None or not (_BACKUP_NAME_RE.match(name) or _ROLLBACK_NAME_RE.match(name)):
            continue
        p = bdir / name
        if p.is_symlink() or not p.exists() or p.resolve().parent != root:
            continue
        try:
            shutil.rmtree(p) if p.is_dir() else p.unlink()
        except OSError as e:
            problems.append(f"{p}: {e}")
    clear_demo_backups()
    return problems


def start_fresh(db: Session, actor: str) -> str:
    """Wipe the demo. Returns "setup" (back to the first-run Setup screen) or
    "login" (auto-seeding build: a clean demo was loaded). Raises
    services.backup.BackupBusy while a backup or restore runs."""
    from services import backup as backup_svc
    from services import demo_seed, rate_limit
    from services.setup_token import clear_setup_token, generate_setup_token

    with backup_svc._OperationLock():  # no backup/restore (or second Start fresh) meanwhile
        _active.set()  # other API calls get 503 until this finishes (main.restore_gate)
        try:
            _wipe_database(db)
            db.commit()
            db.expunge_all()  # the deleted rows' objects; their ids get reused
            problems = _empty_dir(settings.evidence_dir)
            problems += _empty_dir(settings.custom_frameworks_dir)
            problems += _delete_demo_backups()
            rate_limit.reset()
            backup_svc._reload_frameworks()

            outcome = "setup"
            if is_demo_mode(settings):
                try:
                    demo_seed.seed_demo(db)
                    db.commit()
                    outcome = "login"
                except Exception as exc:  # fall back to the Setup screen
                    db.rollback()
                    demo_seed.discard_demo_files()
                    _logger.warning("start fresh: re-seeding the demo failed (%s); the instance is empty", exc)
            for problem in problems:
                _logger.warning("start fresh: could not delete %s", problem)
            _logger.warning("START FRESH: %s deleted all demo data on this instance (companies, users, "
                            "evidence, custom frameworks, demo backups, sessions, API tokens, audit log).", actor)
            clear_setup_token()
            if outcome == "setup":
                generate_setup_token()  # logged + <DATA_DIR>/setup-token, like first boot
            return outcome
        finally:
            _active.clear()

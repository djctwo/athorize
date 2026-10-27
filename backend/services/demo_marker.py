"""Is this a demo instance? (DOCKER-4)

The demo seed marks every organization it creates with
``settings["demo_data"] = True``. The marker lives in the database rather than
in an env var or a data-dir file so it travels with the data: a demo database
restored elsewhere still shows the banner, and restoring a real backup over a
demo instance removes it."""
from sqlalchemy.orm import Session

from models.organization import Organization

DEMO_KEY = "demo_data"


def mark_demo(org: Organization) -> None:
    org.settings = {**(org.settings or {}), DEMO_KEY: True}


def is_demo_instance(db: Session) -> bool:
    return any((s or {}).get(DEMO_KEY) for (s,) in db.query(Organization.settings).all())


# --------------------------------------------------------------------------- demo backups
# "Start fresh" deletes the backups made while the instance held demo data —
# and only those. Which ones they are is recorded when they are written (a
# ledger in DATA_DIR): encrypted archives cannot be inspected later, and a
# backup of REAL data (made before a demo backup was restored over it, or the
# rollback copy a restore keeps) must never be deleted by mistake.

LEDGER_NAME = "demo-backups.json"


def _ledger_path():
    from config import settings
    return settings.data_dir / LEDGER_NAME


def demo_backups() -> list[str]:
    import json
    try:
        names = json.loads(_ledger_path().read_text()).get("names", [])
    except (OSError, ValueError, AttributeError):
        return []
    return [n for n in names if isinstance(n, str)]


def _write_ledger(names: list[str]) -> None:
    import json
    import os
    path = _ledger_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"names": names}, f)
    os.replace(tmp, path)


def record_demo_backup(name: str) -> None:
    names = demo_backups()
    if name not in names:
        _write_ledger([*names, name])


def clear_demo_backups() -> None:
    try:
        _ledger_path().unlink()
    except OSError:
        pass


def sqlite_file_is_demo(path) -> bool:
    """Does this SQLite file (a backup snapshot) hold demo data? Read-only,
    standard library only; any doubt answers False (= never treated as demo)."""
    import json
    import sqlite3
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            rows = [r[0] for r in con.execute("SELECT settings FROM organizations")]
        finally:
            con.close()
    except sqlite3.Error:
        return False
    for raw in rows:
        try:
            s = json.loads(raw) if isinstance(raw, str) else (raw or {})
        except ValueError:
            continue
        if isinstance(s, dict) and s.get(DEMO_KEY):
            return True
    return False

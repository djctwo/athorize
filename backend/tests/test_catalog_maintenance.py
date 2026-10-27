"""R2INSTALL-5: restoring an archive made by an older version brought back its
old catalogs (old text, the 38-control NERC set, wrong scores) until a restart.
R2INSTALL-6: frameworks that are no longer shipped (CIS v8, SOC 2, HITRUST)
stayed active and counted after an upgrade, with no way to manage them.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from models import AuditEntry, Organization
from models.control import Control
from models.framework_activation import FrameworkActivation
from tests.test_backup_safety import datadir, make_instance_db, system_names  # noqa: F401

REPO = Path(__file__).resolve().parents[2]
NERC_NOW = len(json.loads((REPO / "frameworks" / "nerc-cip" / "catalog.json").read_text())["controls"])


def _age_instance(path: Path) -> None:
    """Make an instance DB look like one from the June 2026 build: NERC CIP with
    an old 38-control catalog and no catalog-state rows, SOC 2 active."""
    eng = create_engine(f"sqlite:///{path}")
    with Session(eng) as db:
        org_id = db.query(Organization.id).scalar()
        for fid in ("nerc-cip", "soc-2"):
            db.add(FrameworkActivation(organization_id=org_id, framework_id=fid, is_active=True))
        for i in range(38):
            db.add(Control(framework_id="nerc-cip", control_id=f"OLD-{i}", title=f"old text {i}"))
        for i in range(5):
            db.add(Control(framework_id="soc-2", control_id=f"CC{i}", title="retired"))
        db.commit()
    eng.dispose()


def _q(path: Path, sql: str):
    con = sqlite3.connect(path)
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def test_restore_of_an_old_archive_refreshes_catalogs_and_retires_removed_frameworks(datadir):
    from services import backup
    live = datadir / "data.db"
    make_instance_db(live, ["OLD"])
    _age_instance(live)
    old_archive, _ = backup.create_backup_bytes(None)
    live.unlink()
    for side in ("-wal", "-shm"):
        (datadir / f"data.db{side}").unlink(missing_ok=True)
    make_instance_db(live, ["CURRENT"])

    out = backup.restore_from_bytes(old_archive)

    assert system_names(live) == ["OLD"]
    assert _q(live, "SELECT count(*) FROM controls WHERE framework_id='nerc-cip'")[0][0] == NERC_NOW
    assert _q(live, "SELECT count(*) FROM controls WHERE control_id LIKE 'OLD-%'")[0][0] == 0
    assert "nerc-cip" in out["catalogs_refreshed"]
    assert _q(live, "SELECT is_active FROM framework_activations WHERE framework_id='soc-2'") == [(0,)]
    assert _q(live, "SELECT count(*) FROM controls WHERE framework_id='soc-2'")[0][0] == 0
    assert any("SOC 2" in w and "no longer included" in w for w in out["warnings"])
    summaries = [r[0] for r in _q(live, "SELECT summary FROM audit_entries WHERE action='DEACTIVATE'")]
    assert any("SOC 2" in s for s in summaries)


def test_startup_retires_removed_frameworks_once(db):
    """main._refresh_stale_catalogs runs at every start (against the app DB)."""
    import main
    org = Organization(name="Acme Industrial Corp", slug="acme")
    db.add(org)
    db.flush()
    db.add(FrameworkActivation(organization_id=org.id, framework_id="cis-controls-v8", is_active=True))
    db.add(FrameworkActivation(organization_id=org.id, framework_id="nist-csf-2.0", is_active=True))
    db.add(Control(framework_id="cis-controls-v8", control_id="1.1", title="Enterprise Asset Inventory"))
    db.commit()

    main._refresh_stale_catalogs()
    db.expire_all()
    acts = {a.framework_id: a.is_active for a in db.query(FrameworkActivation)}
    assert acts == {"cis-controls-v8": False, "nist-csf-2.0": True}
    assert db.query(Control).filter(Control.framework_id == "cis-controls-v8").count() == 0
    assert db.query(Control).filter(Control.framework_id == "nist-csf-2.0").count() > 0
    notes = db.query(AuditEntry).filter(AuditEntry.action == "DEACTIVATE").all()
    assert len(notes) == 1 and "CIS Controls v8" in notes[0].summary

    main._refresh_stale_catalogs()   # idempotent: nothing more to retire
    assert db.query(AuditEntry).filter(AuditEntry.action == "DEACTIVATE").count() == 1


def test_custom_plugin_with_a_retired_id_is_left_alone(db, tmp_path):
    from services.catalog_maintenance import retire_removed_frameworks

    class _Loader:
        def get_metadata(self, fid):
            return object() if fid == "soc-2" else None

    org = Organization(name="Acme Industrial Corp", slug="acme")
    db.add(org)
    db.flush()
    db.add(FrameworkActivation(organization_id=org.id, framework_id="soc-2", is_active=True))
    db.commit()
    assert retire_removed_frameworks(db, _Loader()) == []
    assert db.query(FrameworkActivation).one().is_active is True

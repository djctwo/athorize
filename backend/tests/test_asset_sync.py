"""Scheduled connector asset sync (services/asset_sync.py) — mocked fetchers.

The fetchers are mocked (no real Tanium / Cisco ISE); rows go through the real
normalize → dedup → validate → insert path shared with the manual confirm
endpoint, so these tests cover the whole scheduled data path.
"""
import services.asset_connectors as C
import services.asset_sync as S
from models import Organization
from models.audit import AuditEntry
from models.it_asset import ITAsset
from models.system import System


TANIUM_RESULT = {
    "columns": [{"name": "Computer Name"}, {"name": "Operating System"},
                {"name": "IP Address"}, {"name": "MAC Address"}, {"name": "Chassis Type"}],
    "rows": [
        {"data": [[{"text": "WS-SYNC-01"}], [{"text": "Windows 11 Pro"}],
                  [{"text": "10.9.0.1"}], [{"text": "00:11:22:33:44:55"}], [{"text": "Laptop"}]]},
        {"data": [[{"text": "SRV-SYNC-02"}], [{"text": "Ubuntu 22.04"}],
                  [{"text": "10.9.0.2"}], [{"text": "66:77:88:99:AA:BB"}], [{"text": "Server"}]]},
    ],
}

ISE_ENDPOINTS = [{
    "id": "ep1", "name": "AA:BB:CC:DD:EE:FF", "mac": "AA:BB:CC:DD:EE:FF",
    "customAttributes": {"customAttributes": {
        "Operating System": "Windows 10", "EndPointPolicy": "Workstation",
    }},
}]


def _tanium_rows():
    return C.normalize_tanium_result(TANIUM_RESULT)


def _ise_rows():
    return C.normalize_ise_endpoints(ISE_ENDPOINTS)


ALL_VARS = (
    "TANIUM_URL", "TANIUM_API_TOKEN", "TANIUM_SAVED_QUESTION_ID",
    "CISCO_ISE_URL", "CISCO_ISE_USER", "CISCO_ISE_PASSWORD",
    "ASSET_SYNC_INTERVAL_HOURS", "ASSET_SYNC_ORG_SLUG",
)


def _configure(monkeypatch, tanium=False, ise=False):
    for var in ALL_VARS:
        monkeypatch.delenv(var, raising=False)
    if tanium:
        monkeypatch.setenv("TANIUM_URL", "https://tanium.internal")
        monkeypatch.setenv("TANIUM_API_TOKEN", "tok")
        monkeypatch.setenv("TANIUM_SAVED_QUESTION_ID", "42")
    if ise:
        monkeypatch.setenv("CISCO_ISE_URL", "https://ise.internal")
        monkeypatch.setenv("CISCO_ISE_USER", "ers")
        monkeypatch.setenv("CISCO_ISE_PASSWORD", "pw")


def _mk_system(db, org_id, name="ERP Platform", acronym="ERP"):
    s = System(organization_id=org_id, name=name, acronym=acronym)
    db.add(s)
    db.commit()
    return s


class TestOffByDefault:
    def test_interval_off_by_default(self, monkeypatch):
        _configure(monkeypatch)
        assert S.sync_interval_hours() == 0
        status = S.sync_status()
        assert status["enabled"] is False
        assert status["interval_hours"] is None

    def test_invalid_interval_is_off(self, monkeypatch):
        _configure(monkeypatch)
        monkeypatch.setenv("ASSET_SYNC_INTERVAL_HOURS", "not-a-number")
        assert S.sync_interval_hours() == 0
        monkeypatch.setenv("ASSET_SYNC_INTERVAL_HOURS", "-3")
        assert S.sync_interval_hours() == 0

    def test_interval_enabled(self, monkeypatch):
        _configure(monkeypatch)
        monkeypatch.setenv("ASSET_SYNC_INTERVAL_HOURS", "6")
        status = S.sync_status()
        assert status["enabled"] is True
        assert status["interval_hours"] == 6.0


class TestRun:
    def test_inserts_assets_and_audits(self, db, seeded, monkeypatch):
        _configure(monkeypatch, tanium=True)
        monkeypatch.setitem(C.CONNECTORS, "tanium", _tanium_rows)
        system = _mk_system(db, seeded["org"].id)

        result = S.run_asset_sync(db)

        assert result["ran"] is True
        assert result["organization_id"] == seeded["org"].id
        assert result["system_id"] == system.id
        assert result["connectors"]["tanium"] == {
            "ok": True, "created": 2, "skipped": 0, "error_count": 0,
        }
        assets = db.query(ITAsset).filter(ITAsset.system_id == system.id).all()
        assert {a.asset_name for a in assets} == {"WS-SYNC-01", "SRV-SYNC-02"}
        assert all(a.organization_id == seeded["org"].id for a in assets)

        # Audit: the standard ASSET_IMPORT entry (shared confirm path) plus the
        # per-run ASSET_SYNC entry, both as the scheduler actor.
        imports = db.query(AuditEntry).filter(AuditEntry.action == "ASSET_IMPORT").all()
        assert len(imports) == 1
        assert imports[0].actor_username == "asset-sync-scheduler"
        assert imports[0].actor_id is None
        runs = db.query(AuditEntry).filter(AuditEntry.action == "ASSET_SYNC").all()
        assert len(runs) == 1
        assert runs[0].actor_username == "asset-sync-scheduler"
        assert "tanium: +2 new" in runs[0].summary

    def test_second_run_is_idempotent(self, db, seeded, monkeypatch):
        _configure(monkeypatch, tanium=True)
        monkeypatch.setitem(C.CONNECTORS, "tanium", _tanium_rows)
        system = _mk_system(db, seeded["org"].id)

        first = S.run_asset_sync(db)
        second = S.run_asset_sync(db)

        assert first["connectors"]["tanium"]["created"] == 2
        assert second["connectors"]["tanium"]["created"] == 0
        assert second["connectors"]["tanium"]["skipped"] == 2
        assert db.query(ITAsset).filter(ITAsset.system_id == system.id).count() == 2
        # every run is audit-logged, even a no-op one
        assert db.query(AuditEntry).filter(AuditEntry.action == "ASSET_SYNC").count() == 2

    def test_fault_isolation_one_connector_failing(self, db, seeded, monkeypatch):
        _configure(monkeypatch, tanium=True, ise=True)

        def boom():
            raise C.ConnectorError("Tanium request failed: connection refused")

        monkeypatch.setitem(C.CONNECTORS, "tanium", boom)
        monkeypatch.setitem(C.CONNECTORS, "cisco_ise", _ise_rows)
        system = _mk_system(db, seeded["org"].id)

        result = S.run_asset_sync(db)  # must not raise

        assert result["connectors"]["tanium"]["ok"] is False
        assert "connection refused" in result["connectors"]["tanium"]["error"]
        assert result["connectors"]["cisco_ise"] == {
            "ok": True, "created": 1, "skipped": 0, "error_count": 0,
        }
        names = {a.asset_name for a in db.query(ITAsset).filter(ITAsset.system_id == system.id)}
        assert names == {"AA:BB:CC:DD:EE:FF"}
        run = db.query(AuditEntry).filter(AuditEntry.action == "ASSET_SYNC").one()
        assert "tanium: FAILED" in run.summary
        assert "cisco_ise: +1 new" in run.summary

    def test_org_slug_targets_named_org(self, db, seeded, monkeypatch):
        org2 = Organization(name="Second Org", slug="second-org")
        db.add(org2)
        db.flush()
        _mk_system(db, seeded["org"].id)  # first org has a system too
        sys2 = _mk_system(db, org2.id, name="Plant Network", acronym="PLT")

        _configure(monkeypatch, tanium=True)
        monkeypatch.setenv("ASSET_SYNC_ORG_SLUG", "second-org")
        monkeypatch.setitem(C.CONNECTORS, "tanium", _tanium_rows)

        result = S.run_asset_sync(db)

        assert result["organization_id"] == org2.id
        assert result["system_id"] == sys2.id
        assert db.query(ITAsset).filter(ITAsset.organization_id == org2.id).count() == 2
        assert db.query(ITAsset).filter(ITAsset.organization_id == seeded["org"].id).count() == 0

    def test_blank_slug_falls_back_to_first_org(self, db, seeded, monkeypatch):
        org2 = Organization(name="Second Org", slug="second-org")
        db.add(org2)
        db.flush()
        _mk_system(db, org2.id, name="Plant Network", acronym="PLT")
        system1 = _mk_system(db, seeded["org"].id)

        _configure(monkeypatch, tanium=True)
        monkeypatch.setitem(C.CONNECTORS, "tanium", _tanium_rows)

        result = S.run_asset_sync(db)

        assert result["organization_id"] == seeded["org"].id
        assert result["system_id"] == system1.id

    def test_no_system_skips_quietly(self, db, seeded, monkeypatch):
        _configure(monkeypatch, tanium=True)
        monkeypatch.setitem(C.CONNECTORS, "tanium", _tanium_rows)

        result = S.run_asset_sync(db)  # org exists, but has no systems

        assert result["ran"] is False
        assert db.query(ITAsset).count() == 0

    def test_no_connectors_configured_still_audits_run(self, db, seeded, monkeypatch):
        _configure(monkeypatch)  # nothing configured
        _mk_system(db, seeded["org"].id)

        result = S.run_asset_sync(db)

        assert result["ran"] is True
        assert result["connectors"] == {}
        run = db.query(AuditEntry).filter(AuditEntry.action == "ASSET_SYNC").one()
        assert "no live connectors configured" in run.summary


class TestStatusEndpoint:
    def test_connectors_endpoint_reports_manual_only(self, auth_client, monkeypatch):
        client, seeded, _csrf = auth_client
        _configure(monkeypatch)
        resp = client.get("/api/asset-import/connectors")
        assert resp.status_code == 200
        body = resp.json()
        assert {c["key"] for c in body["connectors"]} == {"tanium", "cisco_ise"}
        assert body["sync"]["enabled"] is False
        assert body["sync"]["interval_hours"] is None
        assert body["sync"]["last_synced"] is None

    def test_connectors_endpoint_reports_auto_sync(self, auth_client, db, monkeypatch):
        client, seeded, _csrf = auth_client
        _configure(monkeypatch, tanium=True)
        monkeypatch.setenv("ASSET_SYNC_INTERVAL_HOURS", "12")
        monkeypatch.setitem(C.CONNECTORS, "tanium", _tanium_rows)
        _mk_system(db, seeded["org"].id)
        S.run_asset_sync(db)

        resp = client.get("/api/asset-import/connectors")
        assert resp.status_code == 200
        body = resp.json()
        assert body["sync"]["enabled"] is True
        assert body["sync"]["interval_hours"] == 12.0
        assert body["sync"]["last_synced"] is not None

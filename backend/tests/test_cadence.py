"""ConMon cadence: resolution order, status computation, overrides."""
from datetime import date, timedelta

from models import ConMonEntry, ConMonCadence, FrameworkActivation, System
from services import conmon_cadence as svc


def _system(db, org):
    s = System(organization_id=org.id, name="S", acronym="S", description="",
               system_type="", environment="production", criticality="moderate")
    db.add(s); db.flush()
    return s.id


def _seed_entry(db, org, activity, days_ago, framework_id="", system_id=None):
    if system_id is None:
        system_id = _system(db, org)
    db.add(ConMonEntry(
        organization_id=org.id, system_id=system_id, framework_id=framework_id,
        entry_date=date.today() - timedelta(days=days_ago),
        activity_type=activity, description="x",
    ))


class TestResolution:
    def test_default_cadence_overdue(self, db, seeded):
        org = seeded["org"]
        # VULNERABILITY_SCAN default = 30d; last done 60d ago → OVERDUE
        _seed_entry(db, org, "VULNERABILITY_SCAN", 60)
        db.commit()
        rows = {(r["framework_id"], r["activity_type"]): r for r in svc.list_cadences(db, org.id)}
        r = rows[("", "VULNERABILITY_SCAN")]
        assert r["status"] == "OVERDUE"
        assert r["days_overdue"] == 30
        assert r["source"] == "default"

    def test_never_done(self, db, seeded):
        org = seeded["org"]
        db.commit()
        rows = {(r["framework_id"], r["activity_type"]): r for r in svc.list_cadences(db, org.id)}
        assert rows[("", "POLICY_REVIEW")]["status"] == "NEVER"

    def test_ok_when_recent(self, db, seeded):
        org = seeded["org"]
        _seed_entry(db, org, "LOG_REVIEW", 5)  # default 30d
        db.commit()
        rows = {(r["framework_id"], r["activity_type"]): r for r in svc.list_cadences(db, org.id)}
        assert rows[("", "LOG_REVIEW")]["status"] == "OK"

    def test_framework_metadata_cadence(self, db, seeded):
        org = seeded["org"]
        db.add(FrameworkActivation(organization_id=org.id, framework_id="pci-dss-v4", is_active=True))
        db.commit()
        rows = {(r["framework_id"], r["activity_type"]): r for r in svc.list_cadences(db, org.id)}
        # PCI metadata sets VULNERABILITY_SCAN = 90d
        assert ("pci-dss-v4", "VULNERABILITY_SCAN") in rows
        assert rows[("pci-dss-v4", "VULNERABILITY_SCAN")]["interval_days"] == 90
        assert rows[("pci-dss-v4", "VULNERABILITY_SCAN")]["source"] == "framework"

    def test_org_override_wins(self, db, seeded):
        org = seeded["org"]
        svc.set_cadence(db, org.id, "", "LOG_REVIEW", 7, True)
        db.commit()
        rows = {(r["framework_id"], r["activity_type"]): r for r in svc.list_cadences(db, org.id)}
        assert rows[("", "LOG_REVIEW")]["interval_days"] == 7
        assert rows[("", "LOG_REVIEW")]["source"] == "override"

    def test_disabled_override_suppresses(self, db, seeded):
        org = seeded["org"]
        svc.set_cadence(db, org.id, "", "USER_TRAINING", 365, False)
        db.commit()
        rows = {(r["framework_id"], r["activity_type"]): r for r in svc.list_cadences(db, org.id)}
        assert ("", "USER_TRAINING") not in rows


class TestApi:
    def test_list_requires_auth(self, client):
        assert client.get("/api/conmon/cadences").status_code == 401

    def test_upsert_and_list(self, auth_client, db):
        client, seeded, csrf = auth_client
        h = {"X-CSRF-Token": csrf} if csrf else {}
        r = client.put("/api/conmon/cadences", json={
            "framework_id": "", "activity_type": "PATCH_REVIEW", "interval_days": 14, "enabled": True,
        }, headers=h)
        assert r.status_code == 200
        rows = client.get("/api/conmon/cadences").json()
        patch = next(x for x in rows if x["activity_type"] == "PATCH_REVIEW" and x["framework_id"] == "")
        assert patch["interval_days"] == 14

    def test_upsert_validates_interval(self, auth_client):
        client, seeded, csrf = auth_client
        h = {"X-CSRF-Token": csrf} if csrf else {}
        r = client.put("/api/conmon/cadences", json={
            "activity_type": "PATCH_REVIEW", "interval_days": 0,
        }, headers=h)
        assert r.status_code == 422

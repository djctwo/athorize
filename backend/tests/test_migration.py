"""POA&M / SSP migration importers — flexible headers, non-clobber, dedup."""
import pytest

from models import Control, ControlImplementation, Finding, System
from tests.conftest import activate_framework


def _h(csrf):
    return {"X-CSRF-Token": csrf} if csrf else {}


def _mk_system(db, org_id):
    s = System(organization_id=org_id, name="Migrated", acronym="MIG")
    db.add(s)
    db.flush()
    return s


POAM_CSV = b"""Weakness,Risk Level,POA&M Status,Scheduled Completion Date,POC,Security Control,Mitigation
Unpatched web server,High,Ongoing,12/15/2026,Jane Doe,SI-2,Apply vendor patches quarterly
Weak admin passwords,Moderate,Open,2026-11-01,Bob Smith,IA-5,Enforce 14-char minimum
Legacy TLS endpoint,Low,Completed,,Jane Doe,SC-8,Disabled TLS 1.0
"""

SSP_CSV = b"""Control ID,Implementation Status,Implementation Narrative,Responsible Role
AC-1,Implemented,Access policy documented and reviewed annually.,CISO
AC-2,Partially Implemented,Account reviews quarterly; service accounts pending.,IT Ops
AC-3,Not Applicable,No shared resources in scope.,CISO
ZZ-99,Implemented,Ghost control.,Nobody
"""


class TestPoamImport:
    @pytest.fixture(autouse=True)
    def _active_fw(self, db, seeded):
        # POA&M import needs an active framework with a loaded catalog (R2DATA-6).
        activate_framework(db, seeded["org"], "test-fw", "SI-2", "IA-5", "SC-8")

    def test_preview_then_commit(self, auth_client, db):
        client, seeded, csrf = auth_client
        s = _mk_system(db, seeded["org"].id)
        db.commit()

        files = {"file": ("poam.csv", POAM_CSV, "text/csv")}
        data = {"system_id": str(s.id), "framework_id": "test-fw", "commit": "false"}
        prev = client.post("/api/migration/poam", data=data, files=files, headers=_h(csrf)).json()
        assert prev["total"] == 3 and prev["new"] == 3
        assert db.query(Finding).count() == 0  # preview writes nothing

        data["commit"] = "true"
        res = client.post("/api/migration/poam", data=data, files=files, headers=_h(csrf)).json()
        assert res["created"] == 3

        rows = {f.title: f for f in db.query(Finding).all()}
        f1 = rows["Unpatched web server"]
        assert f1.severity == "HIGH" and f1.status == "IN_PROGRESS"
        assert f1.control_id == "SI-2" and f1.owner_name == "Jane Doe"
        assert str(f1.due_date) == "2026-12-15"  # 12/15/2026 parsed
        assert f1.milestones and f1.milestones[0]["title"].startswith("Apply vendor")
        assert rows["Legacy TLS endpoint"].status == "CLOSED"

    def test_reimport_skips_duplicates(self, auth_client, db):
        client, seeded, csrf = auth_client
        s = _mk_system(db, seeded["org"].id)
        db.commit()
        files = {"file": ("poam.csv", POAM_CSV, "text/csv")}
        data = {"system_id": str(s.id), "framework_id": "test-fw", "commit": "true"}
        client.post("/api/migration/poam", data=data, files=files, headers=_h(csrf))
        res = client.post("/api/migration/poam", data=data, files=files, headers=_h(csrf)).json()
        assert res["created"] == 0 and res["duplicates"] == 3

    def test_unrecognized_columns_reported(self, auth_client, db):
        client, seeded, csrf = auth_client
        s = _mk_system(db, seeded["org"].id)
        db.commit()
        files = {"file": ("junk.csv", b"colA,colB\n1,2\n", "text/csv")}
        prev = client.post("/api/migration/poam", data={
            "system_id": str(s.id), "framework_id": "test-fw", "commit": "false",
        }, files=files, headers=_h(csrf)).json()
        assert prev["total"] == 0 and any("No title" in i for i in prev["issues"])


class TestSspImport:
    def _catalog(self, db):
        for cid in ("AC-1", "AC-2", "AC-3"):
            db.add(Control(framework_id="ssp-fw", control_id=cid, title=cid))

    def test_import_validates_and_maps(self, auth_client, db):
        client, seeded, csrf = auth_client
        s = _mk_system(db, seeded["org"].id)
        self._catalog(db)
        # AC-2 was already assessed by a human — must survive untouched.
        db.add(ControlImplementation(system_id=s.id, framework_id="ssp-fw",
                                     control_id="AC-2", implementation_status="IMPLEMENTED",
                                     narrative="Human wrote this."))
        db.commit()

        files = {"file": ("ssp.csv", SSP_CSV, "text/csv")}
        data = {"system_id": str(s.id), "framework_id": "ssp-fw", "commit": "true"}
        res = client.post("/api/migration/ssp", data=data, files=files, headers=_h(csrf)).json()
        assert res["written"] == 2            # AC-1 + AC-3
        assert res["already_assessed"] == 1   # AC-2 preserved
        assert res["unknown_controls"] == 1   # ZZ-99 rejected

        impls = {i.control_id: i for i in db.query(ControlImplementation).filter(
            ControlImplementation.system_id == s.id).all()}
        assert impls["AC-1"].implementation_status == "IMPLEMENTED"
        assert impls["AC-3"].implementation_status == "NOT_APPLICABLE"
        assert impls["AC-2"].narrative == "Human wrote this."

    def test_framework_without_catalog_404(self, auth_client, db):
        client, seeded, csrf = auth_client
        s = _mk_system(db, seeded["org"].id)
        db.commit()
        files = {"file": ("ssp.csv", SSP_CSV, "text/csv")}
        r = client.post("/api/migration/ssp", data={
            "system_id": str(s.id), "framework_id": "no-such-fw", "commit": "false",
        }, files=files, headers=_h(csrf))
        assert r.status_code == 404


class TestImportCatalogChecks:
    """R2DATA-6 / R2USER-7: imports refuse a framework that isn't active, and
    report control ids the catalog doesn't have."""

    def test_poam_refuses_a_framework_that_is_not_active(self, auth_client, db):
        client, seeded, csrf = auth_client
        s = _mk_system(db, seeded["org"].id)
        db.commit()
        r = client.post("/api/migration/poam", data={"system_id": str(s.id), "framework_id": "no-such-fw",
                                                      "commit": "true"},
                        files={"file": ("poam.csv", POAM_CSV, "text/csv")}, headers=_h(csrf))
        assert r.status_code == 422 and "not active" in r.json()["detail"]
        assert db.query(Finding).count() == 0

    def test_poam_reports_unknown_control_ids_and_uses_catalog_spelling(self, auth_client, db):
        client, seeded, csrf = auth_client
        activate_framework(db, seeded["org"], "test-fw", "SI-2", "IA-5")
        s = _mk_system(db, seeded["org"].id)
        db.commit()
        csv = b"Weakness,Security Control\nA,si-2\nB,SC-99\n"
        r = client.post("/api/migration/poam", data={"system_id": str(s.id), "framework_id": "test-fw",
                                                      "commit": "true"},
                        files={"file": ("poam.csv", csv, "text/csv")}, headers=_h(csrf)).json()
        assert r["created"] == 2
        assert any("SC-99" in i and "not in the test-fw catalog" in i for i in r["issues"]), r["issues"]
        assert {f.title: f.control_id for f in db.query(Finding).all()} == {"A": "SI-2", "B": "SC-99"}

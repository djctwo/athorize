"""Inspection Prep: readiness scoring, punch list, timeline."""
from datetime import date, timedelta

from models import Control, ControlImplementation, EvidenceArtifact, System
from services import inspection_prep as ip


def _setup(db, org):
    sysrow = System(organization_id=org.id, name="Sys", acronym="SYS",
                    description="", system_type="", environment="production", criticality="moderate")
    db.add(sysrow)
    db.flush()
    # 3 controls in AC family
    for cid, title in [("AC-2", "Account Mgmt"), ("AC-3", "Access Enforce"), ("AC-17", "Remote Access")]:
        db.add(Control(framework_id="cmmc-2.0", control_id=cid, family="AC", family_name="Access Control", title=title))
    db.flush()
    return sysrow.id


class TestReadiness:
    def test_fully_ready_control_scores(self, db, seeded):
        org = seeded["org"]
        sid = _setup(db, org)
        # AC-2: implemented + good narrative + fresh evidence = ready
        db.add(ControlImplementation(system_id=sid, framework_id="cmmc-2.0", control_id="AC-2",
                                     implementation_status="IMPLEMENTED",
                                     narrative="X" * 100, responsible_party="IT Security"))
        db.add(EvidenceArtifact(organization_id=org.id, system_id=sid, filename="e.pdf",
                                control_ids=["AC-2"], framework_ids=["cmmc-2.0"],
                                # still fresh ON the inspection date (R2DATA-7: freshness is judged then)
                                expiration_date=date.today() + timedelta(days=120)))
        db.commit()
        pkg = ip.build_prep(db, org.id, "cmmc-2.0", [sid], date.today() + timedelta(days=90))
        ac2_punch = [p for p in pkg["punch_list"] if p["control_id"] == "AC-2"]
        assert ac2_punch == []  # ready → not on punch list

    def test_punch_list_priorities(self, db, seeded):
        org = seeded["org"]
        sid = _setup(db, org)
        # AC-2 not assessed (pri 1), AC-3 implemented no evidence (pri 2)
        db.add(ControlImplementation(system_id=sid, framework_id="cmmc-2.0", control_id="AC-3",
                                     implementation_status="IMPLEMENTED", narrative="Y" * 100))
        db.commit()
        pkg = ip.build_prep(db, org.id, "cmmc-2.0", [sid], None)
        by_ctrl = {p["control_id"]: p for p in pkg["punch_list"]}
        assert by_ctrl["AC-2"]["priority"] == 1  # NOT_ASSESSED
        assert by_ctrl["AC-3"]["priority"] == 2  # implemented, no evidence
        assert "no evidence linked" in by_ctrl["AC-3"]["issues"]

    def test_stale_evidence_flagged(self, db, seeded):
        org = seeded["org"]
        sid = _setup(db, org)
        db.add(ControlImplementation(system_id=sid, framework_id="cmmc-2.0", control_id="AC-2",
                                     implementation_status="IMPLEMENTED", narrative="Z" * 100))
        db.add(EvidenceArtifact(organization_id=org.id, system_id=sid, filename="old.pdf",
                                control_ids=["AC-2"], framework_ids=["cmmc-2.0"],
                                expiration_date=date.today() - timedelta(days=1)))
        db.commit()
        pkg = ip.build_prep(db, org.id, "cmmc-2.0", [sid], None)
        ac2 = next(p for p in pkg["punch_list"] if p["control_id"] == "AC-2")
        assert ac2["priority"] == 3
        assert "evidence is expired" in ac2["issues"]

    def test_family_breakdown_and_timeline(self, db, seeded):
        org = seeded["org"]
        sid = _setup(db, org)
        db.commit()
        pkg = ip.build_prep(db, org.id, "cmmc-2.0", [sid], date.today() + timedelta(days=45))
        assert pkg["control_count"] == 3
        assert any(f["family"] == "AC" for f in pkg["families"])
        assert pkg["readiness_score"] == 0.0  # nothing implemented
        assert len(pkg["timeline"]) == 4


class TestApi:
    def test_prep_requires_system(self, auth_client):
        client, seeded, _ = auth_client
        r = client.get("/api/inspection/prep?framework_id=cmmc-2.0")
        assert r.status_code == 422

    def test_prep_and_csv(self, auth_client, db):
        client, seeded, _ = auth_client
        sid = _setup(db, seeded["org"])
        db.commit()
        r = client.get(f"/api/inspection/prep?framework_id=cmmc-2.0&system_ids={sid}")
        assert r.status_code == 200
        assert r.json()["control_count"] == 3
        csv_r = client.get(f"/api/inspection/prep/punch-list.csv?framework_id=cmmc-2.0&system_ids={sid}")
        assert csv_r.status_code == 200
        assert "Priority,System,Control" in csv_r.text

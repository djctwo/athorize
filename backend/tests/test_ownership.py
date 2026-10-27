"""Control/evidence ownership, /dashboard/my-work, and assignee reminders."""
from datetime import date, timedelta

from models import Control, ControlImplementation, EvidenceArtifact, Finding, System, User
from services.auth import hash_password
from services import assignee_reminders


def _h(csrf):
    return {"X-CSRF-Token": csrf} if csrf else {}


def _mk_system(db, org_id, name="OwnSys"):
    s = System(organization_id=org_id, name=name, acronym=name[:4].upper())
    db.add(s)
    db.flush()
    return s


class TestControlOwnership:
    def test_upsert_with_owner(self, auth_client, db):
        client, seeded, csrf = auth_client
        s = _mk_system(db, seeded["org"].id)
        db.commit()
        r = client.put(f"/api/controls/systems/{s.id}/test-fw/AC-1", json={
            "implementation_status": "PLANNED", "owner_id": seeded["admin"].id,
        }, headers=_h(csrf))
        assert r.status_code == 200
        assert r.json()["owner_id"] == seeded["admin"].id

    def test_owner_outside_org_rejected(self, auth_client, db):
        client, seeded, csrf = auth_client
        s = _mk_system(db, seeded["org"].id)
        from models import Organization
        other = Organization(name="OtherOwn", slug="other-own")
        db.add(other)
        db.flush()
        outsider = User(organization_id=other.id, username="outsider",
                        password_hash=hash_password("x" * 12), role="admin")
        db.add(outsider)
        db.commit()
        r = client.put(f"/api/controls/systems/{s.id}/test-fw/AC-1", json={
            "implementation_status": "PLANNED", "owner_id": outsider.id,
        }, headers=_h(csrf))
        assert r.status_code == 422

    def test_bulk_assign_owner(self, auth_client, db):
        client, seeded, csrf = auth_client
        s = _mk_system(db, seeded["org"].id)
        db.commit()
        r = client.post(f"/api/controls/systems/{s.id}/bulk", json={
            "framework_id": "test-fw", "control_ids": ["AC-1", "AC-2"],
            "assign_owner": True, "owner_id": seeded["admin"].id,
        }, headers=_h(csrf))
        assert r.status_code == 200 and r.json()["updated"] == 2
        rows = db.query(ControlImplementation).filter(
            ControlImplementation.system_id == s.id).all()
        assert all(row.owner_id == seeded["admin"].id for row in rows)

    def test_bulk_requires_a_change(self, auth_client, db):
        client, seeded, csrf = auth_client
        s = _mk_system(db, seeded["org"].id)
        db.commit()
        r = client.post(f"/api/controls/systems/{s.id}/bulk", json={
            "framework_id": "test-fw", "control_ids": ["AC-1"],
        }, headers=_h(csrf))
        assert r.status_code == 422


class TestMyWork:
    def test_my_work_aggregates_three_types(self, auth_client, db):
        client, seeded, csrf = auth_client
        me = seeded["admin"]
        s = _mk_system(db, seeded["org"].id)
        db.add(Finding(organization_id=seeded["org"].id, system_id=s.id,
                       framework_id="test-fw", control_id="AC-1", title="Mine",
                       severity="HIGH", status="OPEN", owner_id=me.id,
                       due_date=date.today() - timedelta(days=1)))
        db.add(ControlImplementation(system_id=s.id, framework_id="test-fw",
                                     control_id="AC-2", implementation_status="PLANNED",
                                     owner_id=me.id))
        db.add(EvidenceArtifact(organization_id=seeded["org"].id, system_id=s.id,
                                filename="stale.pdf", owner_id=me.id,
                                expiration_date=date.today() - timedelta(days=2)))
        # noise: unassigned + implemented items must not appear
        db.add(ControlImplementation(system_id=s.id, framework_id="test-fw",
                                     control_id="AC-3", implementation_status="IMPLEMENTED",
                                     owner_id=me.id))
        db.commit()

        w = client.get("/api/dashboard/my-work").json()
        assert len(w["findings"]) == 1 and w["findings"][0]["overdue"] is True
        assert len(w["controls"]) == 1 and w["controls"][0]["control_id"] == "AC-2"
        assert len(w["evidence"]) == 1 and w["evidence"][0]["expired"] is True


class TestAssigneeReminders:
    def test_build_reminders_groups_by_user(self, db, seeded):
        me = seeded["admin"]
        s = _mk_system(db, seeded["org"].id)
        db.add(Finding(organization_id=seeded["org"].id, system_id=s.id,
                       framework_id="test-fw", control_id="AC-1", title="Due soon",
                       severity="HIGH", status="OPEN", owner_id=me.id,
                       due_date=date.today() + timedelta(days=3)))
        db.add(EvidenceArtifact(organization_id=seeded["org"].id, system_id=s.id,
                                filename="expiring.pdf", owner_id=me.id,
                                expiration_date=date.today() + timedelta(days=5)))
        # outside the horizons — must NOT trigger
        db.add(Finding(organization_id=seeded["org"].id, system_id=s.id,
                       framework_id="test-fw", control_id="AC-9", title="Far away",
                       severity="LOW", status="OPEN", owner_id=me.id,
                       due_date=date.today() + timedelta(days=60)))
        db.commit()

        work = assignee_reminders.build_reminders(db, seeded["org"].id)
        assert set(work.keys()) == {me.id}
        assert len(work[me.id]["findings"]) == 1
        assert len(work[me.id]["evidence"]) == 1
        subject, html, text = assignee_reminders.render(work[me.id])
        assert "2 item(s)" in subject
        assert "Due soon" in text and "expiring.pdf" in text

    def test_closed_findings_never_remind(self, db, seeded):
        me = seeded["admin"]
        s = _mk_system(db, seeded["org"].id)
        db.add(Finding(organization_id=seeded["org"].id, system_id=s.id,
                       framework_id="test-fw", control_id="AC-1", title="Done",
                       severity="HIGH", status="CLOSED", owner_id=me.id,
                       due_date=date.today() - timedelta(days=5)))
        db.commit()
        assert assignee_reminders.build_reminders(db, seeded["org"].id) == {}


class TestAssignableUsers:
    def test_any_role_gets_directory(self, client, db, seeded):
        # a non-admin (auditor) can still populate an owner picker
        aud = User(organization_id=seeded["org"].id, username="aud1",
                   password_hash=hash_password("auditorpass123!"), role="auditor")
        db.add(aud)
        db.commit()
        r = client.post("/api/auth/login", json={"username": "aud1", "password": "auditorpass123!"})
        assert r.status_code == 200
        rows = client.get("/api/users/assignable").json()
        assert {u["username"] for u in rows} >= {"testadmin", "aud1"}
        assert set(rows[0].keys()) == {"id", "display_name", "username"}  # minimal fields only

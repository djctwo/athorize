"""POST /api/controls/bulk — cross-system bulk implementation edit.

Mirrors the findings bulk pattern: org-scope + system-scope validated per
target, invalid targets are skipped and reported (not failed), one
summarizing audit entry per batch.
"""
from models import AuditEntry, ControlImplementation, Organization, System, SystemAssignment, User
from services.auth import hash_password


def _h(csrf):
    return {"X-CSRF-Token": csrf} if csrf else {}


def _mk_system(db, org_id, name="BulkSys"):
    s = System(organization_id=org_id, name=name, acronym=name[:4].upper())
    db.add(s)
    db.flush()
    return s


def _target(system_id, control_id, framework_id="test-fw"):
    return {"system_id": system_id, "framework_id": framework_id, "control_id": control_id}


class TestBulkControls:
    def test_bulk_status_change_creates_and_updates(self, auth_client, db):
        client, seeded, csrf = auth_client
        s = _mk_system(db, seeded["org"].id)
        db.add(ControlImplementation(system_id=s.id, framework_id="test-fw",
                                     control_id="AC-1", implementation_status="NOT_ASSESSED",
                                     narrative="keep me"))
        db.commit()
        r = client.post("/api/controls/bulk", json={
            "targets": [_target(s.id, "AC-1"), _target(s.id, "AC-2")],
            "implementation_status": "IMPLEMENTED",
        }, headers=_h(csrf))
        assert r.status_code == 200
        body = r.json()
        assert body["updated"] == 2 and body["skipped"] == []
        rows = db.query(ControlImplementation).filter(ControlImplementation.system_id == s.id).all()
        assert {row.control_id for row in rows} == {"AC-1", "AC-2"}
        assert all(row.implementation_status == "IMPLEMENTED" for row in rows)
        # bulk status edits never clobber assessed prose
        assert next(row for row in rows if row.control_id == "AC-1").narrative == "keep me"

    def test_bulk_assign_owner(self, auth_client, db):
        client, seeded, csrf = auth_client
        s = _mk_system(db, seeded["org"].id)
        db.commit()
        r = client.post("/api/controls/bulk", json={
            "targets": [_target(s.id, "AC-1"), _target(s.id, "AC-2")],
            "owner_id": seeded["admin"].id,
        }, headers=_h(csrf))
        assert r.status_code == 200 and r.json()["updated"] == 2
        rows = db.query(ControlImplementation).filter(ControlImplementation.system_id == s.id).all()
        assert len(rows) == 2
        assert all(row.owner_id == seeded["admin"].id for row in rows)

    def test_owner_outside_org_rejected(self, auth_client, db):
        client, seeded, csrf = auth_client
        s = _mk_system(db, seeded["org"].id)
        other = Organization(name="OtherOwnerBulk", slug="other-owner-bulk")
        db.add(other)
        db.flush()
        outsider = User(organization_id=other.id, username="bulkoutsider",
                        password_hash=hash_password("x" * 12), role="admin")
        db.add(outsider)
        db.commit()
        r = client.post("/api/controls/bulk", json={
            "targets": [_target(s.id, "AC-1")], "owner_id": outsider.id,
        }, headers=_h(csrf))
        assert r.status_code == 422

    def test_org_isolation_foreign_targets_skipped(self, auth_client, db):
        client, seeded, csrf = auth_client
        mine = _mk_system(db, seeded["org"].id, "Mine")
        other = Organization(name="OtherBulk", slug="other-bulk")
        db.add(other)
        db.flush()
        theirs = _mk_system(db, other.id, "Theirs")
        db.commit()
        r = client.post("/api/controls/bulk", json={
            "targets": [_target(mine.id, "AC-1"), _target(theirs.id, "AC-1")],
            "implementation_status": "PARTIALLY",
        }, headers=_h(csrf))
        assert r.status_code == 200
        body = r.json()
        assert body["updated"] == 1
        assert len(body["skipped"]) == 1
        assert body["skipped"][0]["system_id"] == theirs.id
        assert body["skipped"][0]["reason"] == "system not found"
        # nothing was written into the foreign org
        assert db.query(ControlImplementation).filter(
            ControlImplementation.system_id == theirs.id).count() == 0

    def test_system_scoped_user_restricted(self, client, db, seeded):
        # assessor has assess:control but is assigned only to system Alpha
        org = seeded["org"]
        sys_a = _mk_system(db, org.id, "Alpha")
        sys_b = _mk_system(db, org.id, "Bravo")
        assessor = User(organization_id=org.id, username="bulkscoped",
                        password_hash=hash_password("bulkscoped123!"), role="assessor")
        db.add(assessor)
        db.flush()
        db.add(SystemAssignment(user_id=assessor.id, system_id=sys_a.id))
        db.commit()
        r = client.post("/api/auth/login",
                        json={"username": "bulkscoped", "password": "bulkscoped123!"})
        assert r.status_code == 200
        csrf = client.cookies.get("universal_csrf")
        r = client.post("/api/controls/bulk", json={
            "targets": [_target(sys_a.id, "AC-1"), _target(sys_b.id, "AC-1")],
            "implementation_status": "PLANNED",
        }, headers=_h(csrf))
        assert r.status_code == 200
        body = r.json()
        assert body["updated"] == 1
        assert [skip["system_id"] for skip in body["skipped"]] == [sys_b.id]
        assert db.query(ControlImplementation).filter(
            ControlImplementation.system_id == sys_a.id).count() == 1
        assert db.query(ControlImplementation).filter(
            ControlImplementation.system_id == sys_b.id).count() == 0

    def test_nonexistent_system_skipped_not_failed(self, auth_client, db):
        client, seeded, csrf = auth_client
        s = _mk_system(db, seeded["org"].id)
        db.commit()
        r = client.post("/api/controls/bulk", json={
            "targets": [_target(s.id, "AC-1"), _target(999999, "AC-1")],
            "implementation_status": "IMPLEMENTED",
        }, headers=_h(csrf))
        assert r.status_code == 200
        body = r.json()
        assert body["updated"] == 1
        assert body["skipped"][0]["system_id"] == 999999

    def test_duplicate_targets_collapse(self, auth_client, db):
        client, seeded, csrf = auth_client
        s = _mk_system(db, seeded["org"].id)
        db.commit()
        r = client.post("/api/controls/bulk", json={
            "targets": [_target(s.id, "AC-1"), _target(s.id, "AC-1")],
            "implementation_status": "IMPLEMENTED",
        }, headers=_h(csrf))
        assert r.json()["updated"] == 1
        assert db.query(ControlImplementation).filter(
            ControlImplementation.system_id == s.id).count() == 1

    def test_validation_errors(self, auth_client, db):
        client, seeded, csrf = auth_client
        s = _mk_system(db, seeded["org"].id)
        db.commit()
        # empty selection
        r = client.post("/api/controls/bulk", json={
            "targets": [], "implementation_status": "IMPLEMENTED"}, headers=_h(csrf))
        assert r.status_code == 422
        # nothing to change
        r = client.post("/api/controls/bulk", json={
            "targets": [_target(s.id, "AC-1")]}, headers=_h(csrf))
        assert r.status_code == 422
        # bogus status
        r = client.post("/api/controls/bulk", json={
            "targets": [_target(s.id, "AC-1")], "implementation_status": "DONEISH"},
            headers=_h(csrf))
        assert r.status_code == 422

    def test_single_summarizing_audit_entry(self, auth_client, db):
        client, seeded, csrf = auth_client
        s = _mk_system(db, seeded["org"].id)
        db.commit()
        client.post("/api/controls/bulk", json={
            "targets": [_target(s.id, "AC-1"), _target(s.id, "AC-2"), _target(s.id, "AC-3")],
            "implementation_status": "IMPLEMENTED", "owner_id": seeded["admin"].id,
        }, headers=_h(csrf))
        entries = db.query(AuditEntry).filter(
            AuditEntry.action == "BULK_UPDATE",
            AuditEntry.entity_type == "control_implementation",
        ).all()
        assert len(entries) == 1
        assert "3 control implementation(s)" in entries[0].summary
        assert "status → IMPLEMENTED" in entries[0].summary
        assert "owner assigned" in entries[0].summary
        assert entries[0].system_id == s.id  # single-system batch keeps the link

"""Bulk finding update: status change + owner assignment, skip invalid transitions."""


def _h(csrf):
    return {"X-CSRF-Token": csrf} if csrf else {}


def _seed_findings(db, org_id, statuses):
    from models.system import System
    from models.finding import Finding
    sysm = System(organization_id=org_id, name="Sys", acronym="SYS")
    db.add(sysm); db.flush()
    ids = []
    for i, st in enumerate(statuses):
        f = Finding(organization_id=org_id, system_id=sysm.id, framework_id="nist-800-53-r5",
                    title=f"F{i}", severity="HIGH", status=st)
        db.add(f); db.flush(); ids.append(f.id)
    db.commit()
    return ids


class TestBulkFindings:
    def test_bulk_mark_in_progress(self, auth_client, db, seeded):
        client, _s, csrf = auth_client
        ids = _seed_findings(db, seeded["org"].id, ["OPEN", "OPEN"])
        r = client.post("/api/findings/bulk", json={"ids": ids, "status": "IN_PROGRESS"}, headers=_h(csrf))
        assert r.status_code == 200
        assert r.json()["updated"] == 2

    def test_bulk_close_autofills_completion(self, auth_client, db, seeded):
        client, _s, csrf = auth_client
        ids = _seed_findings(db, seeded["org"].id, ["OPEN"])
        r = client.post("/api/findings/bulk", json={"ids": ids, "status": "CLOSED"}, headers=_h(csrf))
        assert r.json()["updated"] == 1  # actual_completion auto-filled so the transition succeeds

    def test_invalid_transition_skipped_not_failed(self, auth_client, db, seeded):
        client, _s, csrf = auth_client
        # CLOSED is terminal → cannot go to IN_PROGRESS; the batch reports it skipped
        ids = _seed_findings(db, seeded["org"].id, ["OPEN", "CLOSED"])
        r = client.post("/api/findings/bulk", json={"ids": ids, "status": "IN_PROGRESS"}, headers=_h(csrf))
        body = r.json()
        assert body["updated"] == 1 and len(body["skipped"]) == 1

    def test_bulk_assign_owner(self, auth_client, db, seeded):
        client, _s, csrf = auth_client
        ids = _seed_findings(db, seeded["org"].id, ["OPEN"])
        admin_id = seeded["admin"].id
        r = client.post("/api/findings/bulk", json={"ids": ids, "owner_id": admin_id, "owner_name": "Admin"}, headers=_h(csrf))
        assert r.json()["updated"] == 1
        got = client.get(f"/api/findings?owner_id={admin_id}").json()
        assert any(f["id"] in ids for f in got)

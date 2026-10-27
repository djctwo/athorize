"""Control implementation editing: single upsert + bulk status set + validation."""


def _h(csrf):
    return {"X-CSRF-Token": csrf} if csrf else {}


def _system(db, org_id):
    from models.system import System
    s = System(organization_id=org_id, name="Sys", acronym="SYS")
    db.add(s); db.commit(); db.refresh(s)
    return s.id


class TestImplementationEditing:
    def test_single_upsert_creates_then_updates(self, auth_client, db, seeded):
        client, _s, csrf = auth_client
        sid = _system(db, seeded["org"].id)
        url = f"/api/controls/systems/{sid}/nist-800-53-r5/AC-1"
        r = client.put(url, json={"implementation_status": "IMPLEMENTED", "narrative": "done"}, headers=_h(csrf))
        assert r.status_code == 200 and r.json()["implementation_status"] == "IMPLEMENTED"
        # update preserves the row, changes status
        r = client.put(url, json={"implementation_status": "PARTIALLY"}, headers=_h(csrf))
        assert r.json()["implementation_status"] == "PARTIALLY"

    def test_invalid_status_rejected(self, auth_client, db, seeded):
        client, _s, csrf = auth_client
        sid = _system(db, seeded["org"].id)
        r = client.put(f"/api/controls/systems/{sid}/nist-800-53-r5/AC-2",
                       json={"implementation_status": "BOGUS"}, headers=_h(csrf))
        assert r.status_code == 422

    def test_bulk_set_status(self, auth_client, db, seeded):
        client, _s, csrf = auth_client
        sid = _system(db, seeded["org"].id)
        r = client.post(f"/api/controls/systems/{sid}/bulk", json={
            "framework_id": "nist-800-53-r5",
            "control_ids": ["AC-1", "AC-2", "AC-3"],
            "implementation_status": "NOT_APPLICABLE",
        }, headers=_h(csrf))
        assert r.status_code == 200 and r.json()["updated"] == 3
        impls = client.get(f"/api/controls/systems/{sid}?framework_id=nist-800-53-r5").json()
        assert {i["control_id"] for i in impls} >= {"AC-1", "AC-2", "AC-3"}
        assert all(i["implementation_status"] == "NOT_APPLICABLE" for i in impls)

    def test_bulk_invalid_status_rejected(self, auth_client, db, seeded):
        client, _s, csrf = auth_client
        sid = _system(db, seeded["org"].id)
        r = client.post(f"/api/controls/systems/{sid}/bulk",
                        json={"framework_id": "x", "control_ids": ["AC-1"], "implementation_status": "NOPE"},
                        headers=_h(csrf))
        assert r.status_code == 422

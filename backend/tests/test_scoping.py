"""Scoping wizard — baseline tailoring without clobbering assessed work."""
from models import Control, ControlImplementation, System


def _h(csrf):
    return {"X-CSRF-Token": csrf} if csrf else {}


def _setup(db, org_id):
    system = System(organization_id=org_id, name="Scoped", acronym="SCP")
    db.add(system)
    db.flush()
    db.add(Control(framework_id="scope-fw", control_id="S-1", title="In L1", baselines=["L1", "L2"]))
    db.add(Control(framework_id="scope-fw", control_id="S-2", title="L2 only", baselines=["L2"]))
    db.add(Control(framework_id="scope-fw", control_id="S-3", title="Also L2 only", baselines=["L2"]))
    # S-3 was already assessed by a human — scoping must NOT touch it.
    db.add(ControlImplementation(system_id=system.id, framework_id="scope-fw",
                                 control_id="S-3", implementation_status="IMPLEMENTED",
                                 narrative="Already done."))
    db.commit()
    return system


def test_baselines_listing(auth_client, db):
    client, seeded, _ = auth_client
    _setup(db, seeded["org"].id)
    assert client.get("/api/controls/baselines?framework_id=scope-fw").json() == ["L1", "L2"]


def test_scope_marks_na_without_clobbering(auth_client, db):
    client, seeded, csrf = auth_client
    system = _setup(db, seeded["org"].id)
    r = client.post(f"/api/controls/systems/{system.id}/scope", json={
        "framework_id": "scope-fw", "baseline": "L1",
    }, headers=_h(csrf))
    assert r.status_code == 200
    body = r.json()
    assert body == {"in_scope": 1, "marked_na": 1, "skipped_assessed": 1}

    impls = {i.control_id: i for i in db.query(ControlImplementation).filter(
        ControlImplementation.system_id == system.id).all()}
    assert "S-1" not in impls                       # in scope — untouched
    assert impls["S-2"].implementation_status == "NOT_APPLICABLE"
    assert impls["S-3"].implementation_status == "IMPLEMENTED"  # human work preserved
    assert impls["S-3"].narrative == "Already done."


def test_scope_unknown_baseline_422(auth_client, db):
    client, seeded, csrf = auth_client
    system = _setup(db, seeded["org"].id)
    r = client.post(f"/api/controls/systems/{system.id}/scope", json={
        "framework_id": "scope-fw", "baseline": "NOPE",
    }, headers=_h(csrf))
    assert r.status_code == 422

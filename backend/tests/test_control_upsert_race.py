"""INTEGRITY-4: two first-time saves of the same control (two tabs / two
assessors) raced read-then-insert; the loser hit the UNIQUE constraint and got
HTTP 500 with its edit lost. The loser must now land as an update."""
import routers.controls as controls_router
from models import ControlImplementation, System


def test_insert_race_on_first_save_becomes_an_update(auth_client, db, monkeypatch):
    client, seeded, csrf = auth_client
    s = System(organization_id=seeded["org"].id, name="Race", acronym="RC")
    db.add(s)
    db.flush()
    # The "other tab" already created the row…
    db.add(ControlImplementation(system_id=s.id, framework_id="race-fw", control_id="AC-2",
                                 implementation_status="PLANNED", narrative="from tab B"))
    db.commit()

    # …but this request read before that commit: its first lookup sees nothing.
    real = controls_router._find_impl
    calls = {"n": 0}

    def stale_then_real(*a, **kw):
        calls["n"] += 1
        return None if calls["n"] == 1 else real(*a, **kw)

    monkeypatch.setattr(controls_router, "_find_impl", stale_then_real)
    r = client.put(f"/api/controls/systems/{s.id}/race-fw/AC-2",
                   json={"implementation_status": "IMPLEMENTED", "narrative": "from tab A"},
                   headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200, r.text
    rows = db.query(ControlImplementation).filter_by(system_id=s.id, framework_id="race-fw").all()
    assert len(rows) == 1
    db.refresh(rows[0])
    assert rows[0].implementation_status == "IMPLEMENTED"
    assert rows[0].narrative == "from tab A"

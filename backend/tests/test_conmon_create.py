"""E2E-4 / E2E-8: logging a ConMon activity from the UI.

- Blank optional fields arrive as null from a form; that must save, not 422.
- A framework-specific entry (framework_id) satisfies that framework's cadence,
  and an unknown/inactive framework_id is refused with a readable 422."""
from datetime import date

from models import ConMonCadence, FrameworkActivation, System


def _h(csrf):
    return {"X-CSRF-Token": csrf} if csrf else {}


def _system(db, org):
    s = System(organization_id=org.id, name="Plant", acronym="PLT")
    db.add(s)
    db.commit()
    return s


def test_blank_optional_fields_sent_as_null_are_accepted(auth_client, db):
    client, seeded, csrf = auth_client
    s = _system(db, seeded["org"])
    r = client.post("/api/conmon", json={
        "system_id": s.id, "entry_date": date.today().isoformat(), "activity_type": "LOG_REVIEW",
        "description": "Weekly SIEM log review", "performed_by": None, "findings": None,
        "actions_taken": None, "framework_id": None, "follow_up_required": False, "follow_up_date": None,
    }, headers=_h(csrf))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["performed_by"] == "" and body["findings"] == "" and body["actions_taken"] == ""


def test_framework_entry_satisfies_framework_cadence(auth_client, db):
    client, seeded, csrf = auth_client
    org = seeded["org"]
    s = _system(db, org)
    db.add(FrameworkActivation(organization_id=org.id, framework_id="cad-fw", is_active=True))
    db.add(ConMonCadence(organization_id=org.id, framework_id="cad-fw",
                         activity_type="VULNERABILITY_SCAN", interval_days=30, enabled=True))
    db.commit()

    def status():
        rows = client.get("/api/conmon/cadences").json()
        return next(r["status"] for r in rows
                    if r["framework_id"] == "cad-fw" and r["activity_type"] == "VULNERABILITY_SCAN")

    assert status() == "NEVER"
    r = client.post("/api/conmon", json={
        "system_id": s.id, "framework_id": "cad-fw", "entry_date": date.today().isoformat(),
        "activity_type": "VULNERABILITY_SCAN", "description": "Quarterly ASV scan",
    }, headers=_h(csrf))
    assert r.status_code == 200, r.text
    assert status() == "OK"


def test_inactive_framework_id_is_refused(auth_client, db):
    client, seeded, csrf = auth_client
    s = _system(db, seeded["org"])
    r = client.post("/api/conmon", json={
        "system_id": s.id, "framework_id": "not-active", "entry_date": date.today().isoformat(),
        "activity_type": "VULNERABILITY_SCAN", "description": "x",
    }, headers=_h(csrf))
    assert r.status_code == 422
    assert "framework" in r.json()["detail"]


# --- evidence_artifact_id must be the caller's (company + system scope) ---------

def _evidence(db, org_id, system_id, name="scan.pdf"):
    from models import EvidenceArtifact
    ev = EvidenceArtifact(organization_id=org_id, system_id=system_id, filename=name)
    db.add(ev)
    db.commit()
    return ev


def _entry(system_id, **extra):
    return {"system_id": system_id, "entry_date": date.today().isoformat(),
            "activity_type": "VULNERABILITY_SCAN", "description": "scan", **extra}


def test_evidence_from_another_company_is_refused(auth_client, db):
    from models import Organization
    client, seeded, csrf = auth_client
    s = _system(db, seeded["org"])
    other = Organization(name="Other Co", slug="other-conmon-ev")
    db.add(other)
    db.flush()
    other_sys = System(organization_id=other.id, name="Theirs", acronym="TH")
    db.add(other_sys)
    db.commit()
    foreign = _evidence(db, other.id, other_sys.id)
    r = client.post("/api/conmon", json=_entry(s.id, evidence_artifact_id=foreign.id), headers=_h(csrf))
    assert r.status_code == 404
    mine = _evidence(db, seeded["org"].id, s.id)
    r = client.post("/api/conmon", json=_entry(s.id, evidence_artifact_id=mine.id), headers=_h(csrf))
    assert r.status_code == 200, r.text
    # and PATCH can't re-point an entry at foreign evidence either
    r2 = client.patch(f"/api/conmon/{r.json()['id']}", json={"evidence_artifact_id": foreign.id}, headers=_h(csrf))
    assert r2.status_code == 404


def test_evidence_outside_system_scope_is_refused(db, seeded):
    """Only org-wide roles (admin, compliance_manager) hold edit:conmon today, so
    the scope half is defence in depth — exercised directly with a scoped user."""
    import pytest
    from fastapi import HTTPException
    from models import SystemAssignment, User
    from routers.conmon import _require_evidence_visible
    org = seeded["org"]
    a = _system(db, org)
    b = System(organization_id=org.id, name="Bravo", acronym="B")
    db.add(b)
    db.flush()
    scoped = User(organization_id=org.id, username="scoped-as", role="assessor", password_hash="x")
    db.add(scoped)
    db.flush()
    db.add(SystemAssignment(user_id=scoped.id, system_id=a.id))
    db.commit()
    ev_a, ev_b = _evidence(db, org.id, a.id, "a.pdf"), _evidence(db, org.id, b.id, "b.pdf")
    _require_evidence_visible(db, scoped, ev_a.id)  # in scope: fine
    with pytest.raises(HTTPException) as exc:
        _require_evidence_visible(db, scoped, ev_b.id)
    assert exc.value.status_code == 404

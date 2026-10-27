"""Red Team reads the assessment status the app actually stores.

The Assessments API and the demo seed write status "COMPLETE"; the analyzer
compared against "COMPLETED", so every completed assessment was ignored and
the report claimed "No completed assessments" (plus an "Assessment Program
Failure" chain whenever a deadline was overdue)."""
from datetime import date, datetime, timedelta, timezone

from models import Assessment, CalendarEvent, System
from models.assessment import ASSESSMENT_COMPLETE
from services.redteam_analyzer import analyze_system


def _system(db, org):
    s = System(organization_id=org.id, name="Plant", acronym="PLT", description="",
               system_type="", environment="production", criticality="high")
    db.add(s)
    db.flush()
    return s


def _titles(result):
    return [f["title"] for f in result["findings"]]


def test_completed_assessment_counts(db, seeded):
    org = seeded["org"]
    s = _system(db, org)
    db.add(Assessment(organization_id=org.id, system_id=s.id, framework_id="cmmc-2.0",
                      assessment_type="Annual", status=ASSESSMENT_COMPLETE,
                      started_at=datetime.now(timezone.utc) - timedelta(days=40),
                      completed_at=datetime.now(timezone.utc) - timedelta(days=30)))
    # An overdue deadline: with the old bug this completed the bogus
    # "Assessment Program Failure" chain.
    db.add(CalendarEvent(organization_id=org.id, system_id=s.id, framework_id="cmmc-2.0",
                         event_type="DEADLINE", title="SSP update", event_date=date.today() - timedelta(days=5)))
    db.commit()
    result = analyze_system(db, s.id, "cmmc-2.0", organization_id=org.id, run_by="t")
    assert "No completed assessments" not in _titles(result)
    assert "No assessments conducted for this framework" not in _titles(result)
    assert all(c["title"] != "Assessment Program Failure" for c in result["attack_chains"])


def test_completed_via_api_is_seen_by_red_team(auth_client, db):
    """End to end: the status the Assessments API writes is the one Red Team reads."""
    client, seeded, csrf = auth_client
    org = seeded["org"]
    s = _system(db, org)
    from tests.conftest import activate_framework
    activate_framework(db, org, "cmmc-2.0", "AC.L2-3.1.1")
    db.commit()
    h = {"X-CSRF-Token": csrf}
    r = client.post("/api/assessments", json={"system_id": s.id, "framework_id": "cmmc-2.0",
                                                "assessment_type": "Annual"}, headers=h)
    assert r.status_code == 200, r.text
    aid = r.json()["id"]
    r = client.put(f"/api/assessments/{aid}", json={"status": ASSESSMENT_COMPLETE}, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["completed_at"]
    result = analyze_system(db, s.id, "cmmc-2.0", organization_id=org.id, run_by="t")
    assert "No completed assessments" not in _titles(result)


def test_in_progress_only_is_still_flagged(db, seeded):
    org = seeded["org"]
    s = _system(db, org)
    db.add(Assessment(organization_id=org.id, system_id=s.id, framework_id="cmmc-2.0",
                      assessment_type="Annual", status="IN_PROGRESS"))
    db.commit()
    result = analyze_system(db, s.id, "cmmc-2.0", organization_id=org.id, run_by="t")
    assert "No completed assessments" in _titles(result)


def test_api_rejects_non_canonical_status(auth_client, db):
    client, seeded, csrf = auth_client
    org = seeded["org"]
    s = _system(db, org)
    from tests.conftest import activate_framework
    activate_framework(db, org, "cmmc-2.0", "AC.L2-3.1.1")
    db.commit()
    h = {"X-CSRF-Token": csrf}
    aid = client.post("/api/assessments", json={"system_id": s.id, "framework_id": "cmmc-2.0",
                                                 "assessment_type": "Annual"}, headers=h).json()["id"]
    r = client.put(f"/api/assessments/{aid}", json={"status": "COMPLETED"}, headers=h)
    assert r.status_code == 422

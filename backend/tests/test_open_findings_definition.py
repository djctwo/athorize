"""One meaning of "open" (services/metrics.py) on every surface.

The Dashboard counted Delayed findings as open while the Findings page counted
only Open + In Progress (12 vs 11 in the demo). The server now marks each
finding `is_open` and reports how many open findings are Delayed, so both pages
show the same number and say that Delayed is included."""
from models import Control, Finding, FrameworkActivation, System


def _setup(db, org):
    db.add(FrameworkActivation(organization_id=org.id, framework_id="x", is_active=True))
    db.add(Control(framework_id="x", control_id="AC-2", title="x"))
    s = System(organization_id=org.id, name="S1", acronym="S1", description="", system_type="",
               environment="production", criticality="moderate")
    db.add(s)
    db.flush()
    for i, status in enumerate(["OPEN", "IN_PROGRESS", "DELAYED", "CLOSED", "RISK_ACCEPTED", "FALSE_POSITIVE"]):
        db.add(Finding(organization_id=org.id, system_id=s.id, framework_id="x", control_id="AC-2",
                       title=f"f{i}", severity="HIGH", status=status))
    db.commit()
    return s


def test_findings_list_marks_open_with_the_server_definition(auth_client, db):
    client, seeded, _ = auth_client
    _setup(db, seeded["org"])
    rows = client.get("/api/findings").json()
    by_status = {r["status"]: r["is_open"] for r in rows}
    assert by_status == {"OPEN": True, "IN_PROGRESS": True, "DELAYED": True,
                         "CLOSED": False, "RISK_ACCEPTED": False, "FALSE_POSITIVE": False}


def test_dashboard_open_count_matches_findings_list_and_reports_delayed(auth_client, db):
    client, seeded, _ = auth_client
    _setup(db, seeded["org"])
    snap = client.get("/api/dashboard/snapshot").json()
    rows = client.get("/api/findings").json()
    assert snap["open_findings"] == sum(1 for r in rows if r["is_open"]) == 3
    assert snap["delayed_findings"] == 1

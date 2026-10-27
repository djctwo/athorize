def test_dashboard_snapshot(auth_client):
    client, _, _ = auth_client
    resp = client.get("/api/dashboard/snapshot")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_systems" in data
    assert "open_findings" in data
    assert "open_risks" in data


def test_finding_aging(auth_client):
    client, _, _ = auth_client
    resp = client.get("/api/dashboard/finding-aging")
    assert resp.status_code == 200
    data = resp.json()
    assert "overdue" in data
    assert "on_track" in data


def test_evidence_freshness(auth_client):
    client, _, _ = auth_client
    resp = client.get("/api/dashboard/evidence-freshness")
    assert resp.status_code == 200
    data = resp.json()
    assert "fresh" in data
    assert "total" in data


def test_activity_feed(auth_client):
    client, _, _ = auth_client
    resp = client.get("/api/dashboard/activity")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_snapshot_system_filter(auth_client, db):
    client, seeded, _ = auth_client
    from models import Control, FrameworkActivation, System, Finding
    org = seeded["org"]
    # Company numbers count findings of active frameworks with a loaded catalog (R2DATA-6).
    db.add(FrameworkActivation(organization_id=org.id, framework_id="x", is_active=True))
    db.add(Control(framework_id="x", control_id="AC-2", title="x"))
    s1 = System(organization_id=org.id, name="S1", acronym="S1", description="", system_type="", environment="production", criticality="moderate")
    s2 = System(organization_id=org.id, name="S2", acronym="S2", description="", system_type="", environment="production", criticality="moderate")
    db.add_all([s1, s2]); db.flush()
    db.add(Finding(organization_id=org.id, system_id=s1.id, framework_id="x", control_id="AC-2", title="f1", severity="HIGH", status="OPEN"))
    db.add(Finding(organization_id=org.id, system_id=s2.id, framework_id="x", control_id="AC-3", title="f2", severity="HIGH", status="OPEN"))
    db.commit()

    allsys = client.get("/api/dashboard/snapshot").json()
    one = client.get(f"/api/dashboard/snapshot?system_id={s1.id}").json()
    assert allsys["open_findings"] >= 2
    assert one["open_findings"] == 1


def test_compliance_reports_assessed_controls_per_pair(auth_client, db):
    """The Dashboard bar chart hides system x framework pairs nobody has started
    (76 bars, most at 0%, in the demo). It needs to know which pairs have data:
    a 0% pair whose controls are assessed Not Implemented is real information."""
    client, seeded, _ = auth_client
    from models import Control, ControlImplementation, FrameworkActivation, System
    org = seeded["org"]
    for fw in ("x", "y"):
        db.add(FrameworkActivation(organization_id=org.id, framework_id=fw, is_active=True))
        db.add(Control(framework_id=fw, control_id="AC-2", title="x"))
        db.add(Control(framework_id=fw, control_id="AC-3", title="x"))
    s = System(organization_id=org.id, name="S1", acronym="S1", description="", system_type="", environment="production", criticality="moderate")
    db.add(s); db.flush()
    db.add(ControlImplementation(system_id=s.id, framework_id="x", control_id="AC-2", implementation_status="NOT_IMPLEMENTED"))
    db.add(ControlImplementation(system_id=s.id, framework_id="x", control_id="AC-3", implementation_status="NOT_ASSESSED"))
    db.commit()
    rows = {r["framework_id"]: r for r in client.get("/api/dashboard/compliance").json()}
    assert rows["x"]["score_percentage"] == 0 and rows["x"]["assessed_controls"] == 1
    assert rows["y"]["assessed_controls"] == 0

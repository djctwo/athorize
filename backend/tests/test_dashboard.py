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

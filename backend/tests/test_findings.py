import pytest

from tests.conftest import activate_framework


@pytest.fixture(autouse=True)
def _pci_active(db, seeded):
    # Findings can only be filed under an active framework with a loaded catalog (R2DATA-6).
    activate_framework(db, seeded["org"], "pci-dss-v4")


def _create_system(client, csrf):
    resp = client.post("/api/systems", json={"name": "FindingSys", "acronym": "FS"},
                       headers={"X-CSRF-Token": csrf} if csrf else {})
    return resp.json()["id"]


def test_create_finding(auth_client):
    client, _, csrf = auth_client
    sys_id = _create_system(client, csrf)
    resp = client.post("/api/findings", json={
        "system_id": sys_id,
        "framework_id": "pci-dss-v4",
        "title": "Test Finding",
        "severity": "HIGH",
    }, headers={"X-CSRF-Token": csrf} if csrf else {})
    assert resp.status_code == 200
    data = resp.json()
    assert data["title"] == "Test Finding"
    assert data["status"] == "OPEN"
    assert "aging_bucket" in data


def test_finding_state_machine_valid(auth_client):
    client, _, csrf = auth_client
    sys_id = _create_system(client, csrf)
    headers = {"X-CSRF-Token": csrf} if csrf else {}
    resp = client.post("/api/findings", json={
        "system_id": sys_id, "framework_id": "pci-dss-v4",
        "title": "SM Test", "severity": "MEDIUM",
    }, headers=headers)
    fid = resp.json()["id"]

    resp = client.patch(f"/api/findings/{fid}", json={"status": "IN_PROGRESS"}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "IN_PROGRESS"


def test_finding_state_machine_invalid(auth_client):
    client, _, csrf = auth_client
    sys_id = _create_system(client, csrf)
    headers = {"X-CSRF-Token": csrf} if csrf else {}
    resp = client.post("/api/findings", json={
        "system_id": sys_id, "framework_id": "pci-dss-v4",
        "title": "SM Invalid", "severity": "LOW",
    }, headers=headers)
    fid = resp.json()["id"]

    resp = client.patch(f"/api/findings/{fid}", json={"status": "DELAYED"}, headers=headers)
    assert resp.status_code == 422


def test_list_findings_filtered(auth_client):
    client, _, csrf = auth_client
    sys_id = _create_system(client, csrf)
    headers = {"X-CSRF-Token": csrf} if csrf else {}
    client.post("/api/findings", json={
        "system_id": sys_id, "framework_id": "pci-dss-v4",
        "title": "Critical", "severity": "CRITICAL",
    }, headers=headers)
    client.post("/api/findings", json={
        "system_id": sys_id, "framework_id": "pci-dss-v4",
        "title": "Low", "severity": "LOW",
    }, headers=headers)

    resp = client.get("/api/findings?severity=CRITICAL")
    assert resp.status_code == 200
    assert all(f["severity"] == "CRITICAL" for f in resp.json())


def test_terminal_finding_has_no_aging(auth_client, db):
    from services.aging import compute_aging
    from datetime import date, timedelta
    past_due = date.today() - timedelta(days=10)
    # Active finding past due → OVERDUE
    assert compute_aging(past_due, None, "OPEN")["aging_bucket"] == "OVERDUE"
    # Terminal statuses → RESOLVED, no countdown, even with a past due date
    for status in ("CLOSED", "RISK_ACCEPTED", "FALSE_POSITIVE"):
        enriched = compute_aging(past_due, None, status)
        assert enriched["aging_bucket"] == "RESOLVED"
        assert enriched["days_until_due"] is None

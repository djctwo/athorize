def test_create_system(auth_client):
    client, seeded, csrf = auth_client
    resp = client.post("/api/systems", json={
        "name": "Test System",
        "acronym": "TST",
    }, headers={"X-CSRF-Token": csrf} if csrf else {})
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "Test System"
    assert data["acronym"] == "TST"


def test_list_systems(auth_client):
    client, seeded, csrf = auth_client
    client.post("/api/systems", json={"name": "Sys1", "acronym": "S1"},
                headers={"X-CSRF-Token": csrf} if csrf else {})
    resp = client.get("/api/systems")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1


def test_get_system_not_found(auth_client):
    client, _, _ = auth_client
    resp = client.get("/api/systems/9999")
    assert resp.status_code == 404

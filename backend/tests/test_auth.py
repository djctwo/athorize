def test_setup_creates_org(client, setup_token_value):
    # Setup always needs the token now (it used to be open when the token file
    # was missing — SECCODE-9; see test_setup_fail_closed.py).
    resp = client.post("/api/auth/setup", json={
        "org_name": "NewOrg",
        "username": "setupadmin",
        "password": "Password1234!",
        "setup_token": setup_token_value,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "user_id" in data
    assert "org_id" in data


def test_setup_requires_token_when_present(client, tmp_path, monkeypatch):
    from services import setup_token
    token_file = tmp_path / "setup-token"
    token_file.write_text("the-real-token")
    monkeypatch.setattr(setup_token, "_TOKEN_PATH", token_file)

    # Wrong/missing token is rejected
    bad = client.post("/api/auth/setup", json={
        "org_name": "Org", "username": "admin1", "password": "Password1234!",
        "setup_token": "wrong",
    })
    assert bad.status_code == 403

    # Correct token succeeds and the token is consumed
    good = client.post("/api/auth/setup", json={
        "org_name": "Org", "username": "admin1", "password": "Password1234!",
        "setup_token": "the-real-token",
    })
    assert good.status_code == 200
    assert not token_file.exists()


def test_setup_rejects_weak_password(client, setup_token_value):
    resp = client.post("/api/auth/setup", json={
        "org_name": "Org", "username": "adminuser", "password": "alllowercaseletters",
        "setup_token": setup_token_value,
    })
    assert resp.status_code == 422


def test_login_success(client, seeded):
    resp = client.post("/api/auth/login", json={"username": "testadmin", "password": "testpass1234!"})
    assert resp.status_code == 200
    assert "session_id" in resp.cookies


def test_login_wrong_password(client, seeded):
    resp = client.post("/api/auth/login", json={"username": "testadmin", "password": "wrong"})
    assert resp.status_code == 401


def test_me_unauthenticated(client):
    resp = client.get("/api/auth/me")
    assert resp.status_code == 401


def test_me_authenticated(auth_client):
    client, seeded, _ = auth_client
    resp = client.get("/api/auth/me")
    assert resp.status_code == 200
    assert resp.json()["username"] == "testadmin"


def test_admin_password_reset_works_and_kills_sessions(auth_client):
    client, seeded, csrf = auth_client
    h = {"X-CSRF-Token": csrf} if csrf else {}
    r = client.post("/api/users", json={
        "username": "resetme", "password": "Walrus-Trampoline-99",
        "email": "r@x.com", "display_name": "R", "role": "assessor",
    }, headers=h)
    assert r.status_code == 200, r.text
    uid = r.json()["id"]
    # weak replacement rejected
    r = client.patch(f"/api/users/{uid}", json={"password": "short"}, headers=h)
    assert r.status_code == 422
    # strong replacement accepted
    r = client.patch(f"/api/users/{uid}", json={"password": "Giraffe-Lantern-2026!"}, headers=h)
    assert r.status_code == 200
    # old password no longer works, new one does
    assert client.post("/api/auth/login", json={"username": "resetme", "password": "Walrus-Trampoline-99"}).status_code == 401
    assert client.post("/api/auth/login", json={"username": "resetme", "password": "Giraffe-Lantern-2026!"}).status_code == 200

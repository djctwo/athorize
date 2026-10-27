"""API tokens: mint once, authenticate via bearer, list redacted, revoke."""


def _h(csrf):
    return {"X-CSRF-Token": csrf} if csrf else {}


class TestApiTokens:
    def test_create_returns_raw_token_once(self, auth_client):
        client, _seeded, csrf = auth_client
        r = client.post("/api/tokens", json={"name": "ci-bot"}, headers=_h(csrf))
        assert r.status_code == 200
        body = r.json()
        assert body["token"].startswith("athu_")
        assert body["name"] == "ci-bot"
        # listing never returns the raw token, only the prefix
        lst = client.get("/api/tokens").json()
        assert all("token" not in t for t in lst)
        assert any(t["token_prefix"] == body["token_prefix"] for t in lst)

    def test_bearer_token_authenticates(self, auth_client):
        client, _seeded, csrf = auth_client
        raw = client.post("/api/tokens", json={"name": "bot"}, headers=_h(csrf)).json()["token"]
        # a fresh client with no session cookie, only the bearer header
        client.cookies.clear()
        r = client.get("/api/frameworks", headers={"Authorization": f"Bearer {raw}"})
        assert r.status_code == 200

    def test_revoked_token_rejected(self, auth_client):
        client, _seeded, csrf = auth_client
        created = client.post("/api/tokens", json={"name": "temp"}, headers=_h(csrf)).json()
        raw, tid = created["token"], created["id"]
        assert client.delete(f"/api/tokens/{tid}", headers=_h(csrf)).status_code == 200
        client.cookies.clear()
        r = client.get("/api/frameworks", headers={"Authorization": f"Bearer {raw}"})
        assert r.status_code == 401

    def test_garbage_bearer_rejected(self, client):
        r = client.get("/api/frameworks", headers={"Authorization": "Bearer not-a-real-token"})
        assert r.status_code == 401

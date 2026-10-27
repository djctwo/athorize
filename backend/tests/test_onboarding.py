"""Dashboard onboarding checklist endpoint."""


class TestOnboarding:
    def test_fresh_org_has_pending_steps(self, auth_client):
        client, _seeded, _csrf = auth_client
        r = client.get("/api/dashboard/onboarding")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 6
        assert {"framework", "system", "team", "implementation", "evidence", "conmon"} == {s["key"] for s in body["steps"]}
        # a fresh seeded org (one admin, nothing set up) is not complete
        assert body["complete"] is False
        assert all("to" in s and "label" in s and "done" in s for s in body["steps"])

    def test_requires_auth(self, client):
        assert client.get("/api/dashboard/onboarding").status_code == 401

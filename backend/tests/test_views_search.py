"""Saved filter views + global content search."""
from models import Finding, System, User
from services.auth import hash_password


def _h(csrf):
    return {"X-CSRF-Token": csrf} if csrf else {}


class TestSavedViews:
    def test_crud_and_same_name_updates(self, auth_client):
        client, _seeded, csrf = auth_client
        v = client.post("/api/views", json={
            "page": "findings", "name": "Critical open",
            "params": {"filterSeverity": "CRITICAL", "filterStatus": "OPEN"},
        }, headers=_h(csrf)).json()
        assert v["params"]["filterSeverity"] == "CRITICAL"

        # same name = update in place, not duplicate
        client.post("/api/views", json={
            "page": "findings", "name": "Critical open",
            "params": {"filterSeverity": "HIGH"},
        }, headers=_h(csrf))
        views = client.get("/api/views?page=findings").json()
        assert len(views) == 1 and views[0]["params"]["filterSeverity"] == "HIGH"

        assert client.delete(f"/api/views/{views[0]['id']}", headers=_h(csrf)).status_code == 200
        assert client.get("/api/views?page=findings").json() == []

    def test_rollout_page_keys_round_trip(self, auth_client):
        # SavedViews now ships on Evidence/Controls/Assets too — each page key
        # must store and list independently.
        client, _seeded, csrf = auth_client
        for page in ("evidence", "controls", "assets"):
            r = client.post("/api/views", json={
                "page": page, "name": f"{page} view", "params": {"mineOnly": True},
            }, headers=_h(csrf))
            assert r.status_code == 200, page
        for page in ("evidence", "controls", "assets"):
            views = client.get(f"/api/views?page={page}").json()
            assert [v["name"] for v in views] == [f"{page} view"]
            assert views[0]["params"] == {"mineOnly": True}

    def test_views_are_private_to_the_user(self, auth_client, db):
        client, seeded, csrf = auth_client
        client.post("/api/views", json={"page": "findings", "name": "Mine", "params": {}},
                    headers=_h(csrf))
        other = User(organization_id=seeded["org"].id, username="viewer2",
                     password_hash=hash_password("viewerpass123!"), role="assessor")
        db.add(other)
        db.commit()
        client.post("/api/auth/login", json={"username": "viewer2", "password": "viewerpass123!"})
        assert client.get("/api/views?page=findings").json() == []  # not the admin's views


class TestSearch:
    def test_search_finds_and_scopes(self, auth_client, db):
        client, seeded, _ = auth_client
        s = System(organization_id=seeded["org"].id, name="Payment Gateway", acronym="PAY")
        db.add(s)
        db.flush()
        db.add(Finding(organization_id=seeded["org"].id, system_id=s.id,
                       framework_id="test-fw", control_id="AC-1",
                       title="Payment logs unencrypted", severity="HIGH", status="OPEN"))
        # another org's finding with the same term must NOT surface
        from models import Organization
        other = Organization(name="OtherSearch", slug="other-search")
        db.add(other)
        db.flush()
        s2 = System(organization_id=other.id, name="Foreign", acronym="FRN")
        db.add(s2)
        db.flush()
        db.add(Finding(organization_id=other.id, system_id=s2.id,
                       framework_id="test-fw", control_id="AC-1",
                       title="Payment fraud elsewhere", severity="HIGH", status="OPEN"))
        db.commit()

        res = client.get("/api/search?q=payment").json()
        assert [f["title"] for f in res["findings"]] == ["Payment logs unencrypted"]
        assert [x["acronym"] for x in res["systems"]] == ["PAY"]

    def test_short_query_returns_empty(self, auth_client):
        client, _seeded, _ = auth_client
        res = client.get("/api/search?q=a").json()
        assert all(v == [] for v in res.values())

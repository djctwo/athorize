"""Custom framework builder — authoring, activation without a license, guards."""
import pytest

from config import settings
from routers.frameworks import loader


def _h(csrf):
    return {"X-CSRF-Token": csrf} if csrf else {}


@pytest.fixture
def custom_dir(tmp_path, monkeypatch, request):
    """Point both the settings property source and the live loader at a temp
    custom dir; re-discover on teardown so other tests see a clean registry."""
    monkeypatch.setattr(settings, "data_dir", tmp_path)
    monkeypatch.setattr(loader, "_custom_dir", tmp_path / "custom_frameworks")
    loader.discover()
    request.addfinalizer(lambda: loader.discover())  # runs after monkeypatch undo
    return tmp_path / "custom_frameworks"


def _create(client, csrf, name="Acme Security Policy"):
    return client.post("/api/custom-frameworks", json={
        "name": name, "description": "In-house policy", "publisher": "Acme",
    }, headers=_h(csrf))


class TestBuilder:
    def test_create_edit_activate_delete(self, auth_client, custom_dir):
        client, _seeded, csrf = auth_client
        r = _create(client, csrf)
        assert r.status_code == 200
        fid = r.json()["id"]
        # R2SEC-12: ids are qualified by the creating company
        assert fid == f"custom-{_seeded['org'].id}-acme-security-policy"
        assert (custom_dir / fid / "catalog.json").exists()

        # author controls
        r = client.put(f"/api/custom-frameworks/{fid}/controls", json={"controls": [
            {"id": "POL-1", "family": "POL", "title": "Password policy", "description": "12+ chars."},
            {"id": "POL-2", "family": "POL", "title": "Screen lock", "description": "5 minutes."},
        ]}, headers=_h(csrf))
        assert r.status_code == 200 and r.json()["controls"] == 2

        # appears in the marketplace as custom + entitled DESPITE no license
        fw = {f["id"]: f for f in client.get("/api/frameworks").json()}[fid]
        assert fw["is_custom"] is True and fw["entitled"] is True
        assert fw["control_count"] == 2

        # activates with no license installed (custom bypasses entitlement)
        r = client.post(f"/api/frameworks/{fid}/activate", json={"license_key": ""}, headers=_h(csrf))
        assert r.status_code == 200

        # its controls are queryable like any framework's
        rows = client.get(f"/api/controls?framework_id={fid}").json()
        assert {c["control_id"] for c in rows} == {"POL-1", "POL-2"}

        # delete refused while active; allowed after deactivation
        assert client.delete(f"/api/custom-frameworks/{fid}", headers=_h(csrf)).status_code == 409
        client.post(f"/api/frameworks/{fid}/deactivate", headers=_h(csrf))
        assert client.delete(f"/api/custom-frameworks/{fid}", headers=_h(csrf)).status_code == 200
        assert not (custom_dir / fid).exists()

    def test_duplicate_ids_rejected(self, auth_client, custom_dir):
        client, _seeded, csrf = auth_client
        fid = _create(client, csrf).json()["id"]
        r = client.put(f"/api/custom-frameworks/{fid}/controls", json={"controls": [
            {"id": "X-1", "title": "A"}, {"id": "X-1", "title": "B"},
        ]}, headers=_h(csrf))
        assert r.status_code == 422

    def test_cannot_touch_bundled_frameworks(self, auth_client, custom_dir):
        client, _seeded, csrf = auth_client
        # a bundled id is not a custom framework — every mutating route 404s
        r = client.put("/api/custom-frameworks/nist-800-53-r5/controls",
                       json={"controls": []}, headers=_h(csrf))
        assert r.status_code == 404
        assert client.delete("/api/custom-frameworks/nist-800-53-r5", headers=_h(csrf)).status_code == 404

    def test_name_collision_with_existing_framework(self, auth_client, custom_dir):
        client, _seeded, csrf = auth_client
        assert _create(client, csrf).status_code == 200
        assert _create(client, csrf).status_code == 409  # same slug

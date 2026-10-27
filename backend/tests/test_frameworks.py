"""Framework activation.

Every bundled framework activates freely — there is no vendor license. Only
third-party-content frameworks (`restriction: licensed` in metadata) require the
user to attest their own publisher license key. None ship today; the path is
exercised by patching a framework's metadata.
"""
import dataclasses
import json

from routers import frameworks as fw_router


def _h(csrf):
    return {"X-CSRF-Token": csrf} if csrf else {}


class TestActivation:
    def test_bundled_framework_activates_without_license(self, auth_client):
        client, _seeded, csrf = auth_client
        r = client.post("/api/frameworks/nist-csf-2.0/activate", json={"license_key": ""}, headers=_h(csrf))
        assert r.status_code == 200

    def test_list_reports_every_bundled_framework_entitled(self, auth_client):
        client, _seeded, _csrf = auth_client
        frameworks = client.get("/api/frameworks").json()
        assert frameworks and all(f["entitled"] for f in frameworks)

    def test_licensed_third_party_content_needs_attested_key(self, auth_client, monkeypatch):
        client, _seeded, csrf = auth_client
        real = fw_router.loader.get_metadata

        def patched(fid):
            meta = real(fid)
            if fid == "cmmc-2.0" and meta is not None:
                return dataclasses.replace(meta, license={"restriction": "licensed", "licensor": "Example Publisher"})
            return meta

        monkeypatch.setattr(fw_router.loader, "get_metadata", patched)
        blocked = client.post("/api/frameworks/cmmc-2.0/activate", json={"license_key": ""}, headers=_h(csrf))
        assert blocked.status_code == 403
        assert "Example Publisher" in blocked.json()["detail"]
        ok = client.post("/api/frameworks/cmmc-2.0/activate", json={"license_key": "MY-KEY"}, headers=_h(csrf))
        assert ok.status_code == 200


class TestPluginCatalogs:
    """Every shipped framework plugin must load with a well-formed catalog."""

    def _loader(self):
        from config import settings
        from services.framework_loader import FrameworkLoader
        return FrameworkLoader(settings.frameworks_dir)

    def test_all_catalogs_wellformed(self):
        loader = self._loader()
        # BUNDLED catalogs only — a developer machine may carry local custom
        # frameworks in the data dir (their validation is the builder's job).
        metas = [m for m in loader.list_all() if not m.is_custom]
        assert len(metas) >= 18  # 17 original + iec-62443
        for m in metas:
            cat = json.loads((loader._paths[m.id] / "catalog.json").read_text())
            assert cat["framework_id"] == m.id
            ids = [c["id"] for c in cat["controls"]]
            assert ids, f"{m.id} has no controls"
            assert len(ids) == len(set(ids)), f"{m.id} has duplicate control ids"
            for c in cat["controls"]:
                assert c.get("id") and c.get("title") and c.get("description"), f"{m.id}:{c.get('id')} missing fields"

    def test_iec_62443_present_and_loads(self, db):
        loader = self._loader()
        m = loader.get_metadata("iec-62443")
        assert m is not None and m.short_name == "IEC 62443"
        n = loader.load_catalog("iec-62443", db)
        assert n == 80  # 51 System Requirements (3-3) + 29 component requirements (4-2)

    def test_iec_62443_crosswalk_resolves_through_hub(self, db):
        from services.crosswalk import resolve, HUB_FRAMEWORK
        loader = self._loader()
        for f in (HUB_FRAMEWORK, "iec-62443", "iso-27001-2022"):
            loader.load_catalog(f, db)
            loader.load_mappings(f, db)
        db.flush()
        active = {HUB_FRAMEWORK, "iec-62443", "iso-27001-2022"}
        # SR-2.5 (session lock) is equivalent to 800-53 AC-11 and must fan out.
        entries = resolve(db, "iec-62443", "SR-2.5", active)
        hub = [e for e in entries if e.framework_id == HUB_FRAMEWORK]
        assert any(e.control_id == "AC-11" and e.relationship == "equivalent" for e in hub)
        assert any(e.path.startswith("via ") and e.framework_id == "iso-27001-2022" for e in entries)

    def test_iec_62443_activates(self, auth_client):
        client, _seeded, csrf = auth_client
        r = client.post("/api/frameworks/iec-62443/activate", json={"license_key": ""}, headers=_h(csrf))
        assert r.status_code == 200

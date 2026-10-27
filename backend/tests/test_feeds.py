"""Threat feeds: KEV normalization, control inference, IT-asset matching."""
from types import SimpleNamespace

from services.control_inference import infer_controls
from services.feeds_kev import fetch_kev, normalize_kev
from services.ics_advisories import match_advisory_it


class TestKevNormalize:
    def test_fixture_loads_and_normalizes(self):
        items = fetch_kev(live=False)
        assert len(items) >= 3
        first = items[0]
        # The bundled fixture is fictional sample data (DEMO- ids, no links).
        assert first["advisory_id"].startswith("KEV-DEMO-")
        assert first["source_url"] == ""
        assert first["cve_ids"]
        assert first["severity"] in ("CRITICAL", "HIGH")

    def test_ransomware_use_escalates_severity(self):
        items = normalize_kev([
            {"cveID": "CVE-1", "knownRansomwareCampaignUse": "Known"},
            {"cveID": "CVE-2", "knownRansomwareCampaignUse": "Unknown"},
        ])
        assert items[0]["severity"] == "CRITICAL"
        assert items[1]["severity"] == "HIGH"

    def test_missing_cve_skipped(self):
        assert normalize_kev([{"vendorProject": "X"}]) == []


class TestControlInference:
    def test_base_controls_always_present(self):
        out = infer_controls({"title": "Some bug", "summary": "", "recommended_mitigations": ""})
        assert "RA-5" in out and "SI-2" in out

    def test_ransomware_adds_contingency_and_ir(self):
        out = infer_controls({"title": "Ransomware campaign", "summary": "encrypted files"})
        assert "CP-9" in out and "IR-4" in out

    def test_auth_keywords_add_ia(self):
        out = infer_controls({"title": "Default credentials on HMI", "summary": ""})
        assert "IA-5" in out

    def test_no_duplicates(self):
        out = infer_controls({"title": "remote code execution via vpn rdp remote access", "summary": ""})
        assert len(out) == len(set(out))


class TestItMatching:
    def _asset(self, **kw):
        base = dict(id=1, system_id=10, vendor="", model="", os_family="", os_version="")
        base.update(kw)
        return SimpleNamespace(**base)

    def test_vendor_product_match(self):
        adv = {"affected_vendor": "Microsoft", "affected_product": "SQL Server"}
        asset = self._asset(vendor="Microsoft", model="SQL Server 2019")
        m = match_advisory_it(adv, [asset])
        assert m and m[0]["confidence"] == "VENDOR_PRODUCT"
        assert m[0]["it_asset_id"] == 1 and m[0]["system_id"] == 10

    def test_os_match_without_vendor(self):
        adv = {"affected_vendor": "Microsoft", "affected_product": "Windows"}
        asset = self._asset(vendor="Lenovo", model="ThinkPad T14", os_family="WINDOWS", os_version="11 23H2")
        m = match_advisory_it(adv, [asset])
        assert m and m[0]["confidence"] == "VENDOR_ONLY"

    def test_no_match(self):
        adv = {"affected_vendor": "Cisco", "affected_product": "IOS XE"}
        asset = self._asset(vendor="Dell", model="PowerEdge R750", os_family="LINUX", os_version="RHEL 9")
        assert match_advisory_it(adv, [asset]) == []


class TestNvdFeed:
    def test_fixture_normalizes_with_cpe_vendor(self):
        from services.feeds_nvd import fetch_nvd
        items = fetch_nvd(live=False)
        assert len(items) >= 3
        byid = {i["advisory_id"]: i for i in items}
        assert byid["NVD-DEMO-2026-0203"]["severity"] == "CRITICAL"
        assert byid["NVD-DEMO-2026-0202"]["affected_vendor"] == "Adatum Networks"  # humanized CPE
        assert byid["NVD-DEMO-2026-0201"]["affected_product"] == "Litwareos"
        # Fictional DEMO- ids never link to NVD; real CVE ids do (test_sample_advisories_fictional).
        assert all(i["source_url"] == "" for i in items)


class TestAaFeed:
    def test_fixture_parses_rss_and_extracts_cves(self):
        from services.feeds_aa import fetch_aa
        items = fetch_aa(live=False)
        assert len(items) == 2
        byid = {i["advisory_id"]: i for i in items}
        assert byid["DEMO-AA26-158A"]["severity"] == "CRITICAL"  # ransomware hint
        assert byid["DEMO-AA26-158A"]["cve_ids"] == ["DEMO-2026-0102"]
        assert byid["DEMO-AA26-152A"]["severity"] == "HIGH"
        assert all(i["source_url"] == "" for i in items)

    def test_xxe_payload_rejected(self):
        from services.feeds_aa import AaFeedError, _parse_rss
        import pytest
        evil = (
            '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
            "<rss><channel><item><title>AA26-001A: &x;</title></item></channel></rss>"
        )
        with pytest.raises(AaFeedError):
            _parse_rss(evil)


class TestPsirtFeed:
    def test_fixture_loads_with_dates(self):
        from services.feeds_psirt import fetch_psirt
        from datetime import date
        items = fetch_psirt(live=False)
        assert len(items) == 2
        assert all(isinstance(i["published_date"], date) for i in items)

    def test_live_with_no_providers_returns_empty(self, monkeypatch):
        from services.feeds_psirt import fetch_psirt
        monkeypatch.delenv("ATHORIZE_PSIRT_PROVIDERS", raising=False)
        assert fetch_psirt(live=True) == []


class TestFeedRefreshService:
    def test_refresh_for_org_creates_advisories_and_audit(self, db, seeded):
        from models import AuditEntry, IcsAdvisory
        from services.feed_refresh import refresh_feeds_for_org

        org = seeded["org"]
        result = refresh_feeds_for_org(db, org.id, actor_id=None, actor_username="feed-scheduler")
        assert result["advisories_refreshed"] > 0
        assert result["feed_errors"] == []
        assert db.query(IcsAdvisory).filter(IcsAdvisory.organization_id == org.id).count() > 0
        audit = db.query(AuditEntry).filter(
            AuditEntry.organization_id == org.id,
            AuditEntry.action == "REFRESH",
        ).first()
        assert audit is not None and audit.actor_username == "feed-scheduler"

    def test_refresh_is_idempotent(self, db, seeded):
        from models import IcsAdvisory
        from services.feed_refresh import refresh_feeds_for_org

        org = seeded["org"]
        refresh_feeds_for_org(db, org.id, actor_id=None, actor_username="feed-scheduler")
        count1 = db.query(IcsAdvisory).count()
        refresh_feeds_for_org(db, org.id, actor_id=None, actor_username="feed-scheduler")
        assert db.query(IcsAdvisory).count() == count1


class TestFeedStatusEndpoint:
    def test_status_reports_last_refresh(self, auth_client, db):
        client, seeded, csrf = auth_client
        r = client.get("/api/advisories/feed-status")
        assert r.status_code == 200
        assert r.json()["last_refreshed"] is None

        rr = client.post("/api/advisories/refresh", headers={"X-CSRF-Token": csrf} if csrf else {})
        assert rr.status_code == 200

        r2 = client.get("/api/advisories/feed-status")
        body = r2.json()
        assert body["last_refreshed"] is not None
        assert body["last_refreshed_by"] == "testadmin"
        assert body["live"] is False

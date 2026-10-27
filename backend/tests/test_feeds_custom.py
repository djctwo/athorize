"""Custom advisory feeds: RSS/CSAF parsing, SSRF guard, refresh wiring, settings API."""
from __future__ import annotations

import ipaddress

import httpx
import pytest

from models import AuditEntry, Organization, User
from services import feeds_custom
from services.auth import hash_password
from services.feeds_custom import (
    CustomFeedError,
    _ip_rejection,
    _require_locked_url,
    _walk_csaf_provider,
    assert_public_host,
    fetch_custom_feed,
    fetch_custom_feeds,
    parse_custom_rss,
    validate_feed_entries,
)

RSS_FIXTURE = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Acme Vendor Security Feed</title>
    <item>
      <title>Apache Log4j 2 RCE via JNDI lookups (Log4Shell)</title>
      <link>https://feeds.example.com/advisories/acme-router-rce</link>
      <guid>acme-router-rce-2026</guid>
      <description>Remote code execution (CVE-2021-44228) in Apache Log4j 2 &lt;b&gt;before 2.15.0&lt;/b&gt;.</description>
      <pubDate>Sun, 07 Jun 2026 12:00:00 EST</pubDate>
    </item>
    <item>
      <title>Ransomware campaign targeting Acme NAS devices</title>
      <link>https://feeds.example.com/advisories/acme-nas-ransomware</link>
      <description>LockBit affiliates are encrypting exposed NAS shares.</description>
      <pubDate>Mon, 01 Jun 2026 09:00:00 EST</pubDate>
    </item>
    <item>
      <title>Acme quarterly patch notes</title>
      <link>javascript:alert(1)</link>
      <description>Routine maintenance rollup, no CVEs.</description>
    </item>
    <item>
      <title></title>
      <description>No title — must be skipped.</description>
    </item>
  </channel>
</rss>"""

CSAF_DOC = {
    "document": {
        "title": "Acme PLC Hardcoded Credentials",
        "tracking": {"id": "ACME-SA-2026-001", "initial_release_date": "2026-05-01T00:00:00Z"},
        "notes": [{"category": "summary", "text": "Hardcoded credentials in Acme PLC."}],
    },
    "vulnerabilities": [
        {
            "cve": "DEMO-2026-22222",  # fictional product → fictional id, never a CVE
            "scores": [{"cvss_v3": {"baseSeverity": "CRITICAL", "baseScore": 9.8}}],
            "remediations": [{"details": "Update firmware to 2.0."}],
        }
    ],
    "product_tree": {
        "branches": [
            {"category": "vendor", "name": "Acme",
             "branches": [{"category": "product_name", "name": "PLC-9000"}]}
        ]
    },
}


def _addrinfo(ip: str):
    import socket
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sockaddr = (ip, 443, 0, 0) if family == socket.AF_INET6 else (ip, 443)
    return [(family, socket.SOCK_STREAM, 6, "", sockaddr)]


class TestRssParsing:
    def test_fixture_parses_items(self):
        items = parse_custom_rss(RSS_FIXTURE, "Acme Feed")
        assert len(items) == 3  # titleless item skipped
        assert all(i["advisory_id"].startswith("CF-") for i in items)

    def test_severity_heuristics(self):
        items = parse_custom_rss(RSS_FIXTURE, "Acme Feed")
        by_title = {i["title"]: i for i in items}
        assert by_title["Apache Log4j 2 RCE via JNDI lookups (Log4Shell)"]["severity"] == "HIGH"  # has CVE
        assert by_title["Ransomware campaign targeting Acme NAS devices"]["severity"] == "CRITICAL"
        assert by_title["Acme quarterly patch notes"]["severity"] == "MEDIUM"

    def test_cves_extracted_and_html_stripped(self):
        items = parse_custom_rss(RSS_FIXTURE, "Acme Feed")
        rce = next(i for i in items if "RCE" in i["title"])
        assert rce["cve_ids"] == ["CVE-2021-44228"]
        assert "<b>" not in rce["summary"]

    def test_pubdate_parsed(self):
        items = parse_custom_rss(RSS_FIXTURE, "Acme Feed")
        rce = next(i for i in items if "RCE" in i["title"])
        assert str(rce["published_date"]) == "2026-06-07"

    def test_advisory_id_stable_across_parses(self):
        a = parse_custom_rss(RSS_FIXTURE, "Acme Feed")
        b = parse_custom_rss(RSS_FIXTURE, "Acme Feed")
        assert [i["advisory_id"] for i in a] == [i["advisory_id"] for i in b]

    def test_advisory_id_differs_per_feed_name(self):
        a = parse_custom_rss(RSS_FIXTURE, "Feed One")
        b = parse_custom_rss(RSS_FIXTURE, "Feed Two")
        assert a[0]["advisory_id"] != b[0]["advisory_id"]

    def test_non_https_source_link_dropped(self):
        items = parse_custom_rss(RSS_FIXTURE, "Acme Feed")
        notes = next(i for i in items if "patch notes" in i["title"])
        assert notes["source_url"] == ""  # javascript: link sanitized away

    def test_xxe_payload_rejected(self):
        evil = (
            '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
            "<rss><channel><item><title>Evil &x;</title></item></channel></rss>"
        )
        with pytest.raises(CustomFeedError):
            parse_custom_rss(evil, "Evil Feed")

    def test_invalid_xml_rejected(self):
        with pytest.raises(CustomFeedError):
            parse_custom_rss("this is not xml <", "Broken Feed")


class TestSettingsValidation:
    def _one(self, **kw):
        base = {"name": "Acme", "url": "https://feeds.example.com/all.xml", "format": "rss"}
        base.update(kw)
        return [base]

    def test_valid_entries_normalized(self):
        out = validate_feed_entries(self._one(format="RSS ", name="  Acme "))
        assert out == [{"name": "Acme", "url": "https://feeds.example.com/all.xml", "format": "rss"}]

    def test_missing_name_rejected(self):
        with pytest.raises(ValueError, match="name is required"):
            validate_feed_entries(self._one(name=""))

    def test_bad_format_rejected(self):
        with pytest.raises(ValueError, match="format must be one of"):
            validate_feed_entries(self._one(format="atom"))

    def test_http_url_rejected(self):
        with pytest.raises(ValueError, match="must use https"):
            validate_feed_entries(self._one(url="http://feeds.example.com/all.xml"))

    def test_credentials_in_url_rejected(self):
        with pytest.raises(ValueError, match="credentials"):
            validate_feed_entries(self._one(url="https://user:pw@feeds.example.com/all.xml"))

    def test_private_ip_literal_rejected(self):
        with pytest.raises(ValueError, match="private"):
            validate_feed_entries(self._one(url="https://192.168.1.10/feed.xml"))

    def test_loopback_ip_literal_rejected(self):
        with pytest.raises(ValueError, match="loopback"):
            validate_feed_entries(self._one(url="https://127.0.0.1/feed.xml"))

    def test_duplicate_names_rejected(self):
        entries = self._one() + self._one(url="https://other.example.com/x.xml", name="acme")
        with pytest.raises(ValueError, match="duplicate feed name"):
            validate_feed_entries(entries)

    def test_too_many_feeds_rejected(self):
        entries = [
            {"name": f"Feed {i}", "url": f"https://f{i}.example.com/a.xml", "format": "rss"}
            for i in range(feeds_custom.MAX_FEEDS + 1)
        ]
        with pytest.raises(ValueError, match="At most"):
            validate_feed_entries(entries)

    def test_overlong_name_rejected(self):
        with pytest.raises(ValueError, match="exceeds"):
            validate_feed_entries(self._one(name="x" * (feeds_custom.MAX_NAME_LEN + 1)))

    def test_missing_url_rejected(self):
        with pytest.raises(ValueError, match="URL is required"):
            validate_feed_entries(self._one(url=""))


class TestSsrfGuard:
    """Every rejection path of the resolve-before-connect guard."""

    @pytest.mark.parametrize("ip,reason", [
        ("127.0.0.1", "loopback"),
        ("10.0.0.5", "private"),
        ("172.16.3.4", "private"),
        ("192.168.0.1", "private"),
        ("169.254.169.254", "link-local/metadata"),  # cloud metadata endpoint
        ("0.0.0.0", "unspecified"),
        ("224.0.0.1", "multicast"),
        ("240.0.0.1", "reserved"),
    ])
    def test_ipv4_ranges_rejected(self, monkeypatch, ip, reason):
        monkeypatch.setattr(feeds_custom.socket, "getaddrinfo", lambda *a, **k: _addrinfo(ip))
        with pytest.raises(CustomFeedError, match=reason.replace("/", ".")):
            assert_public_host("evil.example.com")

    @pytest.mark.parametrize("ip", ["::1", "fe80::1", "fc00::1", "::"])
    def test_ipv6_ranges_rejected(self, monkeypatch, ip):
        monkeypatch.setattr(feeds_custom.socket, "getaddrinfo", lambda *a, **k: _addrinfo(ip))
        with pytest.raises(CustomFeedError):
            assert_public_host("evil.example.com")

    def test_ipv4_mapped_ipv6_bypass_rejected(self):
        assert _ip_rejection(ipaddress.ip_address("::ffff:10.0.0.1")) == "private"
        assert _ip_rejection(ipaddress.ip_address("::ffff:127.0.0.1")) == "loopback"

    def test_any_bad_address_in_answer_set_rejects(self, monkeypatch):
        answers = _addrinfo("93.184.216.34") + _addrinfo("10.0.0.5")
        monkeypatch.setattr(feeds_custom.socket, "getaddrinfo", lambda *a, **k: answers)
        with pytest.raises(CustomFeedError, match="private"):
            assert_public_host("rebind.example.com")

    def test_public_address_accepted(self, monkeypatch):
        monkeypatch.setattr(feeds_custom.socket, "getaddrinfo",
                            lambda *a, **k: _addrinfo("93.184.216.34"))
        assert_public_host("feeds.example.com")  # must not raise

    def test_dns_failure_rejected(self, monkeypatch):
        def boom(*a, **k):
            raise OSError("no such host")
        monkeypatch.setattr(feeds_custom.socket, "getaddrinfo", boom)
        with pytest.raises(CustomFeedError, match="DNS resolution failed"):
            assert_public_host("nxdomain.example.com")

    def test_empty_dns_answer_rejected(self, monkeypatch):
        monkeypatch.setattr(feeds_custom.socket, "getaddrinfo", lambda *a, **k: [])
        with pytest.raises(CustomFeedError, match="no addresses"):
            assert_public_host("empty.example.com")

    def test_ip_literal_checked_without_dns(self, monkeypatch):
        def boom(*a, **k):
            raise AssertionError("getaddrinfo must not be called for IP literals")
        monkeypatch.setattr(feeds_custom.socket, "getaddrinfo", boom)
        with pytest.raises(CustomFeedError, match="loopback"):
            assert_public_host("127.0.0.1")

    def test_fetch_rejects_private_host_before_connecting(self, monkeypatch):
        monkeypatch.setattr(feeds_custom.socket, "getaddrinfo",
                            lambda *a, **k: _addrinfo("192.168.7.7"))

        def no_connect(*a, **k):
            raise AssertionError("must not connect when DNS check fails")
        monkeypatch.setattr(feeds_custom.httpx, "Client", no_connect)
        with pytest.raises(CustomFeedError, match="private"):
            fetch_custom_feed({"name": "Bad", "url": "https://internal.example.com/f.xml", "format": "rss"})


class TestHostLock:
    def test_cross_host_url_rejected(self):
        with pytest.raises(CustomFeedError, match="leaves the configured host"):
            _require_locked_url("https://other.example.com/doc.json", "feeds.example.com")

    def test_http_url_rejected(self):
        with pytest.raises(CustomFeedError, match="must be https"):
            _require_locked_url("http://feeds.example.com/doc.json", "feeds.example.com")

    def test_credentials_rejected(self):
        with pytest.raises(CustomFeedError, match="credentials"):
            _require_locked_url("https://a:b@feeds.example.com/doc.json", "feeds.example.com")

    def test_same_host_accepted(self):
        _require_locked_url("https://FEEDS.example.com/doc.json", "feeds.example.com")


class _FakeResponse:
    def __init__(self, body: bytes, status_code=200, content_type="application/xml"):
        self.body = body
        self.status_code = status_code
        self.headers = {"content-type": content_type}
        self.charset_encoding = "utf-8"

    @property
    def is_redirect(self):
        return 300 <= self.status_code < 400

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("error", request=None, response=None)

    def iter_bytes(self):
        chunk = 1024 * 64
        for i in range(0, len(self.body), chunk):
            yield self.body[i:i + chunk]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeClient:
    def __init__(self, responses: dict[str, _FakeResponse]):
        self.responses = responses

    def stream(self, method, url):
        if url not in self.responses:
            raise AssertionError(f"unexpected fetch: {url}")
        return self.responses[url]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestRssFetchHardening:
    URL = "https://feeds.example.com/all.xml"
    FEED = {"name": "Acme Feed", "url": URL, "format": "rss"}

    def _patch(self, monkeypatch, response: _FakeResponse):
        monkeypatch.setattr(feeds_custom, "assert_public_host", lambda host: None)
        monkeypatch.setattr(
            feeds_custom.httpx, "Client",
            lambda *a, **k: _FakeClient({self.URL: response}),
        )

    def test_happy_path_returns_advisories(self, monkeypatch):
        self._patch(monkeypatch, _FakeResponse(RSS_FIXTURE.encode()))
        items = fetch_custom_feed(self.FEED)
        assert len(items) == 3
        assert items[0]["advisory_id"].startswith("CF-")

    def test_redirect_rejected(self, monkeypatch):
        self._patch(monkeypatch, _FakeResponse(b"", status_code=301))
        with pytest.raises(CustomFeedError, match="Redirects are not followed"):
            fetch_custom_feed(self.FEED)

    def test_body_cap_enforced(self, monkeypatch):
        huge = b"<rss>" + b"x" * (feeds_custom._MAX_BODY_BYTES + 1)
        self._patch(monkeypatch, _FakeResponse(huge))
        with pytest.raises(CustomFeedError, match="exceeded"):
            fetch_custom_feed(self.FEED)

    def test_http_error_wrapped(self, monkeypatch):
        self._patch(monkeypatch, _FakeResponse(b"", status_code=500))
        with pytest.raises(CustomFeedError):
            fetch_custom_feed(self.FEED)


class TestCsafWalk:
    HOST = "psirt.example.com"
    META = f"https://{HOST}/.well-known/csaf/provider-metadata.json"

    def _provider(self, feed_url):
        return {"distributions": [{"rolie": {"feeds": [
            {"tlp_label": "WHITE", "url": feed_url},
        ]}}]}

    def _rolie(self, doc_urls):
        return {"feed": {"entry": [
            {"updated": "2026-05-01", "link": [{"rel": "self", "href": u}]}
            for u in doc_urls
        ]}}

    def _patch_json(self, monkeypatch, by_url: dict):
        def fake_safe_json(client, url):
            if url not in by_url:
                raise AssertionError(f"unexpected fetch: {url}")
            return by_url[url]
        monkeypatch.setattr(feeds_custom, "_safe_json", fake_safe_json)

    def test_happy_path_parses_csaf_documents(self, monkeypatch):
        feed_url = f"https://{self.HOST}/csaf/feed.json"
        doc_url = f"https://{self.HOST}/csaf/acme-sa-2026-001.json"
        self._patch_json(monkeypatch, {
            self.META: self._provider(feed_url),
            feed_url: self._rolie([doc_url]),
            doc_url: CSAF_DOC,
        })
        out = _walk_csaf_provider(None, self.META, self.HOST)
        assert len(out) == 1
        assert out[0]["advisory_id"] == "ACME-SA-2026-001"
        assert out[0]["severity"] == "CRITICAL"
        assert out[0]["affected_vendor"] == "Acme"

    def test_cross_host_rolie_feed_rejected(self, monkeypatch):
        self._patch_json(monkeypatch, {
            self.META: self._provider("https://evil.example.com/feed.json"),
        })
        with pytest.raises(CustomFeedError, match="No public ROLIE feed"):
            _walk_csaf_provider(None, self.META, self.HOST)

    def test_cross_host_document_skipped(self, monkeypatch):
        feed_url = f"https://{self.HOST}/csaf/feed.json"
        self._patch_json(monkeypatch, {
            self.META: self._provider(feed_url),
            feed_url: self._rolie(["https://evil.example.com/doc.json"]),
        })
        assert _walk_csaf_provider(None, self.META, self.HOST) == []

    def test_broken_document_isolated(self, monkeypatch):
        feed_url = f"https://{self.HOST}/csaf/feed.json"
        bad_url = f"https://{self.HOST}/csaf/bad.json"
        good_url = f"https://{self.HOST}/csaf/good.json"
        by_url = {
            self.META: self._provider(feed_url),
            feed_url: self._rolie([bad_url, good_url]),
            good_url: CSAF_DOC,
        }

        def fake_safe_json(client, url):
            if url == bad_url:
                raise feeds_custom.IcsFeedError("malformed")
            return by_url[url]
        monkeypatch.setattr(feeds_custom, "_safe_json", fake_safe_json)
        out = _walk_csaf_provider(None, self.META, self.HOST)
        assert [a["advisory_id"] for a in out] == ["ACME-SA-2026-001"]


class TestFaultIsolation:
    def test_one_broken_feed_does_not_kill_the_rest(self, monkeypatch):
        def fake_fetch(feed):
            if feed["name"] == "Broken":
                raise CustomFeedError("Broken: DNS resolution failed")
            return [{"advisory_id": "CF-OK", "title": "ok"}]
        monkeypatch.setattr(feeds_custom, "fetch_custom_feed", fake_fetch)
        advisories, errors = fetch_custom_feeds([
            {"name": "Broken", "url": "https://a.example.com/x", "format": "rss"},
            {"name": "Working", "url": "https://b.example.com/x", "format": "rss"},
        ])
        assert len(errors) == 1 and "Broken" in errors[0]
        assert advisories == [({"advisory_id": "CF-OK", "title": "ok"}, "Working")]


class TestRefreshIntegration:
    def _configure(self, db, org, feeds):
        settings = dict(org.settings or {})
        settings["custom_feeds"] = feeds
        org.settings = settings
        db.commit()

    def test_refresh_pulls_custom_feeds_with_source_label(self, db, seeded, monkeypatch):
        from models import IcsAdvisory
        from services import feed_refresh
        from services.feed_refresh import refresh_feeds_for_org

        org = seeded["org"]
        self._configure(db, org, [
            {"name": "Acme PSIRT", "url": "https://feeds.example.com/all.xml", "format": "rss"},
        ])
        advisories = [(a, "Acme PSIRT") for a in parse_custom_rss(RSS_FIXTURE, "Acme PSIRT")]
        monkeypatch.setattr(feed_refresh, "fetch_custom_feeds", lambda cfg: (advisories, []))

        result = refresh_feeds_for_org(db, org.id, actor_id=None, actor_username="feed-scheduler")
        assert result["feed_errors"] == []
        assert "CUSTOM" in result["feed_source"]
        custom_rows = db.query(IcsAdvisory).filter(
            IcsAdvisory.organization_id == org.id,
            IcsAdvisory.source == "Acme PSIRT",
        ).all()
        assert len(custom_rows) == 3
        assert all(r.advisory_id.startswith("CF-") for r in custom_rows)

    def test_custom_feed_error_reported_but_not_fatal(self, db, seeded, monkeypatch):
        from models import IcsAdvisory
        from services import feed_refresh
        from services.feed_refresh import refresh_feeds_for_org

        org = seeded["org"]
        self._configure(db, org, [
            {"name": "Down Feed", "url": "https://down.example.com/all.xml", "format": "rss"},
        ])
        monkeypatch.setattr(
            feed_refresh, "fetch_custom_feeds",
            lambda cfg: ([], ["Down Feed: DNS resolution failed"]),
        )
        result = refresh_feeds_for_org(db, org.id, actor_id=None, actor_username="feed-scheduler")
        assert result["feed_errors"] == ["Down Feed: DNS resolution failed"]
        # the bundled fixture feeds still landed
        assert db.query(IcsAdvisory).filter(IcsAdvisory.organization_id == org.id).count() > 0

    def test_no_custom_feeds_configured_is_a_noop(self, db, seeded, monkeypatch):
        from services import feed_refresh
        from services.feed_refresh import refresh_feeds_for_org

        def boom(cfg):
            raise AssertionError("fetch_custom_feeds must not be called when none configured")
        monkeypatch.setattr(feed_refresh, "fetch_custom_feeds", boom)
        result = refresh_feeds_for_org(db, seeded["org"].id, actor_id=None, actor_username="x")
        assert "CUSTOM" not in result["feed_source"]

    def test_refresh_is_idempotent_for_custom_advisories(self, db, seeded, monkeypatch):
        from models import IcsAdvisory
        from services import feed_refresh
        from services.feed_refresh import refresh_feeds_for_org

        org = seeded["org"]
        self._configure(db, org, [
            {"name": "Acme PSIRT", "url": "https://feeds.example.com/all.xml", "format": "rss"},
        ])
        monkeypatch.setattr(
            feed_refresh, "fetch_custom_feeds",
            lambda cfg: ([(a, "Acme PSIRT") for a in parse_custom_rss(RSS_FIXTURE, "Acme PSIRT")], []),
        )
        refresh_feeds_for_org(db, org.id, actor_id=None, actor_username="x")
        count1 = db.query(IcsAdvisory).count()
        refresh_feeds_for_org(db, org.id, actor_id=None, actor_username="x")
        assert db.query(IcsAdvisory).count() == count1


class TestCustomFeedsEndpoints:
    VALID = {"feeds": [
        {"name": "Acme PSIRT", "url": "https://feeds.example.com/all.xml", "format": "rss"},
        {"name": "Contoso CSAF", "url": "https://csaf.contoso.example/provider-metadata.json", "format": "csaf"},
    ]}

    def test_fixed_path_not_shadowed_by_advisory_id(self, auth_client):
        # the /{advisory_id} shadowing bug: /custom-feeds must NOT 422
        client, seeded, csrf = auth_client
        r = client.get("/api/advisories/custom-feeds")
        assert r.status_code == 200
        assert r.json() == {"feeds": []}

    def test_put_then_get_roundtrip(self, auth_client, db):
        client, seeded, csrf = auth_client
        r = client.put("/api/advisories/custom-feeds", json=self.VALID,
                       headers={"X-CSRF-Token": csrf} if csrf else {})
        assert r.status_code == 200
        assert [f["name"] for f in r.json()["feeds"]] == ["Acme PSIRT", "Contoso CSAF"]

        r2 = client.get("/api/advisories/custom-feeds")
        assert r2.json()["feeds"] == r.json()["feeds"]

        org = db.query(Organization).filter(Organization.id == seeded["org"].id).first()
        db.refresh(org)
        assert len(org.settings["custom_feeds"]) == 2

    def test_put_is_audit_logged(self, auth_client, db):
        client, seeded, csrf = auth_client
        client.put("/api/advisories/custom-feeds", json=self.VALID,
                   headers={"X-CSRF-Token": csrf} if csrf else {})
        entry = db.query(AuditEntry).filter(
            AuditEntry.organization_id == seeded["org"].id,
            AuditEntry.action == "UPDATE",
            AuditEntry.entity_type == "organization",
        ).order_by(AuditEntry.id.desc()).first()
        assert entry is not None
        assert "custom advisory feeds" in entry.summary
        assert "Acme PSIRT" in entry.summary

    def test_put_invalid_url_rejected(self, auth_client):
        client, seeded, csrf = auth_client
        bad = {"feeds": [{"name": "X", "url": "http://feeds.example.com/a.xml", "format": "rss"}]}
        r = client.put("/api/advisories/custom-feeds", json=bad,
                       headers={"X-CSRF-Token": csrf} if csrf else {})
        assert r.status_code == 422
        assert "https" in r.json()["detail"]

    def test_put_invalid_format_rejected(self, auth_client):
        client, seeded, csrf = auth_client
        bad = {"feeds": [{"name": "X", "url": "https://feeds.example.com/a.xml", "format": "atom"}]}
        r = client.put("/api/advisories/custom-feeds", json=bad,
                       headers={"X-CSRF-Token": csrf} if csrf else {})
        assert r.status_code == 422

    def test_put_private_ip_rejected(self, auth_client):
        client, seeded, csrf = auth_client
        bad = {"feeds": [{"name": "X", "url": "https://10.1.2.3/a.xml", "format": "rss"}]}
        r = client.put("/api/advisories/custom-feeds", json=bad,
                       headers={"X-CSRF-Token": csrf} if csrf else {})
        assert r.status_code == 422

    def test_put_clears_feeds(self, auth_client):
        client, seeded, csrf = auth_client
        headers = {"X-CSRF-Token": csrf} if csrf else {}
        client.put("/api/advisories/custom-feeds", json=self.VALID, headers=headers)
        r = client.put("/api/advisories/custom-feeds", json={"feeds": []}, headers=headers)
        assert r.status_code == 200
        assert client.get("/api/advisories/custom-feeds").json() == {"feeds": []}

    def test_non_admin_cannot_read_or_write(self, client, db, seeded):
        db.add(User(organization_id=seeded["org"].id, username="cm1",
                    password_hash=hash_password("cmpassword123!"),
                    role="compliance_manager"))
        db.commit()
        r = client.post("/api/auth/login", json={"username": "cm1", "password": "cmpassword123!"})
        assert r.status_code == 200
        csrf = client.cookies.get("universal_csrf")
        assert client.get("/api/advisories/custom-feeds").status_code == 403
        r2 = client.put("/api/advisories/custom-feeds", json={"feeds": []},
                        headers={"X-CSRF-Token": csrf} if csrf else {})
        assert r2.status_code == 403

    def test_feed_status_lists_custom_sources(self, auth_client):
        client, seeded, csrf = auth_client
        client.put("/api/advisories/custom-feeds", json=self.VALID,
                   headers={"X-CSRF-Token": csrf} if csrf else {})
        r = client.get("/api/advisories/feed-status")
        assert r.status_code == 200
        feeds = r.json()["custom_feeds"]
        assert [f["name"] for f in feeds] == ["Acme PSIRT", "Contoso CSAF"]
        assert feeds[0]["format"] == "rss"

"""KNOWN-4 (explicit opt-in outbound proxy) and KNOWN-6 (CISA feed host lock +
SSRF guard). Uses the fake-network harness from test_ssrf_pinning."""
from __future__ import annotations

import httpx
import pytest

from config import settings
from services import ics_advisory_cisa as cisa
from services.safe_http import STRICT, guarded_client
from tests.test_ssrf_pinning import PUBLIC, _http, _json, net  # noqa: F401  (fixture)

PROXY_IP = "10.0.0.9"   # an on-prem proxy is fine: it is operator-configured


class TestOutboundProxy:
    @pytest.fixture(autouse=True)
    def _proxy(self, monkeypatch):
        monkeypatch.setattr(settings, "outbound_proxy", "http://proxy.corp.example:3128")

    def test_requests_go_through_the_configured_proxy(self, net):
        n = net({"proxy.corp.example": [[PROXY_IP]], "feeds.example.com": [[PUBLIC]]},
                {PROXY_IP: lambda req: _json({"ok": True})})
        with guarded_client(STRICT, https_only=False) as c:
            r = c.get("http://feeds.example.com/feed.json")
        assert r.json() == {"ok": True}
        assert n.reached == [PROXY_IP]
        assert n.requests[0][1].startswith(b"GET http://feeds.example.com/feed.json")

    @pytest.mark.parametrize("bad", ["127.0.0.1", "169.254.169.254", "10.1.2.3"])
    def test_target_is_still_checked_before_the_proxy_sees_it(self, net, bad):
        n = net({"proxy.corp.example": [[PROXY_IP]], "feeds.example.com": [[bad]]},
                {PROXY_IP: lambda req: _json({"leak": True})})
        with guarded_client(STRICT, https_only=False) as c, pytest.raises(httpx.ConnectError):
            c.get("http://feeds.example.com/feed.json")
        assert n.reached == []

    def test_standard_proxy_env_is_still_ignored_without_opt_in(self, net, monkeypatch):
        monkeypatch.setattr(settings, "outbound_proxy", "")
        n = net({"feeds.example.com": [[PUBLIC]]}, {PUBLIC: lambda req: _json({"direct": True})})
        monkeypatch.setenv("HTTPS_PROXY", "http://proxy.corp.example:3128")
        monkeypatch.setenv("HTTP_PROXY", "http://proxy.corp.example:3128")
        with guarded_client(STRICT, https_only=False) as c:
            assert c.get("http://feeds.example.com/x").json() == {"direct": True}
        assert n.reached == [PUBLIC]


class TestCisaFeed:
    def test_redirect_off_cisa_gov_is_refused(self, net):
        redirect = _http("302 Found", b"", {"Location": "https://attacker.example/x.json"})
        n = net({"www.cisa.gov": [[PUBLIC]], "attacker.example": [["198.51.100.66"]]},
                {PUBLIC: lambda req: redirect, "198.51.100.66": lambda req: _json({})})
        with pytest.raises((cisa.IcsFeedError, httpx.HTTPError)):
            cisa.fetch_cisa_advisories()
        assert "198.51.100.66" not in n.reached

    def test_cisa_name_resolving_to_metadata_is_refused(self, net):
        n = net({"www.cisa.gov": [["169.254.169.254"]]}, {"169.254.169.254": lambda req: _json({})})
        with pytest.raises((cisa.IcsFeedError, httpx.HTTPError)):
            cisa.fetch_cisa_advisories()
        assert n.reached == []


class TestProxyOnlyDns:
    """R2SEC-10: with a proxy configured, a name local DNS cannot resolve goes
    to the proxy (which resolves it) instead of failing before the proxy."""

    @pytest.fixture(autouse=True)
    def _proxy(self, monkeypatch):
        monkeypatch.setattr(settings, "outbound_proxy", "http://proxy.corp.example:3128")

    def test_unresolvable_name_is_forwarded_to_the_proxy(self, net):
        n = net({"proxy.corp.example": [[PROXY_IP]]},   # no local answer for feeds.example.com
                {PROXY_IP: lambda req: _json({"via": "proxy"})})
        with guarded_client(STRICT, https_only=False) as c:
            assert c.get("http://feeds.example.com/feed.json").json() == {"via": "proxy"}
        assert n.reached == [PROXY_IP]

    @pytest.mark.parametrize("url", ["http://127.0.0.1/x", "http://169.254.169.254/latest/meta-data"])
    def test_literal_private_ip_is_still_refused(self, net, url):
        n = net({"proxy.corp.example": [[PROXY_IP]]}, {PROXY_IP: lambda req: _json({"leak": True})})
        with guarded_client(STRICT, https_only=False) as c, pytest.raises(httpx.ConnectError):
            c.get(url)
        assert n.reached == []

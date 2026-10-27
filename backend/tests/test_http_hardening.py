"""SECCODE-20 (CSP/HSTS) and SECCODE-21 (Host check against DNS rebinding)."""
from __future__ import annotations

import pytest

from config import settings


def _get(client, host, path="/api/auth/status"):
    return client.get(path, headers={"Host": host})


class TestHostCheck:
    @pytest.fixture(autouse=True)
    def _defaults(self, monkeypatch):
        monkeypatch.setattr(settings, "allowed_hosts", [])
        monkeypatch.setattr(settings, "trust_xff", False)
        monkeypatch.setattr(settings, "cors_origins", ["http://localhost:3000"])

    def test_rebinding_host_is_refused(self, client):
        r = _get(client, "attacker.example:8001")
        assert r.status_code == 400
        assert "ATHORIZE_ALLOWED_HOSTS" in r.text

    @pytest.mark.parametrize("host", ["localhost", "localhost:8001", "127.0.0.1:8053", "[::1]:8001", "LOCALHOST"])
    def test_local_names_work_by_default(self, client, host):
        """Desktop launcher (127.0.0.1), run-eval.sh (localhost) and the Docker
        healthcheck (127.0.0.1) keep working with no configuration."""
        assert _get(client, host).status_code == 200

    def test_docker_healthcheck_path(self, client):
        assert _get(client, "127.0.0.1:8001", "/api/health").status_code == 200

    def test_configured_and_cors_hosts_are_allowed(self, client, monkeypatch):
        monkeypatch.setattr(settings, "allowed_hosts", ["athorize.example.internal"])
        monkeypatch.setattr(settings, "cors_origins", ["https://ui.example.internal:8443"])
        assert _get(client, "athorize.example.internal").status_code == 200
        assert _get(client, "ui.example.internal").status_code == 200
        assert _get(client, "other.example.internal").status_code == 400

    def test_star_disables(self, client, monkeypatch):
        monkeypatch.setattr(settings, "allowed_hosts", ["*"])
        assert _get(client, "anything.example").status_code == 200

    def test_existing_proxy_installs_keep_working_until_configured(self, client, monkeypatch):
        """INSTALL.md proxy installs set ATHORIZE_TRUST_XFF=1 but no allowed
        hosts yet; they must not break on upgrade (a warning is logged)."""
        monkeypatch.setattr(settings, "trust_xff", True)
        assert _get(client, "compliance.internal.example.com").status_code == 200
        monkeypatch.setattr(settings, "allowed_hosts", ["compliance.internal.example.com"])
        assert _get(client, "evil.example").status_code == 400


class TestSecurityHeaders:
    def test_csp_on_api_responses(self, client):
        csp = client.get("/api/health").headers.get("content-security-policy", "")
        for d in ("default-src 'self'", "frame-ancestors 'none'", "object-src 'none'", "base-uri 'self'"):
            assert d in csp

    def test_hsts_only_over_https(self, client, monkeypatch):
        assert "strict-transport-security" not in client.get("/api/health").headers
        monkeypatch.setattr(settings, "trust_xff", True)
        r = client.get("/api/health", headers={"X-Forwarded-Proto": "https"})
        assert "max-age=" in r.headers.get("strict-transport-security", "")

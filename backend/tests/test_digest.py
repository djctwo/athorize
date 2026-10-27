"""Email digest: builder structure, rendering, SMTP gating, endpoints."""
import pytest

from services import digest as digest_svc
from services import email as email_svc


def _h(csrf):
    return {"X-CSRF-Token": csrf} if csrf else {}


class TestBuilder:
    def test_empty_org_has_no_content(self, db, seeded):
        d = digest_svc.build_digest(db, seeded["org"].id)
        assert set(d["counts"]) == {
            "overdue_findings", "due_soon_findings", "expired_evidence",
            "expiring_evidence", "overdue_cadences",
        }
        assert all(v == 0 for v in d["counts"].values())
        assert digest_svc.has_content(d) is False
        assert "all clear" in digest_svc.subject(d)

    def test_render_includes_overdue_finding(self):
        d = {
            "organization": "Acme", "generated": "2026-06-19",
            "overdue_findings": [{"title": "Patch SCADA", "severity": "HIGH", "system": "SCADA", "due_date": "2026-06-01", "owner": "Pat", "days": -18}],
            "due_soon_findings": [], "expired_evidence": [], "expiring_evidence": [], "overdue_cadences": [],
            "counts": {"overdue_findings": 1, "due_soon_findings": 0, "expired_evidence": 0, "expiring_evidence": 0, "overdue_cadences": 0},
        }
        assert digest_svc.has_content(d) is True
        html = digest_svc.render_html(d)
        assert "Patch SCADA" in html and "Compliance digest" in html
        text = digest_svc.render_text(d)
        assert "OVERDUE" in text and "Patch SCADA" in text
        assert "need attention" in digest_svc.subject(d)

    def test_html_escapes_user_content(self):
        d = {
            "organization": "<b>Acme</b>", "generated": "2026-06-19",
            "overdue_findings": [{"title": "<img src=x onerror=alert(1)>", "severity": "HIGH", "system": "S", "due_date": "2026-06-01", "owner": "o", "days": -1}],
            "due_soon_findings": [], "expired_evidence": [], "expiring_evidence": [], "overdue_cadences": [],
            "counts": {"overdue_findings": 1, "due_soon_findings": 0, "expired_evidence": 0, "expiring_evidence": 0, "overdue_cadences": 0},
        }
        html = digest_svc.render_html(d)
        assert "<img src=x onerror=alert(1)>" not in html
        assert "&lt;img src=x onerror=alert(1)&gt;" in html
        assert "<b>Acme</b>" not in html  # org name escaped too


    def test_subject_counts_due_soon_and_expiring(self):
        # A digest with only upcoming items must NOT say "all clear".
        d = {"counts": {"overdue_findings": 0, "due_soon_findings": 5,
                        "expired_evidence": 0, "expiring_evidence": 9, "overdue_cadences": 0}}
        assert "all clear" not in digest_svc.subject(d)
        assert "14 item(s)" in digest_svc.subject(d)


class TestEmailGating:
    def test_not_configured_by_default(self):
        assert email_svc.is_configured() is False

    def test_send_raises_when_unconfigured(self):
        with pytest.raises(email_svc.EmailNotConfigured):
            email_svc.send_email(["a@b.com"], "s", "<p>h</p>", "t")

    def test_refuses_credentials_over_plaintext(self, monkeypatch):
        from config import settings
        monkeypatch.setattr(settings, "smtp_host", "mail.local")
        monkeypatch.setattr(settings, "smtp_from", "d@local")
        monkeypatch.setattr(settings, "smtp_user", "bob")
        monkeypatch.setattr(settings, "smtp_password", "secret")
        monkeypatch.setattr(settings, "smtp_use_tls", False)
        with pytest.raises(email_svc.EmailNotConfigured):
            email_svc.send_email(["a@b.com"], "s", "<p>h</p>", "t")


class TestEndpoints:
    def test_preview_returns_html(self, auth_client):
        client, _seeded, _csrf = auth_client
        r = client.get("/api/digest/preview")
        assert r.status_code == 200
        assert "html" in r.json() and "has_content" in r.json()

    def test_config_reports_smtp_off(self, auth_client):
        client, _seeded, _csrf = auth_client
        assert client.get("/api/digest/config").json()["smtp_configured"] is False

    def test_send_test_requires_smtp(self, auth_client):
        client, _seeded, csrf = auth_client
        r = client.post("/api/digest/send-test", headers=_h(csrf))
        assert r.status_code == 400

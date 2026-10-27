"""Comments / @mentions: CRUD, org isolation, system-scoped access via the
parent entity, mention parsing, delete permissions, and mention emails."""
import pytest

from models import ControlImplementation, Finding, Organization, System, SystemAssignment, User
from services.auth import hash_password


def _h(csrf):
    return {"X-CSRF-Token": csrf} if csrf else {}


def _login(client, username, password):
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200
    return client.cookies.get("universal_csrf")


@pytest.fixture
def comment_env(db, seeded):
    """A system with a finding + control implementation, and a teammate 'sam'."""
    org = seeded["org"]
    system = System(organization_id=org.id, name="Corp ERP", acronym="ERP")
    db.add(system)
    db.flush()
    finding = Finding(organization_id=org.id, system_id=system.id, framework_id="test-fw",
                      control_id="AC-1", title="Weak passwords", severity="HIGH", status="OPEN")
    impl = ControlImplementation(system_id=system.id, framework_id="test-fw",
                                 control_id="AC-2", implementation_status="IMPLEMENTED")
    sam = User(organization_id=org.id, username="sam",
               password_hash=hash_password("samsampass123!"),
               email="sam@test.com", display_name="Sam Teammate", role="assessor")
    db.add_all([finding, impl, sam])
    db.commit()
    return {"org": org, "system": system, "finding": finding, "impl": impl, "sam": sam}


class TestCommentCrud:
    def test_create_list_on_finding(self, auth_client, comment_env):
        client, seeded, csrf = auth_client
        fid = comment_env["finding"].id
        r = client.post("/api/comments", json={
            "entity_type": "finding", "entity_id": fid, "body": "First look done.",
        }, headers=_h(csrf))
        assert r.status_code == 200
        created = r.json()
        assert created["body"] == "First look done."
        assert created["author_name"] == "Test Admin"
        assert created["mentions"] == []

        rows = client.get(f"/api/comments?entity_type=finding&entity_id={fid}").json()
        assert [c["body"] for c in rows] == ["First look done."]

    def test_create_list_on_control_implementation(self, auth_client, comment_env):
        client, _seeded, csrf = auth_client
        iid = comment_env["impl"].id
        r = client.post("/api/comments", json={
            "entity_type": "control_implementation", "entity_id": iid,
            "body": "Narrative needs the tooling name.",
        }, headers=_h(csrf))
        assert r.status_code == 200
        rows = client.get(
            f"/api/comments?entity_type=control_implementation&entity_id={iid}"
        ).json()
        assert len(rows) == 1 and rows[0]["entity_type"] == "control_implementation"

    def test_body_cap_and_empty_rejected(self, auth_client, comment_env):
        client, _seeded, csrf = auth_client
        fid = comment_env["finding"].id
        r = client.post("/api/comments", json={
            "entity_type": "finding", "entity_id": fid, "body": "x" * 5001,
        }, headers=_h(csrf))
        assert r.status_code == 422
        r = client.post("/api/comments", json={
            "entity_type": "finding", "entity_id": fid, "body": "   ",
        }, headers=_h(csrf))
        assert r.status_code == 422

    def test_invalid_entity_type_rejected(self, auth_client, comment_env):
        client, _seeded, csrf = auth_client
        r = client.post("/api/comments", json={
            "entity_type": "evidence", "entity_id": 1, "body": "hi",
        }, headers=_h(csrf))
        assert r.status_code == 422

    def test_missing_parent_404(self, auth_client, comment_env):
        client, _seeded, csrf = auth_client
        r = client.post("/api/comments", json={
            "entity_type": "finding", "entity_id": 999999, "body": "hi",
        }, headers=_h(csrf))
        assert r.status_code == 404
        assert client.get("/api/comments?entity_type=finding&entity_id=999999").status_code == 404

    def test_comment_create_and_delete_audited(self, auth_client, comment_env):
        client, _seeded, csrf = auth_client
        fid = comment_env["finding"].id
        cid = client.post("/api/comments", json={
            "entity_type": "finding", "entity_id": fid, "body": "audit me",
        }, headers=_h(csrf)).json()["id"]
        client.delete(f"/api/comments/{cid}", headers=_h(csrf))
        entries = client.get("/api/audit?entity_type=comment").json()
        actions = [e["action"] for e in entries]
        assert "CREATE" in actions and "DELETE" in actions


class TestOrgIsolation:
    @pytest.fixture
    def other_org(self, db):
        org2 = Organization(name="Other Co", slug="other-co")
        db.add(org2)
        db.flush()
        outsider = User(organization_id=org2.id, username="outsider",
                        password_hash=hash_password("outsiderpass123!"),
                        role="admin")
        db.add(outsider)
        db.commit()
        return {"org": org2, "outsider": outsider}

    def test_cross_org_parent_404(self, client, comment_env, other_org):
        csrf = _login(client, "outsider", "outsiderpass123!")
        fid = comment_env["finding"].id
        assert client.get(f"/api/comments?entity_type=finding&entity_id={fid}").status_code == 404
        r = client.post("/api/comments", json={
            "entity_type": "finding", "entity_id": fid, "body": "sneaky",
        }, headers=_h(csrf))
        assert r.status_code == 404
        iid = comment_env["impl"].id
        assert client.get(
            f"/api/comments?entity_type=control_implementation&entity_id={iid}"
        ).status_code == 404

    def test_cross_org_delete_404(self, auth_client, client, comment_env, other_org):
        c, _seeded, csrf = auth_client
        cid = c.post("/api/comments", json={
            "entity_type": "finding", "entity_id": comment_env["finding"].id, "body": "keep out",
        }, headers=_h(csrf)).json()["id"]
        csrf2 = _login(client, "outsider", "outsiderpass123!")
        assert client.delete(f"/api/comments/{cid}", headers=_h(csrf2)).status_code == 404


class TestSystemScoping:
    @pytest.fixture
    def scoped(self, db, seeded, comment_env):
        """An assessor assigned ONLY to a second system; comment_env's entities
        live on the first system, so they must be invisible to this user."""
        org = seeded["org"]
        sys_b = System(organization_id=org.id, name="Bravo", acronym="BRV")
        db.add(sys_b)
        db.flush()
        f_b = Finding(organization_id=org.id, system_id=sys_b.id, framework_id="test-fw",
                      control_id="AC-1", title="Bravo finding", severity="LOW", status="OPEN")
        scoped_user = User(organization_id=org.id, username="scopedc",
                           password_hash=hash_password("scopedcpass123!"), role="assessor")
        db.add_all([f_b, scoped_user])
        db.flush()
        db.add(SystemAssignment(user_id=scoped_user.id, system_id=sys_b.id))
        db.commit()
        return {"sys_b": sys_b, "finding_b": f_b, "user": scoped_user}

    def test_scoped_user_blocked_outside_assignment(self, client, comment_env, scoped):
        csrf = _login(client, "scopedc", "scopedcpass123!")
        fid = comment_env["finding"].id  # lives on the unassigned system
        assert client.get(f"/api/comments?entity_type=finding&entity_id={fid}").status_code == 404
        r = client.post("/api/comments", json={
            "entity_type": "finding", "entity_id": fid, "body": "not allowed",
        }, headers=_h(csrf))
        assert r.status_code == 404
        iid = comment_env["impl"].id
        assert client.get(
            f"/api/comments?entity_type=control_implementation&entity_id={iid}"
        ).status_code == 404

    def test_scoped_user_allowed_on_assigned_system(self, client, scoped):
        csrf = _login(client, "scopedc", "scopedcpass123!")
        fid = scoped["finding_b"].id
        r = client.post("/api/comments", json={
            "entity_type": "finding", "entity_id": fid, "body": "in scope",
        }, headers=_h(csrf))
        assert r.status_code == 200
        rows = client.get(f"/api/comments?entity_type=finding&entity_id={fid}").json()
        assert [c["body"] for c in rows] == ["in scope"]


class TestMentions:
    def test_mentions_parsed_case_insensitive(self, auth_client, comment_env):
        client, _seeded, csrf = auth_client
        fid = comment_env["finding"].id
        r = client.post("/api/comments", json={
            "entity_type": "finding", "entity_id": fid,
            "body": "Ping @SAM and @nobody-here about this.",
        }, headers=_h(csrf))
        assert r.status_code == 200
        assert r.json()["mentions"] == [comment_env["sam"].id]

    def test_mention_with_trailing_punctuation(self, auth_client, comment_env):
        client, _seeded, csrf = auth_client
        r = client.post("/api/comments", json={
            "entity_type": "finding", "entity_id": comment_env["finding"].id,
            "body": "Thanks @sam.",
        }, headers=_h(csrf))
        assert r.json()["mentions"] == [comment_env["sam"].id]

    def test_no_email_when_smtp_unconfigured(self, auth_client, comment_env, monkeypatch):
        import services.email as email_svc
        sent = []
        monkeypatch.setattr(email_svc, "send_email", lambda *a, **k: sent.append(a))
        client, _seeded, csrf = auth_client
        r = client.post("/api/comments", json={
            "entity_type": "finding", "entity_id": comment_env["finding"].id,
            "body": "hey @sam",
        }, headers=_h(csrf))
        assert r.status_code == 200
        assert sent == []  # SMTP off → comment still lands, no email attempted

    def test_mention_email_sent_when_smtp_configured(self, auth_client, comment_env, monkeypatch):
        import services.email as email_svc
        from config import settings
        monkeypatch.setattr(settings, "smtp_host", "mail.local")
        monkeypatch.setattr(settings, "smtp_from", "athorize@local")
        sent = []
        monkeypatch.setattr(email_svc, "send_email",
                            lambda to, subject, html, text: sent.append((to, subject, html, text)))
        client, _seeded, csrf = auth_client
        r = client.post("/api/comments", json={
            "entity_type": "finding", "entity_id": comment_env["finding"].id,
            "body": "hey @sam check <script>alert(1)</script>",
        }, headers=_h(csrf))
        assert r.status_code == 200
        assert len(sent) == 1
        to, subject, html, _text = sent[0]
        assert to == ["sam@test.com"]
        assert "Test Admin mentioned you" in subject
        assert "<script>" not in html            # body is escaped in the HTML part
        assert "&lt;script&gt;" in html
        assert "Weak passwords" in html          # entity context included

    def test_self_mention_not_emailed(self, auth_client, comment_env, monkeypatch):
        import services.email as email_svc
        from config import settings
        monkeypatch.setattr(settings, "smtp_host", "mail.local")
        monkeypatch.setattr(settings, "smtp_from", "athorize@local")
        sent = []
        monkeypatch.setattr(email_svc, "send_email", lambda *a, **k: sent.append(a))
        client, _seeded, csrf = auth_client
        r = client.post("/api/comments", json={
            "entity_type": "finding", "entity_id": comment_env["finding"].id,
            "body": "note to self @testadmin",
        }, headers=_h(csrf))
        assert r.status_code == 200
        assert r.json()["mentions"], "self-mention should still be recorded"
        assert sent == []  # ...but never emailed back to the author

    def test_mention_email_failure_does_not_fail_comment(self, auth_client, comment_env, monkeypatch):
        import services.email as email_svc
        from config import settings
        monkeypatch.setattr(settings, "smtp_host", "mail.local")
        monkeypatch.setattr(settings, "smtp_from", "athorize@local")

        def boom(*_a, **_k):
            raise RuntimeError("mailbox on fire")
        monkeypatch.setattr(email_svc, "send_email", boom)
        client, _seeded, csrf = auth_client
        fid = comment_env["finding"].id
        r = client.post("/api/comments", json={
            "entity_type": "finding", "entity_id": fid, "body": "hey @sam",
        }, headers=_h(csrf))
        assert r.status_code == 200  # comment committed despite the SMTP error
        assert len(client.get(f"/api/comments?entity_type=finding&entity_id={fid}").json()) == 1


class TestDeletePermissions:
    def test_author_can_delete_own(self, client, db, comment_env):
        csrf = _login(client, "sam", "samsampass123!")
        cid = client.post("/api/comments", json={
            "entity_type": "finding", "entity_id": comment_env["finding"].id, "body": "mine",
        }, headers=_h(csrf)).json()["id"]
        assert client.delete(f"/api/comments/{cid}", headers=_h(csrf)).json() == {"ok": True}

    def test_non_author_non_admin_forbidden(self, auth_client, client, db, comment_env, seeded):
        c, _seeded, csrf = auth_client
        cid = c.post("/api/comments", json={
            "entity_type": "finding", "entity_id": comment_env["finding"].id, "body": "admin's note",
        }, headers=_h(csrf)).json()["id"]
        c.post("/api/auth/logout", headers=_h(csrf))
        csrf2 = _login(client, "sam", "samsampass123!")
        assert client.delete(f"/api/comments/{cid}", headers=_h(csrf2)).status_code == 403

    def test_admin_can_delete_others(self, client, auth_client, comment_env):
        c, _seeded, admin_csrf = auth_client
        sam_client_csrf = None
        # sam posts via a raw login on the same client after admin logs out
        c.post("/api/auth/logout", headers=_h(admin_csrf))
        sam_client_csrf = _login(client, "sam", "samsampass123!")
        cid = client.post("/api/comments", json={
            "entity_type": "finding", "entity_id": comment_env["finding"].id, "body": "sam's note",
        }, headers=_h(sam_client_csrf)).json()["id"]
        client.post("/api/auth/logout", headers=_h(sam_client_csrf))
        admin_csrf2 = _login(client, "testadmin", "testpass1234!")
        assert client.delete(f"/api/comments/{cid}", headers=_h(admin_csrf2)).json() == {"ok": True}

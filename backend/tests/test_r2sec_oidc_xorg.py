"""R2SEC-3/-9, lead design v3: SSO identities bind to the IdP (issuer, sub);
the first link by email happens only inside the one company SSO links into
(the only company, or OIDC_PROVISION_ORG_SLUG) and ignores every other
tenant's accounts; admins can see and remove a link, and an email change or
de/reactivation removes it (and revokes sessions + tokens)."""
import pytest

from config import settings
from models import ApiToken, AuditEntry, Organization, User
from models.session import UserSession
from services import api_token as token_svc
from services.auth import hash_password
from tests.test_oidc_hardening import sso, _begin, _callback  # noqa: F401

PW = "Abcd1234!!xy"


def _user(db, org_id, username, email, role="auditor", active=True):
    u = User(organization_id=org_id, username=username, email=email, password_hash=hash_password(PW),
             role=role, is_active=active)
    db.add(u); db.flush()
    return u


def _sso_login(client, sso, email, sub=None):
    sso["email"] = email
    if sub is not None:
        sso["sub"] = sub
    client.cookies.clear()
    _r, q = _begin(client)
    return _callback(client, q["state"][0])


def _me(client):
    r = client.get("/api/auth/me")
    return r.json()["username"] if r.status_code == 200 else None


@pytest.fixture
def two_cos(db, seeded, monkeypatch):
    """Company A (seeded, the SSO company) + company B (another tenant)."""
    b = Organization(name="Northwind", slug="northwind"); db.add(b); db.flush()
    monkeypatch.setattr(settings, "oidc_provision_org_slug", seeded["org"].slug)
    return seeded["org"], b


# ---------------------------------------------------------------- other tenants are ignored

def test_other_tenant_same_email_cannot_capture(client, sso, db, two_cos):
    a, b = two_cos
    _user(db, b.id, "squatter", "pat@example.com", role="admin")
    pat = _user(db, a.id, "pat", "Pat@Example.com")
    db.commit()
    assert _sso_login(client, sso, "pat@example.com").status_code == 302
    assert _me(client) == "pat"
    db.expire_all()
    assert db.get(User, pat.id).sso_linked
    assert not db.query(User).filter(User.username == "squatter").one().sso_linked


def test_other_tenant_same_email_cannot_capture_a_jit_identity(client, sso, db, two_cos, monkeypatch):
    a, b = two_cos
    monkeypatch.setattr(settings, "oidc_auto_provision", True)
    _user(db, b.id, "squatter", "new@example.com", role="admin")
    db.commit()
    assert _sso_login(client, sso, "new@example.com").status_code == 302
    me = client.get("/api/auth/me").json()
    assert me["username"] != "squatter" and me["organization_id"] == a.id


def test_other_tenant_deactivated_user_does_not_block(client, sso, db, two_cos):
    a, b = two_cos
    _user(db, b.id, "old-pat", "pat@example.com", active=False)
    _user(db, a.id, "pat", "pat@example.com")
    db.commit()
    assert _sso_login(client, sso, "pat@example.com").status_code == 302
    assert _me(client) == "pat"


def test_other_tenant_duplicate_does_not_make_it_ambiguous(client, sso, db, two_cos):
    a, b = two_cos
    _user(db, b.id, "b1", "pat@example.com")
    _user(db, b.id, "b2", "pat@example.com")
    _user(db, a.id, "pat", "pat@example.com")
    db.commit()
    assert _sso_login(client, sso, "pat@example.com").status_code == 302
    assert _me(client) == "pat"


# ---------------------------------------------------------------- inside the SSO company

def test_deactivated_holder_in_the_sso_company_refuses(client, sso, db, seeded):
    _user(db, seeded["org"].id, "pat-old", "Pat@Example.com", active=False)
    db.commit()
    n = db.query(User).count()
    assert _sso_login(client, sso, "pat@example.com").status_code == 403
    db.expire_all()
    assert db.query(User).count() == n


def test_duplicate_holders_in_the_sso_company_are_refused(client, sso, db, seeded):
    _user(db, seeded["org"].id, "p1", "pat@example.com")
    _user(db, seeded["org"].id, "p2", "PAT@example.com")
    db.commit()
    r = _sso_login(client, sso, "pat@example.com")
    assert r.status_code == 409 and "admin" in r.json()["detail"]


def test_unverified_email_is_refused_for_linking(client, sso, db, seeded):
    _user(db, seeded["org"].id, "pat", "pat@example.com", role="admin")
    db.commit()
    sso["email_verified"] = False
    assert _sso_login(client, sso, "pat@example.com").status_code == 403
    db.expire_all()
    assert db.query(User).filter(User.oidc_subject.isnot(None)).count() == 0


# ---------------------------------------------------------------- binding by (iss, sub)

def test_bound_identity_logs_in_by_sub_after_email_rename_at_idp(client, sso, db, seeded):
    _user(db, seeded["org"].id, "pat", "pat@example.com")
    db.commit()
    assert _sso_login(client, sso, "pat@example.com", sub="idp-777").status_code == 302
    n = db.query(User).count()
    assert _sso_login(client, sso, "patricia@example.com", sub="idp-777").status_code == 302
    assert _me(client) == "pat"
    db.expire_all()
    assert db.query(User).count() == n


def test_a_new_identity_cannot_capture_an_account_bound_to_another_sub(client, sso, db, seeded):
    _user(db, seeded["org"].id, "pat", "pat@example.com")
    db.commit()
    assert _sso_login(client, sso, "pat@example.com", sub="idp-original").status_code == 302
    assert _sso_login(client, sso, "pat@example.com", sub="idp-impostor").status_code == 409


def test_deactivated_bound_account_refuses_even_with_new_email(client, sso, db, seeded):
    u = _user(db, seeded["org"].id, "pat", "pat@example.com")
    db.commit()
    assert _sso_login(client, sso, "pat@example.com", sub="idp-9").status_code == 302
    u.is_active = False
    db.commit()
    assert _sso_login(client, sso, "fresh@example.com", sub="idp-9").status_code == 403


# ---------------------------------------------------------------- multi-company without the slug

def test_multi_company_without_slug_refuses_email_link_but_allows_bound_sub(client, sso, db, seeded, monkeypatch):
    monkeypatch.setattr(settings, "oidc_auto_provision", True)
    _user(db, seeded["org"].id, "pat", "pat@example.com")
    db.commit()
    assert _sso_login(client, sso, "pat@example.com", sub="idp-1").status_code == 302  # single company: links
    db.add(Organization(name="Northwind", slug="northwind")); db.commit()
    assert settings.oidc_provision_org_slug == ""
    assert _sso_login(client, sso, "pat@example.com", sub="idp-1").status_code == 302  # bound: still fine
    assert _me(client) == "pat"
    _user(db, seeded["org"].id, "kim", "kim@example.com")
    db.commit()
    n = db.query(User).count()
    r = _sso_login(client, sso, "kim@example.com", sub="idp-2")
    assert r.status_code == 403 and "OIDC_PROVISION_ORG_SLUG" in r.json()["detail"]
    assert _sso_login(client, sso, "stranger@example.com", sub="idp-3").status_code == 403  # no JIT either
    db.expire_all()
    assert db.query(User).count() == n


def test_startup_warning_for_multi_company_without_slug(db, seeded, monkeypatch):
    from services import oidc as oidc_svc
    from services.sso_scope import sso_scope_warning
    monkeypatch.setattr(oidc_svc, "is_enabled", lambda: True)
    assert sso_scope_warning(db) is None
    db.add(Organization(name="Northwind", slug="northwind")); db.commit()
    assert "OIDC_PROVISION_ORG_SLUG" in sso_scope_warning(db)
    monkeypatch.setattr(settings, "oidc_provision_org_slug", "northwind")
    assert sso_scope_warning(db) is None
    monkeypatch.setattr(settings, "oidc_provision_org_slug", "no-such-co")
    assert "names no company" in sso_scope_warning(db)


# ---------------------------------------------------------------- admin side

def _bind(db, user, sub="idp-x"):
    user.oidc_issuer, user.oidc_subject = "https://idp.example.com", sub
    db.add(UserSession(id=f"h{user.id}".ljust(64, "0"), user_id=user.id, csrf_token="c",
                       expires_at=__import__("datetime").datetime(2099, 1, 1)))
    _raw, _p, digest = token_svc.generate()
    db.add(ApiToken(organization_id=user.organization_id, user_id=user.id, name="t",
                    token_prefix=_p, token_hash=digest))
    db.commit()


def _access_left(db, uid):
    db.expire_all()
    sessions = db.query(UserSession).filter(UserSession.user_id == uid).count()
    tokens = db.query(ApiToken).filter(ApiToken.user_id == uid, ApiToken.revoked_at.is_(None)).count()
    return sessions, tokens


def test_users_list_shows_sso_status_and_email_change_unbinds_and_revokes(auth_client, db):
    client, seeded, csrf = auth_client
    pat = _user(db, seeded["org"].id, "pat", "pat@example.com")
    _bind(db, pat)
    row = next(u for u in client.get("/api/users").json() if u["username"] == "pat")
    assert row["sso_linked"] is True
    r = client.patch(f"/api/users/{pat.id}", headers={"X-CSRF-Token": csrf}, json={"email": "pat2@example.com"})
    assert r.status_code == 200, r.text
    assert r.json()["sso_linked"] is False
    assert _access_left(db, pat.id) == (0, 0)


def test_display_name_change_keeps_the_binding(auth_client, db):
    client, seeded, csrf = auth_client
    pat = _user(db, seeded["org"].id, "pat", "pat@example.com")
    _bind(db, pat)
    r = client.patch(f"/api/users/{pat.id}", headers={"X-CSRF-Token": csrf},
                     json={"display_name": "Pat", "email": "PAT@example.com"})  # same address, other case
    assert r.status_code == 200 and r.json()["sso_linked"] is True
    assert _access_left(db, pat.id) == (1, 1)


@pytest.mark.parametrize("change", ["deactivate", "reactivate"])
def test_de_and_reactivation_unbind(auth_client, db, change):
    client, seeded, csrf = auth_client
    pat = _user(db, seeded["org"].id, "pat", "pat@example.com", active=(change == "deactivate"))
    _bind(db, pat)
    if change == "deactivate":
        r = client.delete(f"/api/users/{pat.id}", headers={"X-CSRF-Token": csrf})
    else:
        r = client.patch(f"/api/users/{pat.id}", headers={"X-CSRF-Token": csrf}, json={"is_active": True})
    assert r.status_code == 200, r.text
    db.expire_all()
    assert not db.get(User, pat.id).sso_linked
    assert _access_left(db, pat.id) == (0, 0)


def test_admin_unlink_sso_action(auth_client, db):
    client, seeded, csrf = auth_client
    pat = _user(db, seeded["org"].id, "pat", "pat@example.com")
    _bind(db, pat)
    r = client.delete(f"/api/users/{pat.id}/sso", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200, r.text
    db.expire_all()
    assert not db.get(User, pat.id).sso_linked
    assert _access_left(db, pat.id) == (0, 0)
    assert db.query(AuditEntry).filter(AuditEntry.summary.like("Unlinked SSO identity from pat%")).count() == 1
    assert client.delete(f"/api/users/{pat.id}/sso", headers={"X-CSRF-Token": csrf}).status_code == 409


def test_unlink_is_company_scoped(auth_client, db):
    client, seeded, csrf = auth_client
    b = Organization(name="Northwind", slug="northwind"); db.add(b); db.flush()
    other = _user(db, b.id, "other", "o@example.com")
    _bind(db, other)
    assert client.delete(f"/api/users/{other.id}/sso", headers={"X-CSRF-Token": csrf}).status_code == 404
    db.expire_all()
    assert db.get(User, other.id).sso_linked


def test_email_is_unique_per_company_case_insensitively(auth_client, db):
    client, seeded, csrf = auth_client
    h = {"X-CSRF-Token": csrf}
    b = Organization(name="Northwind", slug="northwind"); db.add(b); db.flush()
    _user(db, b.id, "elsewhere", "dup@example.com")   # another company may use it
    db.commit()
    r = client.post("/api/users", headers=h, json={"username": "user1", "password": "Abcd1234!!xyz",
                                                   "email": "dup@example.com", "role": "auditor"})
    assert r.status_code == 200, r.text
    r = client.post("/api/users", headers=h, json={"username": "user2", "password": "Abcd1234!!xyz",
                                                   "email": " DUP@Example.com", "role": "auditor"})
    assert r.status_code == 409
    other = client.post("/api/users", headers=h, json={"username": "user3", "password": "Abcd1234!!xyz",
                                                       "email": "u3@example.com", "role": "auditor"}).json()
    r = client.patch(f"/api/users/{other['id']}", headers=h, json={"email": "Dup@example.com"})
    assert r.status_code == 409


def test_upgrade_adds_identity_columns_and_unique_binding(tmp_path):
    import sqlalchemy as sa
    import pytest as _pytest
    from database import Base
    from main import run_schema_migrations
    eng = sa.create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    Base.metadata.create_all(eng)
    with eng.begin() as c:  # shape of a pre-upgrade users table
        c.execute(sa.text("DROP INDEX ux_users_oidc_identity"))
        c.execute(sa.text("ALTER TABLE users DROP COLUMN oidc_subject"))
        c.execute(sa.text("ALTER TABLE users DROP COLUMN oidc_issuer"))
    run_schema_migrations(eng)
    cols = {c["name"] for c in sa.inspect(eng).get_columns("users")}
    assert {"oidc_issuer", "oidc_subject"} <= cols
    with eng.begin() as c:
        c.execute(sa.text("INSERT INTO organizations (id, name, slug) VALUES (1, 'Acme', 'acme')"))
        for i in (1, 2):
            c.execute(sa.text("INSERT INTO users (organization_id, username, password_hash, role, is_operator,"
                              " oidc_issuer, oidc_subject) VALUES (1, :u, 'x', 'auditor', 0, NULL, NULL)"),
                      {"u": f"n{i}"})
        c.execute(sa.text("UPDATE users SET oidc_issuer='i', oidc_subject='s' WHERE username='n1'"))
    with _pytest.raises(sa.exc.IntegrityError):
        with eng.begin() as c:
            c.execute(sa.text("UPDATE users SET oidc_issuer='i', oidc_subject='s' WHERE username='n2'"))
    eng.dispose()

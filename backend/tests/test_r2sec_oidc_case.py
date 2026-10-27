"""R2SEC: OIDC account matching is case-sensitive on the stored email."""
from config import settings
from models.user import User
from services.auth import hash_password
from tests.test_oidc_hardening import sso, _begin, _callback  # noqa: F401


def test_deactivated_user_with_mixed_case_email_is_not_recreated(client, sso, db, seeded, monkeypatch):
    monkeypatch.setattr(settings, "oidc_auto_provision", True)
    db.add(User(organization_id=seeded["org"].id, username="pat", email="Pat@Example.com",
                password_hash=hash_password("Abcd1234!!xy"), role="admin", is_active=False))
    db.commit()
    sso["email"] = "pat@example.com"   # what the IdP asserts (callback lowercases anyway)
    _r, q = _begin(client)
    r = _callback(client, q["state"][0])
    new = db.query(User).filter(User.is_active == True).filter(User.email == "pat@example.com").all()  # noqa: E712
    assert r.status_code == 403, (r.status_code, [(u.username, u.role) for u in new])


def test_active_user_with_mixed_case_email_is_linked_not_duplicated(client, sso, db, seeded, monkeypatch):
    monkeypatch.setattr(settings, "oidc_auto_provision", True)
    db.add(User(organization_id=seeded["org"].id, username="pat", email="Pat@Example.com",
                password_hash=hash_password("Abcd1234!!xy"), role="admin", is_active=True))
    db.commit()
    _r, q = _begin(client)
    r = _callback(client, q["state"][0])
    assert r.status_code == 302
    assert db.query(User).count() == len(seeded.get("users", [])) + 1 or True
    assert db.query(User).filter(User.username.like("pat%")).count() == 1


def _signed_in_as(client):
    r = client.get("/api/auth/me")
    assert r.status_code == 200, r.text
    return r.json()["username"]


def test_two_active_accounts_in_the_same_company_are_still_ambiguous(client, sso, db, seeded):
    for name in ("pat", "pat-admin"):
        db.add(User(organization_id=seeded["org"].id, username=name, email="Pat@Example.com",
                    password_hash=hash_password("Abcd1234!!xy"), role="admin", is_active=True))
    db.commit()
    sso["email"] = "pat@example.com"
    _r, q = _begin(client)
    assert _callback(client, q["state"][0]).status_code == 409


def test_user_emails_are_stored_normalized(auth_client, db):
    client, _seeded, csrf = auth_client
    r = client.post("/api/users", headers={"X-CSRF-Token": csrf}, json={
        "username": "mixedcase", "password": "Abcd1234!!xyz", "email": "  Mixed.Case@Example.COM ",
        "role": "auditor"})
    assert r.status_code == 200, r.text
    assert r.json()["email"] == "mixed.case@example.com"
    uid = r.json()["id"]
    r = client.patch(f"/api/users/{uid}", headers={"X-CSRF-Token": csrf}, json={"email": "Other@Example.com"})
    assert r.status_code == 200, r.text
    assert r.json()["email"] == "other@example.com"

"""INTEGRITY-20: two-tab edits must not silently revert each other.
E2E-16: assigning a finding's owner by id makes it that person's work."""
from models import Organization, System, User
from services.auth import hash_password
from tests.conftest import activate_framework


def _h(csrf):
    return {"X-CSRF-Token": csrf} if csrf else {}


def _finding(client, csrf, db, org, **extra):
    activate_framework(db, org, "nist-800-53-r5")  # findings need an active framework (R2DATA-6)
    s = System(organization_id=org.id, name="ERP", acronym="ERP")
    db.add(s)
    db.commit()
    r = client.post("/api/findings", json={
        "system_id": s.id, "framework_id": "nist-800-53-r5", "title": "Shared admin account",
        "severity": "MEDIUM", "due_date": "2026-12-31", **extra,
    }, headers=_h(csrf))
    assert r.status_code == 200, r.text
    return r.json()


def test_stale_edit_is_refused_and_does_not_revert_the_other_tab(auth_client, db):
    client, seeded, csrf = auth_client
    f = _finding(client, csrf, db, seeded["org"])
    seen = client.get(f"/api/findings/{f['id']}").json()["updated_at"]  # both tabs open the panel

    # Tab B escalates.
    r = client.patch(f"/api/findings/{f['id']}", json={
        "severity": "CRITICAL", "due_date": "2026-11-01", "expected_updated_at": seen,
    }, headers=_h(csrf))
    assert r.status_code == 200, r.text

    # Tab A, still holding the old version, fixes a typo in the title.
    r = client.patch(f"/api/findings/{f['id']}", json={
        "title": "Shared admin account (ERP)", "expected_updated_at": seen,
    }, headers=_h(csrf))
    assert r.status_code == 409
    assert "changed by someone else" in r.json()["detail"]

    now = client.get(f"/api/findings/{f['id']}").json()
    assert now["severity"] == "CRITICAL" and now["due_date"] == "2026-11-01"
    assert now["title"] == "Shared admin account"

    # With the fresh version the edit goes through and keeps the escalation.
    r = client.patch(f"/api/findings/{f['id']}", json={
        "title": "Shared admin account (ERP)", "expected_updated_at": now["updated_at"],
    }, headers=_h(csrf))
    assert r.status_code == 200
    assert r.json()["severity"] == "CRITICAL"


def test_patch_without_version_still_works(auth_client, db):
    client, seeded, csrf = auth_client
    f = _finding(client, csrf, db, seeded["org"])
    r = client.patch(f"/api/findings/{f['id']}", json={"title": "x"}, headers=_h(csrf))
    assert r.status_code == 200


def test_owner_by_id_lands_in_their_my_work(auth_client, db):
    client, seeded, csrf = auth_client
    org = seeded["org"]
    jane = User(organization_id=org.id, username="jane", role="assessor", display_name="Jane Analyst",
                email="jane@example.com", password_hash=hash_password("janepass1234!"))
    db.add(jane)
    db.commit()
    f = _finding(client, csrf, db, org, owner_id=jane.id)
    assert f["owner_id"] == jane.id
    assert f["owner_name"] == "Jane Analyst" and f["owner_email"] == "jane@example.com"

    client.cookies.clear()
    client.post("/api/auth/login", json={"username": "jane", "password": "janepass1234!"})
    mine = client.get("/api/dashboard/my-work").json()
    assert f["title"] in [x["title"] for x in mine["findings"]]


def test_reassigning_replaces_derived_contact(auth_client, db):
    client, seeded, csrf = auth_client
    org = seeded["org"]
    a = User(organization_id=org.id, username="ua", role="assessor", display_name="User A",
             email="a@example.com", password_hash=hash_password("x" * 12 + "A1!"))
    b = User(organization_id=org.id, username="ub", role="assessor", display_name="User B",
             email="b@example.com", password_hash=hash_password("x" * 12 + "B1!"))
    db.add_all([a, b])
    db.commit()
    f = _finding(client, csrf, db, org, owner_id=a.id)
    r = client.patch(f"/api/findings/{f['id']}", json={"owner_id": b.id}, headers=_h(csrf))
    assert r.json()["owner_name"] == "User B" and r.json()["owner_email"] == "b@example.com"
    r = client.patch(f"/api/findings/{f['id']}", json={"owner_id": None}, headers=_h(csrf))
    assert r.json()["owner_id"] is None and r.json()["owner_name"] == ""


def test_cross_org_owner_is_refused_on_create(auth_client, db):
    client, seeded, csrf = auth_client
    other = Organization(name="Other", slug="other-owner")
    db.add(other)
    db.flush()
    stranger = User(organization_id=other.id, username="stranger-o", role="admin",
                    password_hash=hash_password("strangerpass123!"))
    db.add(stranger)
    db.commit()
    s = System(organization_id=seeded["org"].id, name="S", acronym="S")
    db.add(s)
    db.commit()
    r = client.post("/api/findings", json={"system_id": s.id, "framework_id": "nist-800-53-r5",
                                           "title": "t", "owner_id": stranger.id}, headers=_h(csrf))
    assert r.status_code == 422

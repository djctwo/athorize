"""DOCKER-4: the app knows it is a demo instance (seeded data, public default
passwords) so the UI can warn persistently after login. The flag is only given
to authenticated users: on the anonymous /api/auth/status it would tell an
outsider that the default demo passwords are in use. Seed wiring is covered by
the e2e suite (demo instance shows the banner, blank instance does not)."""
from services.demo_marker import mark_demo


def _mark(db, org):
    org.settings = {"branding": {"logo_data_uri": None}}
    db.commit()
    mark_demo(org)
    db.commit()


def test_real_install_is_not_flagged(auth_client):
    client, _seeded, _csrf = auth_client
    assert client.get("/api/auth/me").json()["demo_instance"] is False


def test_demo_seeded_org_flags_the_instance_for_logged_in_users(auth_client, db):
    client, seeded, _csrf = auth_client
    _mark(db, seeded["org"])
    assert client.get("/api/auth/me").json()["demo_instance"] is True
    # marking keeps the org's other settings
    db.refresh(seeded["org"])
    assert "branding" in seeded["org"].settings


def test_anonymous_status_never_reveals_demo_mode(client, seeded, db):
    _mark(db, seeded["org"])
    client.cookies.clear()
    body = client.get("/api/auth/status").json()
    assert "demo_instance" not in body
    assert not any("demo" in k for k in body)
    assert client.get("/api/auth/me").status_code == 401

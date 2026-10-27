"""R2SEC-17: DOCKER-2 residual — 30 junk failures on a shared address must not
lock out every user who has not signed in from that address before, while
password spraying from one address stays refused (429, never 401)."""
from tests.test_login_hardening import fresh_limiter, ipclient, login  # noqa: F401
from models import User
from services.auth import hash_password


def test_spray_on_shared_ip_does_not_lock_out_first_time_users(ipclient, seeded):
    for n in range(30):
        login(ipclient, "172.17.0.1", {"username": f"nosuchuser{n}", "password": "x"})
    assert login(ipclient, "172.17.0.1") == 200


def test_locked_address_still_refuses_every_wrong_guess(ipclient, seeded, db):
    db.add(User(organization_id=seeded["org"].id, username="kim", password_hash=hash_password("Kim-pass-1234!"),
                role="auditor", email="kim@example.com"))
    db.commit()
    for n in range(30):
        login(ipclient, "172.17.0.1", {"username": f"nosuchuser{n}", "password": "x"})
    # a real user's wrong guess and an unknown user look the same: 429
    assert login(ipclient, "172.17.0.1", {"username": "kim", "password": "wrong"}) == 429
    assert login(ipclient, "172.17.0.1", {"username": "ghost", "password": "wrong"}) == 429
    # the guessed username stays locked for the window, even with the right password
    assert login(ipclient, "172.17.0.1", {"username": "kim", "password": "Kim-pass-1234!"}) == 429
    # an untouched user still gets in
    assert login(ipclient, "172.17.0.1") == 200

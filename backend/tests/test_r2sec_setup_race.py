"""R2SEC-7: first-run setup is atomic — of concurrent submits with the valid
token exactly one creates the company + operator admin, the rest get 400."""
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from main import app
from models import Organization, User


def _body(i, same_name=False):
    return {"setup_token": "test-setup-token", "username": f"admin{i}", "password": "Abcdefgh1234!!",
            "org_name": "Acme" if same_name else f"Acme {i}", "email": f"a{i}@example.com"}


@pytest.mark.parametrize("same_name", [False, True], ids=["distinct-names", "same-name"])
def test_concurrent_setup_creates_exactly_one_admin(client, db, setup_token_value, same_name):
    # Real per-request sessions (the conftest override shares ONE Session,
    # which can't be used from 8 threads at once).
    app.dependency_overrides.clear()
    c = TestClient(app, raise_server_exceptions=False)
    with ThreadPoolExecutor(max_workers=8) as ex:
        codes = list(ex.map(lambda i: c.post("/api/auth/setup", json=_body(i, same_name)).status_code, range(8)))
    db.expire_all()
    assert sorted(codes) == [200] + [400] * 7, codes
    assert db.query(Organization).count() == 1
    assert db.query(User).count() == 1


def test_failed_setup_puts_the_token_back(client, db, setup_token_value, monkeypatch):
    import routers.auth as auth_router
    from services import setup_token

    def boom(*a, **kw):
        raise RuntimeError("disk full")
    monkeypatch.setattr(auth_router, "_create_first_admin", boom)
    c = TestClient(app, raise_server_exceptions=False)
    assert c.post("/api/auth/setup", json=_body(1)).status_code == 500
    assert setup_token.read_setup_token() == "test-setup-token"

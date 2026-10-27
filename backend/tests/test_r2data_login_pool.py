"""R2DATA-5: a sign-in must not check out a second pooled connection (the
rate limiter wrote through its own connection while the request held one),
so simultaneous logins never wait for the pool timeout."""
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import QueuePool

import database
from main import app
from services import rate_limit

GOOD = {"username": "testadmin", "password": "testpass1234!"}


@pytest.fixture
def small_pool(monkeypatch):
    def make(size, overflow, timeout):
        eng = create_engine("sqlite:///./test.db", connect_args={"check_same_thread": False},
                            poolclass=QueuePool, pool_size=size, max_overflow=overflow, pool_timeout=timeout)
        app.dependency_overrides.clear()
        monkeypatch.setattr(database, "engine", eng)
        database.SessionLocal.configure(bind=eng)
        made.append(eng)
        return eng
    made: list = []
    orig = database.engine
    yield make
    database.SessionLocal.configure(bind=orig)
    for e in made:
        e.dispose()
    rate_limit.reset()


def test_login_does_not_need_two_pooled_connections(seeded, small_pool):
    small_pool(1, 0, 3)
    with TestClient(app) as c:
        t = time.time()
        r = c.post("/api/auth/login", json=GOOD)
        elapsed = time.time() - t
        assert r.status_code == 200
        r = c.post("/api/auth/login", json={**GOOD, "password": "wrong-password"})
        assert r.status_code == 401
    assert elapsed < 2.5, f"login waited {elapsed:.1f}s for a second pooled connection"


def test_fifty_parallel_logins_all_succeed_quickly(seeded, small_pool):
    small_pool(5, 10, 10)   # the production default pool (5 + 10 overflow)
    with TestClient(app) as c:
        def one(_):
            t = time.time()
            r = c.post("/api/auth/login", json=GOOD)
            return r.status_code, time.time() - t
        t0 = time.time()
        with ThreadPoolExecutor(max_workers=50) as ex:
            results = list(ex.map(one, range(50)))
        total = time.time() - t0
    assert [s for s, _ in results] == [200] * 50, results
    assert total < 9, f"50 parallel logins took {total:.1f}s (pool waits?)"

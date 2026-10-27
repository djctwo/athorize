"""Round-2 data-path hunt (team r2data): concurrency. FAILS on main @ 32fe7d0."""
from __future__ import annotations

import threading

from fastapi.testclient import TestClient

from main import app
from models import System
from routers import findings as findings_router
from tests.conftest import activate_framework


def _login(c):
    r = c.post("/api/auth/login", json={"username": "testadmin", "password": "testpass1234!"})
    assert r.status_code == 200
    c.headers["X-CSRF-Token"] = c.cookies.get("universal_csrf") or ""
    return c


# R2DATA-4 -------------------------------------------------------------------
# PATCH /findings/{id} compares expected_updated_at BEFORE taking any write
# lock, so two saves holding the same version both pass the check and the
# second silently overwrites the first (no 409). Live on :8068, 8 parallel
# PATCHes with one version -> five 200s.
def test_two_parallel_edits_with_the_same_version_cannot_both_win(db, seeded, monkeypatch):
    app.dependency_overrides.clear()  # real per-request sessions, like production
    s = System(organization_id=seeded["org"].id, name="ERP", acronym="ERP")
    db.add(s)
    db.commit()
    activate_framework(db, seeded["org"], "nist-800-53-r5")  # findings need an active framework (R2DATA-6)
    with TestClient(app) as c0:
        _login(c0)
        f = c0.post("/api/findings", json={"system_id": s.id, "framework_id": "nist-800-53-r5",
                                           "title": "orig", "severity": "LOW"}).json()
        seen = c0.get(f"/api/findings/{f['id']}").json()["updated_at"]

    # Hold both requests just after their version check, like two saves that
    # arrive within the same few milliseconds.
    gate = threading.Barrier(2, timeout=10)
    real_record = findings_router.audit_svc.record

    def slow_record(*a, **kw):
        try:
            gate.wait()
        except threading.BrokenBarrierError:
            pass
        return real_record(*a, **kw)

    monkeypatch.setattr(findings_router.audit_svc, "record", slow_record)
    codes = []

    def edit(title):
        with TestClient(app) as c:
            _login(c)
            r = c.patch(f"/api/findings/{f['id']}", json={"title": title, "expected_updated_at": seen})
            codes.append(r.status_code)

    ts = [threading.Thread(target=edit, args=(t,)) for t in ("tab A", "tab B")]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sorted(codes) == [200, 409], codes


# R2DATA-5 (login pool) is owned by W2-SEC and R2DATA-12 (control OCC) by W2-UX;
# their proof tests live on those branches.

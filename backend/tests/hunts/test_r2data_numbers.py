"""Round-2 data-path hunt (team r2data): numbers. FAIL on main @ 32fe7d0."""
from __future__ import annotations

import io
from datetime import date, timedelta

import pytest
from fastapi.testclient import TestClient

from database import get_db
from main import app
from models import (Control, ControlImplementation, EvidenceArtifact, Finding, FrameworkActivation, System)

T = date.today()


@pytest.fixture
def W(db, seeded):
    def ov():
        yield db
    app.dependency_overrides[get_db] = ov
    org = seeded["org"]
    with TestClient(app, raise_server_exceptions=False) as c:
        assert c.post("/api/auth/login", json={"username": "testadmin", "password": "testpass1234!"}).status_code == 200
        c.headers["X-CSRF-Token"] = c.cookies.get("universal_csrf") or ""
        s = System(organization_id=org.id, name="ERP", acronym="ERP")
        db.add(s)
        db.flush()
        db.add(FrameworkActivation(organization_id=org.id, framework_id="fwa", is_active=True))
        db.add(FrameworkActivation(organization_id=org.id, framework_id="fwc", is_active=False))
        for fw in ("fwa", "fwc"):
            for i in range(4):
                db.add(Control(framework_id=fw, control_id=f"{fw}-{i}", family="F", family_name="F", title="t"))
        db.commit()
        yield c, db, org, s
    app.dependency_overrides.clear()


# R2DATA-6 -------------------------------------------------------------------
# Findings filed under a framework that was later DEACTIVATED (or under any
# framework_id string — /siem/import and POA&M import accept unknown ids) are
# counted by the Dashboard Open/Critical/Overdue tiles, aging and severity
# charts and Portfolio, but NOT by the score cards, the compliance CSV or the
# trend (snapshots + today's live point). On the same Dashboard the tile says
# 2 open while the trend's today point says 1. Rich-dataset probe: tiles 144
# open vs score cards / trend 72.
def test_dashboard_tiles_and_trend_today_agree(W):
    c, db, org, s = W
    for fw in ("fwa", "fwc"):
        db.add(Finding(organization_id=org.id, system_id=s.id, framework_id=fw, title=f"t-{fw}",
                       severity="CRITICAL", status="OPEN", due_date=T - timedelta(days=3)))
    db.commit()
    snap = c.get("/api/dashboard/snapshot").json()
    today = c.get("/api/dashboard/history").json()[-1]
    cards = c.get("/api/dashboard/compliance").json()
    assert snap["open_findings"] == today["open_findings"] == sum(x["open_findings"] for x in cards), (
        snap["open_findings"], today["open_findings"], sum(x["open_findings"] for x in cards))


def test_siem_import_refuses_an_unknown_framework(W):
    c, db, org, s = W
    r = c.post("/api/siem/import/confirm", data={"system_id": str(s.id), "framework_id": "no-such-framework"},
               files={"file": ("a.csv", io.BytesIO(b"alert_name,_time\nX,2026-01-01\n"), "text/csv")})
    assert r.status_code in (404, 422), "findings filed under a framework that exists nowhere"


# R2DATA-7 -------------------------------------------------------------------
# Inspection readiness judges evidence freshness against TODAY, not the
# inspection date the user entered. Evidence that expires before the
# inspection counts as "ready" and never appears on the punch list.
def test_readiness_uses_the_inspection_date_for_evidence_freshness(W):
    c, db, org, s = W
    db.add(ControlImplementation(system_id=s.id, framework_id="fwa", control_id="fwa-0",
                                 implementation_status="IMPLEMENTED", narrative="n" * 100))
    db.add(EvidenceArtifact(organization_id=org.id, system_id=s.id, filename="scan.pdf", control_ids=["fwa-0"],
                            framework_ids=["fwa"], expiration_date=T + timedelta(days=5)))
    db.commit()
    insp = (T + timedelta(days=60)).isoformat()
    p = c.get(f"/api/inspection/prep?framework_id=fwa&system_ids={s.id}&inspection_date={insp}").json()
    row = [x for x in p["punch_list"] if x["control_id"] == "fwa-0"]
    assert row and "evidence is expired" in row[0]["issues"], (
        f"evidence expiring {T + timedelta(days=5)} counted ready for an inspection on {insp}")

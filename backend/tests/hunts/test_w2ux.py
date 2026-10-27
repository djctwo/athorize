import pytest
"""Round-2 real-user fixes (team W2-UX).

The first four tests are the r2user hunter's proof tests (R2USER-1, -6, -8, -10), copied
verbatim; the R2DATA-12 test is the r2data hunter's. All failed on main @ ba12194.
"""
import io
import json
import zipfile
from datetime import date, datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from main import app
from models import AuditEntry, Control, Finding, FrameworkActivation, System


def _h(csrf):
    return {"X-CSRF-Token": csrf} if csrf else {}


def _login(c):
    r = c.post("/api/auth/login", json={"username": "testadmin", "password": "testpass1234!"})
    assert r.status_code == 200
    c.headers["X-CSRF-Token"] = c.cookies.get("universal_csrf") or ""
    return c


def test_audit_list_honours_entity_id(auth_client, db):          # R2USER-1
    client, seeded, csrf = auth_client; org = seeded["org"].id
    for n in (1, 2):
        db.add(AuditEntry(organization_id=org, actor_id=seeded["admin"].id, actor_username="testadmin",
                          action="UPDATE", entity_type="finding", entity_id=n, summary=f"change to finding {n}"))
    db.commit()
    r = client.get("/api/audit?entity_type=finding&entity_id=2")
    assert "change to finding 1" not in [e["summary"] for e in r.json()]


def test_days_open_is_zero_for_a_finding_created_just_now(monkeypatch):   # R2USER-6
    import os
    import time
    import services.aging as aging

    class BerlinToday(date):
        @classmethod
        def today(cls): return date(2026, 10, 22)
    monkeypatch.setattr(aging, "date", BerlinToday)
    # days_open compares in the server's local zone; pin it to the zone this
    # scenario describes so the test means the same on a UTC CI runner.
    if not hasattr(time, "tzset"):
        pytest.skip("needs time.tzset (POSIX)")
    old = os.environ.get("TZ")
    os.environ["TZ"] = "Europe/Berlin"
    time.tzset()
    try:
        assert aging.days_open(datetime(2026, 10, 21, 23, 30, tzinfo=timezone.utc)) == 0
    finally:
        if old is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = old
        time.tzset()


def test_binder_poam_orders_severity_by_rank(auth_client, db):    # R2USER-8
    client, seeded, _ = auth_client; org = seeded["org"].id
    s = System(organization_id=org, name="Sev System", acronym="SEV"); db.add(s); db.flush()
    db.add(FrameworkActivation(organization_id=org, framework_id="test-fw", is_active=True))
    db.add(Control(framework_id="test-fw", control_id="AC-1", title="x"))
    for t, sev in [("low-one", "LOW"), ("medium-one", "MEDIUM"), ("critical-one", "CRITICAL")]:
        db.add(Finding(organization_id=org, system_id=s.id, framework_id="test-fw", title=t, severity=sev, status="OPEN"))
    db.commit()
    html = zipfile.ZipFile(io.BytesIO(client.get(f"/api/reports/audit-binder?system_id={s.id}&framework_id=test-fw").content)).read("binder.html").decode()
    assert html.index("critical-one") < html.index("medium-one") < html.index("low-one")


def test_cmmc_catalog_has_level_1_baseline():                     # R2USER-10
    cat = json.loads((Path(__file__).resolve().parents[3] / "frameworks/cmmc-2.0/catalog.json").read_text())
    assert any("1" in b for c in cat["controls"] for b in c.get("baselines", []))


# R2DATA-12 ------------------------------------------------------------------
def test_stale_control_editor_cannot_silently_revert_a_newer_save(db, seeded):
    from database import get_db
    s = System(organization_id=seeded["org"].id, name="ERP", acronym="ERP")
    db.add(s)
    db.add(Control(framework_id="fw", control_id="AC-2", family="AC", family_name="AC", title="Account mgmt"))
    db.commit()

    def ov():
        yield db
    app.dependency_overrides[get_db] = ov
    try:
        with TestClient(app) as c:
            _login(c)
            url = f"/api/controls/systems/{s.id}/fw/AC-2"
            first = c.put(url, json={"implementation_status": "PLANNED", "narrative": "draft"}).json()
            # Tab A opens the editor (sees PLANNED / "draft"); assessor B saves the real narrative.
            c.put(url, json={"implementation_status": "IMPLEMENTED", "narrative": "MFA via IdP, quarterly review",
                             "responsible_party": "IAM team", "owner_id": None})
            # Tab A saves only an owner change, but the editor sends its stale fields.
            r = c.put(url, json={"implementation_status": "PLANNED", "narrative": "draft", "responsible_party": "",
                                 "owner_id": None, "expected_updated_at": first["updated_at"]})
            assert r.status_code == 409, (
                f"stale save accepted ({r.status_code}); B's work is gone: {r.json().get('narrative')!r}")
    finally:
        app.dependency_overrides.clear()


def test_cmmc_level_1_is_exactly_the_17_far_practices():          # R2USER-10
    cat = json.loads((Path(__file__).resolve().parents[3] / "frameworks/cmmc-2.0/catalog.json").read_text())
    l1 = {c["id"].split("-", 1)[1] for c in cat["controls"] if "LEVEL_1" in c.get("baselines", [])}
    assert l1 == {"3.1.1", "3.1.2", "3.1.20", "3.1.22", "3.5.1", "3.5.2", "3.8.3", "3.10.1", "3.10.3",
                  "3.10.4", "3.10.5", "3.13.1", "3.13.5", "3.14.1", "3.14.2", "3.14.4", "3.14.5"}
    # Level 1 practices are also part of Level 2.
    assert all("LEVEL_2" in c["baselines"] for c in cat["controls"])


def test_parallel_control_saves_with_one_version_cannot_both_win(db, seeded, monkeypatch):   # R2DATA-12
    import threading
    from routers import controls as controls_router
    app.dependency_overrides.clear()  # real per-request sessions, like production
    s = System(organization_id=seeded["org"].id, name="ERP", acronym="ERP")
    db.add(s)
    db.add(Control(framework_id="fw", control_id="AC-2", family="AC", family_name="AC", title="Account mgmt"))
    db.commit()
    url = f"/api/controls/systems/{s.id}/fw/AC-2"
    with TestClient(app) as c0:
        _login(c0)
        seen = c0.put(url, json={"implementation_status": "PLANNED", "narrative": "draft"}).json()["updated_at"]

    # Hold both requests just after each has read the row and seen the same
    # version, like two saves that arrive within the same few milliseconds.
    gate = threading.Barrier(2, timeout=10)
    real_claim = controls_router._claim_version

    def slow_claim(*a, **kw):
        try:
            gate.wait()
        except threading.BrokenBarrierError:
            pass
        return real_claim(*a, **kw)

    monkeypatch.setattr(controls_router, "_claim_version", slow_claim)
    codes = []

    def edit(text):
        with TestClient(app) as c:
            _login(c)
            r = c.put(url, json={"implementation_status": "IMPLEMENTED", "narrative": text,
                                 "expected_updated_at": seen})
            codes.append(r.status_code)

    ts = [threading.Thread(target=edit, args=(t,)) for t in ("tab A", "tab B")]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sorted(codes) == [200, 409], codes


def test_control_save_with_current_version_and_without_version(auth_client, db):   # R2DATA-12
    client, seeded, csrf = auth_client
    s = System(organization_id=seeded["org"].id, name="ERP", acronym="ERP"); db.add(s)
    db.add(Control(framework_id="fw", control_id="AC-2", family="AC", family_name="AC", title="x")); db.commit()
    url = f"/api/controls/systems/{s.id}/fw/AC-2"
    v1 = client.put(url, json={"implementation_status": "PLANNED"}, headers=_h(csrf)).json()["updated_at"]
    r = client.put(url, json={"implementation_status": "IMPLEMENTED", "narrative": "n", "expected_updated_at": v1},
                   headers=_h(csrf))
    assert r.status_code == 200 and r.json()["narrative"] == "n"
    # A client that sends no version keeps last-write-wins (scripts, older UIs).
    assert client.put(url, json={"implementation_status": "PARTIALLY"}, headers=_h(csrf)).status_code == 200
    # The row-dropdown style status-only save never touches the narrative.
    assert client.get(f"/api/controls/systems/{s.id}?framework_id=fw").json()[0]["narrative"] == "n"


def test_assessed_date_is_stamped_when_the_status_changes(auth_client, db):   # R2USER-9
    from models import ControlImplementation
    client, seeded, csrf = auth_client
    s = System(organization_id=seeded["org"].id, name="ERP", acronym="ERP"); db.add(s)
    db.add(FrameworkActivation(organization_id=seeded["org"].id, framework_id="test-fw", is_active=True))
    for cid in ("AC-1", "AC-2"):
        db.add(Control(framework_id="test-fw", control_id=cid, family="AC", family_name="AC", title=cid))
    db.commit()
    today = datetime.now(timezone.utc).date()
    client.put(f"/api/controls/systems/{s.id}/test-fw/AC-1", json={"implementation_status": "IMPLEMENTED",
               "narrative": "done"}, headers=_h(csrf))
    client.post(f"/api/controls/systems/{s.id}/bulk", json={"framework_id": "test-fw", "control_ids": ["AC-2"],
                "implementation_status": "PLANNED"}, headers=_h(csrf))
    db.expire_all()
    dates = {i.control_id: i.assessed_date for i in db.query(ControlImplementation).all()}
    assert dates == {"AC-1": today, "AC-2": today}
    html = zipfile.ZipFile(io.BytesIO(client.get(
        f"/api/reports/audit-binder?system_id={s.id}&framework_id=test-fw").content)).read("binder.html").decode()
    assert today.isoformat() in html
    # Back to Not Assessed clears it.
    client.put(f"/api/controls/systems/{s.id}/test-fw/AC-1", json={"implementation_status": "NOT_ASSESSED"},
               headers=_h(csrf))
    db.expire_all()
    assert db.query(ControlImplementation).filter_by(control_id="AC-1").one().assessed_date is None


def test_evidence_expiry_can_be_set_on_upload_and_edit(auth_client, db):   # R2USER-11
    from datetime import timedelta
    client, seeded, csrf = auth_client
    sid = client.post("/api/systems", json={"name": "EvSys"}, headers=_h(csrf)).json()["id"]
    today = date.today()

    def up(**form):
        return client.post("/api/evidence/upload", data={"system_id": str(sid), "artifact_type": "SCAN_RESULT", **form},
                           files={"file": ("scan.csv", b"a,b\n1,2\n", "text/csv")}, headers=_h(csrf))

    r = up(expiration_days="90")
    assert r.status_code == 200 and r.json()["expiration_date"] == (today + timedelta(days=90)).isoformat()
    r = up(expiration_date=(today + timedelta(days=30)).isoformat())
    assert r.status_code == 200, r.text
    assert r.json()["expiration_date"] == (today + timedelta(days=30)).isoformat()
    assert r.json()["expiration_days"] == 30
    assert up(expiration_date="2099-01-01").status_code == 422

    eid = r.json()["id"]
    new = (today + timedelta(days=200)).isoformat()
    r = client.patch(f"/api/evidence/{eid}", json={"expiration_date": new}, headers=_h(csrf))
    assert r.status_code == 200 and r.json()["expiration_date"] == new and r.json()["expiration_days"] == 200
    # An explicit past date is allowed (recording evidence that is already stale).
    past = (today - timedelta(days=1)).isoformat()
    assert client.patch(f"/api/evidence/{eid}", json={"expiration_date": past}, headers=_h(csrf)).json()["expiration_date"] == past


def test_user_can_change_own_password(db, seeded):   # R2USER-13
    from database import get_db
    from models import User
    from services.auth import hash_password
    db.add(User(organization_id=seeded["org"].id, username="ana", password_hash=hash_password("Initial-Pass-123"),
                email="ana@example.com", display_name="Ana", role="assessor"))
    db.commit()

    def ov():
        yield db
    app.dependency_overrides[get_db] = ov
    try:
        with TestClient(app) as a, TestClient(app) as other, TestClient(app) as anon:
            for c in (a, other):
                r = c.post("/api/auth/login", json={"username": "ana", "password": "Initial-Pass-123"})
                assert r.status_code == 200
                c.headers["X-CSRF-Token"] = c.cookies.get("universal_csrf") or ""
            raw = a.post("/api/tokens", json={"name": "bot"}).json()["token"]
            url = "/api/auth/change-password"
            # An API token is not enough: changing the password needs a browser session.
            assert anon.post(url, json={"current_password": "Initial-Pass-123", "new_password": "Brand-New-Pass-456"},
                             headers={"Authorization": f"Bearer {raw}"}).status_code == 401
            assert a.post(url, json={"current_password": "wrong", "new_password": "Brand-New-Pass-456"}).status_code == 400
            weak = a.post(url, json={"current_password": "Initial-Pass-123", "new_password": "short"})
            assert weak.status_code == 422 and "12" in weak.json()["detail"]
            r = a.post(url, json={"current_password": "Initial-Pass-123", "new_password": "Brand-New-Pass-456"})
            assert r.status_code == 200, r.text
            assert r.json()["other_sessions_signed_out"] == 1 and r.json()["api_tokens_revoked"] == 1
            assert a.get("/api/auth/me").status_code == 200            # this session stays signed in
            assert other.get("/api/auth/me").status_code == 401        # every other session is signed out
            assert anon.get("/api/auth/me", headers={"Authorization": f"Bearer {raw}"}).status_code == 401
            assert anon.post("/api/auth/login", json={"username": "ana", "password": "Initial-Pass-123"}).status_code == 401
            assert anon.post("/api/auth/login", json={"username": "ana", "password": "Brand-New-Pass-456"}).status_code == 200
    finally:
        app.dependency_overrides.clear()


def test_one_version_everywhere(client):   # R2USER-19
    from version import __version__
    root = Path(__file__).resolve().parents[3]
    assert client.get("/api/health").json()["version"] == __version__
    assert app.version == __version__
    assert json.loads((root / "frontend/package.json").read_text())["version"] == __version__
    # The UI must not hard-code its own copy (Settings → About said v1.0.0 while package.json said 1.1.0).
    import re
    hard = [str(p.relative_to(root)) for p in (root / "frontend/src").rglob("*.tsx")
            if re.search(r"Athorize v\d", p.read_text())]
    assert hard == []


def test_assigned_owner_can_work_their_finding_and_picker_lists_only_workers(db, seeded):   # R2USER-12
    from database import get_db
    from models import User
    from models.system_assignment import SystemAssignment
    from services.auth import hash_password
    org = seeded["org"].id
    erp = System(organization_id=org, name="ERP", acronym="ERP"); scada = System(organization_id=org, name="SCADA", acronym="SC")
    db.add_all([erp, scada]); db.flush()
    pw = hash_password("Owner-Pass-1234")
    users = {n: User(organization_id=org, username=n, password_hash=pw, email=f"{n}@example.com", display_name=n, role=r)
             for n, r in [("sam", "system_owner"), ("sue", "system_owner"), ("aud", "auditor"), ("eve", "evidence_contributor")]}
    db.add_all(users.values()); db.flush()
    db.add(SystemAssignment(user_id=users["eve"].id, system_id=scada.id))   # Eve may only see SCADA
    f = Finding(organization_id=org, system_id=erp.id, framework_id="fw", title="Zerologon", severity="HIGH",
                status="OPEN", owner_id=users["sam"].id)
    db.add(f); db.commit()

    def ov():
        yield db
    app.dependency_overrides[get_db] = ov
    try:
        with TestClient(app) as c:
            _login(c)
            names = {u["username"] for u in c.get(f"/api/users/assignable?finding_system_id={erp.id}").json()}
            assert names == {"testadmin", "sam", "sue"}          # no auditor; Eve can't see ERP
            assert "eve" in {u["username"] for u in c.get(f"/api/users/assignable?finding_system_id={scada.id}").json()}
            assert len(c.get("/api/users/assignable").json()) == 5   # unfiltered directory unchanged

        def as_user(name):
            c = TestClient(app)
            r = c.post("/api/auth/login", json={"username": name, "password": "Owner-Pass-1234"})
            assert r.status_code == 200
            c.headers["X-CSRF-Token"] = c.cookies.get("universal_csrf") or ""
            return c

        url = f"/api/findings/{f.id}"
        with as_user("sam") as sam:
            assert sam.patch(url, json={"status": "IN_PROGRESS"}).status_code == 200
            r = sam.patch(url, json={"milestones": [{"title": "Patch DCs", "due": "2026-11-01", "complete": False}]})
            assert r.status_code == 200 and r.json()["milestones"][0]["title"] == "Patch DCs"
            assert sam.patch(url, json={"status": "DELAYED"}).status_code == 200
            assert sam.patch(url, json={"title": "renamed"}).status_code == 403
            assert sam.patch(url, json={"status": "CLOSED", "actual_completion": "2026-10-22"}).status_code == 403
            assert sam.patch(url, json={"status": "RISK_ACCEPTED"}).status_code == 403
        with as_user("sue") as sue:   # same role, not the owner
            assert sue.patch(url, json={"status": "OPEN"}).status_code == 403
        f.owner_id = users["aud"].id; db.commit()
        with as_user("aud") as aud:   # the read-only role never works findings
            assert aud.patch(url, json={"status": "OPEN"}).status_code == 403
    finally:
        app.dependency_overrides.clear()


def test_blank_org_has_no_overdue_cadence_until_a_system_has_been_monitored_for_an_interval(db, seeded):   # R2USER-18
    from datetime import timedelta
    from services import conmon_cadence as svc
    org = seeded["org"].id
    assert svc.overdue_count(db, org) == 0                     # nothing registered: nothing can be overdue
    s = System(organization_id=org, name="ERP", acronym="ERP"); db.add(s); db.commit()
    assert svc.overdue_count(db, org) == 0                     # day one: due, not overdue
    rows = {r["activity_type"]: r for r in svc.list_cadences(db, org) if r["framework_id"] == ""}
    assert rows["VULNERABILITY_SCAN"]["status"] == "NEVER"
    assert rows["VULNERABILITY_SCAN"]["next_due"] == (date.today() + timedelta(days=30)).isoformat()
    s.created_at = datetime.now(timezone.utc) - timedelta(days=40); db.commit()
    rows = {r["activity_type"]: r for r in svc.list_cadences(db, org) if r["framework_id"] == ""}
    assert rows["VULNERABILITY_SCAN"]["status"] == "OVERDUE" and rows["VULNERABILITY_SCAN"]["days_overdue"] == 10
    assert rows["POLICY_REVIEW"]["status"] == "NEVER"          # yearly: not due yet
    assert svc.overdue_count(db, org) == 3                      # the three 30-day defaults


def test_owner_picker_filter_cannot_probe_systems_the_caller_cannot_see(db, seeded):   # R2USER-12 (review)
    from database import get_db
    from models import Organization, User
    from models.system_assignment import SystemAssignment
    from services.auth import hash_password
    org = seeded["org"].id
    other = Organization(name="Other Co", slug="other-co"); db.add(other); db.flush()
    erp = System(organization_id=org, name="ERP", acronym="ERP"); scada = System(organization_id=org, name="SCADA", acronym="SC")
    foreign = System(organization_id=other.id, name="Theirs", acronym="TH")
    db.add_all([erp, scada, foreign]); db.flush()
    pw = hash_password("Scoped-Pass-1234")
    sam = User(organization_id=org, username="sam", password_hash=pw, email="s@example.com", display_name="Sam", role="system_owner")
    aud = User(organization_id=org, username="aud", password_hash=pw, email="a@example.com", display_name="Aud", role="auditor")
    db.add_all([sam, aud]); db.flush()
    db.add(SystemAssignment(user_id=sam.id, system_id=scada.id))   # Sam sees only SCADA
    db.commit()

    def ov():
        yield db
    app.dependency_overrides[get_db] = ov
    try:
        def as_user(name, password):
            c = TestClient(app)
            assert c.post("/api/auth/login", json={"username": name, "password": password}).status_code == 200
            return c
        with as_user("sam", "Scoped-Pass-1234") as c:
            assert c.get(f"/api/users/assignable?finding_system_id={erp.id}").status_code == 404      # out of scope
            assert c.get(f"/api/users/assignable?finding_system_id={foreign.id}").status_code == 404  # other org
            assert c.get("/api/users/assignable?finding_system_id=999999").status_code == 404        # nonexistent
            r = c.get(f"/api/users/assignable?finding_system_id={scada.id}")
            assert r.status_code == 200 and {u["username"] for u in r.json()} == {"testadmin", "sam"}
        with as_user("aud", "Scoped-Pass-1234") as c:   # read-only role may not use the filter at all
            assert c.get(f"/api/users/assignable?finding_system_id={scada.id}").status_code == 403
            assert c.get("/api/users/assignable").status_code == 200
        with as_user("testadmin", "testpass1234!") as c:
            assert c.get(f"/api/users/assignable?finding_system_id={foreign.id}").status_code == 404
            assert c.get(f"/api/users/assignable?finding_system_id={erp.id}").status_code == 200
    finally:
        app.dependency_overrides.clear()


def test_calendar_shows_derived_deadlines_scoped_and_read_only(db, seeded):   # R2USER-4
    from datetime import timedelta
    from database import get_db
    from models import EvidenceArtifact, User
    from models.assessment import Assessment
    from models.calendar_event import CalendarEvent
    from models.system_assignment import SystemAssignment
    from services.auth import hash_password
    org = seeded["org"].id
    today = date.today()
    erp = System(organization_id=org, name="ERP", acronym="ERP"); scada = System(organization_id=org, name="SCADA", acronym="SC")
    db.add_all([erp, scada]); db.flush()
    db.add_all([
        Finding(organization_id=org, system_id=erp.id, framework_id="fw", title="Zerologon", severity="HIGH",
                status="OPEN", due_date=today + timedelta(days=7),
                milestones=[{"title": "Patch DCs", "due": (today + timedelta(days=3)).isoformat(), "complete": False},
                            {"title": "Done step", "due": (today + timedelta(days=2)).isoformat(), "complete": True}]),
        Finding(organization_id=org, system_id=erp.id, framework_id="fw", title="Brute Force", severity="MEDIUM",
                status="IN_PROGRESS", due_date=today - timedelta(days=1)),
        Finding(organization_id=org, system_id=erp.id, framework_id="fw", title="Closed one", severity="LOW",
                status="CLOSED", due_date=today + timedelta(days=5)),
        Finding(organization_id=org, system_id=scada.id, framework_id="fw", title="SCADA finding", severity="LOW",
                status="OPEN", due_date=today + timedelta(days=9)),
        EvidenceArtifact(organization_id=org, system_id=erp.id, filename="scan.csv", artifact_type="SCAN_RESULT",
                         expiration_date=today + timedelta(days=90), control_ids=[], framework_ids=[]),
        Assessment(organization_id=org, system_id=erp.id, framework_id="fw", assessment_type="ANNUAL", status="PLANNED"),
        CalendarEvent(organization_id=org, title="Kickoff", event_date=today + timedelta(days=4), event_type="CUSTOM"),
    ])
    sam = User(organization_id=org, username="sam", password_hash=hash_password("Scoped-Pass-1234"),
               email="s@example.com", display_name="Sam", role="system_owner")
    db.add(sam); db.flush(); db.add(SystemAssignment(user_id=sam.id, system_id=scada.id)); db.commit()

    def ov():
        yield db
    app.dependency_overrides[get_db] = ov
    try:
        with TestClient(app) as c:
            _login(c)
            items = c.get("/api/calendar").json()
            titles = {e["title"] for e in items}
            assert {"Kickoff", "Finding due: Zerologon", "Finding due: Brute Force", "Milestone: Patch DCs",
                    "Evidence expires: scan.csv", "Assessment planned: Annual"} <= titles
            assert "Finding due: Closed one" not in titles and "Milestone: Done step" not in titles
            assert any(t.startswith("ConMon due: ") for t in titles)     # a system exists, so cadences are due
            derived = [e for e in items if e["source"] == "derived"]
            assert derived and all(e["id"] is None and e["derived_key"] for e in derived)
            assert [e for e in items if e["title"] == "Kickoff"][0]["source"] == "manual"
            zl = [e for e in items if e["title"] == "Finding due: Zerologon"][0]
            assert zl["link"] == f"/findings?focus={zl['related_entity_id']}"
            assert {e["title"] for e in c.get("/api/calendar?derived=false").json()} == {"Kickoff"}
            assert "Finding due: SCADA finding" not in {e["title"] for e in c.get(f"/api/calendar?system_id={erp.id}").json()}
        with TestClient(app) as c:
            assert c.post("/api/auth/login", json={"username": "sam", "password": "Scoped-Pass-1234"}).status_code == 200
            titles = {e["title"] for e in c.get("/api/calendar").json()}
            assert "Finding due: SCADA finding" in titles
            assert not any("Zerologon" in t or "scan.csv" in t or "Brute Force" in t for t in titles)
    finally:
        app.dependency_overrides.clear()


def test_crosswalk_queue_says_why_it_is_empty(auth_client, db):   # R2USER-15
    from models import ControlImplementation, ControlMapping
    client, seeded, _ = auth_client
    org = seeded["org"].id
    s = System(organization_id=org, name="ERP", acronym="ERP"); db.add(s); db.flush()
    for fw in ("cmmc-2.0", "nist-800-53-r5"):
        db.add(FrameworkActivation(organization_id=org, framework_id=fw, is_active=True))
    db.add(ControlMapping(source_framework_id="cmmc-2.0", source_control_id="AC.L2-3.1.1",
                          target_framework_id="nist-800-53-r5", target_control_id="AC-2",
                          relationship="intersects", confidence="official", rationale="t"))
    db.commit()
    stats = client.get(f"/api/crosswalk/suggestions?system_id={s.id}").json()["stats"]
    assert stats["satisfied_controls"] == 0
    db.add(ControlImplementation(system_id=s.id, framework_id="cmmc-2.0", control_id="AC.L2-3.1.1",
                                 implementation_status="IMPLEMENTED")); db.commit()
    body = client.get(f"/api/crosswalk/suggestions?system_id={s.id}").json()
    assert body["suggestions"] == []
    assert body["stats"]["satisfied_controls"] == 1
    assert body["stats"]["qualifying_mappings"] == 0 and body["stats"]["weaker_mappings"] == 1


NESSUS_V2 = b"""<?xml version="1.0" ?>
<NessusClientData_v2><Report name="Portal scan">
<ReportHost name="portal.example.com"><HostProperties><tag name="host-ip">10.0.5.10</tag></HostProperties>
<ReportItem port="445" svc_name="cifs" protocol="tcp" severity="4" pluginID="142960" pluginName="Netlogon Elevation of Privilege (Zerologon)" pluginFamily="Windows">
<risk_factor>Critical</risk_factor><synopsis>EoP via Netlogon</synopsis><solution>Apply the patch.</solution><cve>CVE-2020-1472</cve></ReportItem>
<ReportItem port="445" svc_name="cifs" protocol="tcp" severity="4" pluginID="97833" pluginName="MS17-010: Security Update for Microsoft Windows SMB Server (ETERNALBLUE)" pluginFamily="Windows">
<risk_factor>Critical</risk_factor><synopsis>The remote Windows host is affected by multiple vulnerabilities.</synopsis><cve>CVE-2017-0143</cve><cve>CVE-2017-0144</cve></ReportItem>
<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="19506" pluginName="Nessus Scan Information" pluginFamily="Settings">
<risk_factor>None</risk_factor><synopsis>Info about the scan</synopsis></ReportItem>
<ReportItem port="0" svc_name="general" protocol="udp" severity="0" pluginID="10287" pluginName="Traceroute Information" pluginFamily="General">
<risk_factor>None</risk_factor></ReportItem>
</ReportHost></Report></NessusClientData_v2>"""


def test_native_nessus_export_imports(auth_client, db):   # R2USER-16
    client, seeded, csrf = auth_client
    from tests.conftest import activate_framework
    activate_framework(db, seeded["org"], "nist-800-53-r5")   # imports need an active framework (R2DATA-6)
    sid = client.post("/api/systems", json={"name": "Portal"}, headers=_h(csrf)).json()["id"]
    for name in ("portal.nessus", "portal-export.xml"):
        r = client.post("/api/siem/import", data={"system_id": str(sid), "framework_id": "nist-800-53-r5"},
                        files={"file": (name, NESSUS_V2, "application/xml")}, headers=_h(csrf))
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["format"] == "nessus_xml"
        assert body["total_parsed"] == 2 and body["skipped_rows"] == 2        # Risk=None plugins are not findings
        by_title = {p["title"]: p for p in body["preview"]}
        zl = by_title["Netlogon Elevation of Privilege (Zerologon)"]
        assert zl["severity"] == "CRITICAL" and zl["extra_data"]["dst_ip"] == "10.0.5.10"
        assert zl["extra_data"]["dst_port"] == 445 and zl["extra_data"]["cve"] == "CVE-2020-1472"
        assert by_title["MS17-010: Security Update for Microsoft Windows SMB Server (ETERNALBLUE)"]["extra_data"]["cve"] == "CVE-2017-0143, CVE-2017-0144"
    fmts = client.get("/api/siem/formats").json()
    fmts = fmts["formats"] if isinstance(fmts, dict) else fmts
    nessus = [f for f in fmts if f["key"] == "nessus_xml"][0]
    assert ".nessus" in nessus["extensions"]          # the upload picker accepts the file


def test_editor_opened_before_the_control_existed_does_not_overwrite_a_colleagues_first_save(auth_client, db):   # R2DATA-12
    client, seeded, csrf = auth_client
    s = System(organization_id=seeded["org"].id, name="ERP", acronym="ERP"); db.add(s)
    db.add(Control(framework_id="fw", control_id="AC-3", family="AC", family_name="AC", title="x")); db.commit()
    url = f"/api/controls/systems/{s.id}/fw/AC-3"
    # Tab A opens AC-3 (no implementation yet); colleague B saves first.
    assert client.put(url, json={"implementation_status": "IMPLEMENTED", "narrative": "B's narrative"},
                      headers=_h(csrf)).status_code == 200
    r = client.put(url, json={"implementation_status": "PLANNED", "narrative": "A's draft", "expected_updated_at": None},
                   headers=_h(csrf))
    assert r.status_code == 409
    assert client.get(f"/api/controls/systems/{s.id}?framework_id=fw").json()[0]["narrative"] == "B's narrative"
    # A first save with the explicit null on a control nobody created still works.
    db.add(Control(framework_id="fw", control_id="AC-4", family="AC", family_name="AC", title="y")); db.commit()
    assert client.put(f"/api/controls/systems/{s.id}/fw/AC-4", json={"implementation_status": "PLANNED",
                      "expected_updated_at": None}, headers=_h(csrf)).status_code == 200

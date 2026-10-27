"""Demo data has a realistic history (SCA rehearsal): before, every demo row was
created "now", so every finding read DAYS OPEN 0, the SCADA assessment report
showed 0 findings in its window, ConMon said "never logged, 310d overdue" for
activities that were logged, and the Compliance Trend was empty. Dates are
backdated relative to the seed time, deterministically (same seed time, same
data)."""
from datetime import date, datetime, timedelta, timezone

import pytest

from models import Assessment, ConMonEntry, EvidenceArtifact, Finding, Organization
from models.compliance_snapshot import ComplianceSnapshot


@pytest.fixture(autouse=True)
def _no_demo_files_left_behind():
    from services import demo_seed
    demo_seed.discard_demo_files()
    yield
    demo_seed.discard_demo_files()


def _seed(db):
    from services import demo_seed
    demo_seed.seed_demo(db)
    db.commit()
    return db.query(Organization).filter_by(slug="acme-industrial-corp").one()


def _days_ago(dt) -> int:
    if isinstance(dt, datetime):
        dt = dt.astimezone(timezone.utc).date() if dt.tzinfo else dt.date()
    return (date.today() - dt).days


def test_findings_have_realistic_ages(db):
    org = _seed(db)
    findings = db.query(Finding).filter_by(organization_id=org.id).all()
    ages = {f.title: _days_ago(f.created_at) for f in findings}
    assert sum(1 for a in ages.values() if a == 0) <= 1, ages
    assert len(set(ages.values())) >= 8, ages
    assert max(ages.values()) >= 90
    for f in findings:
        assert f.created_at <= datetime.now(timezone.utc)
        if f.due_date and f.status not in ("CLOSED", "RISK_ACCEPTED", "FALSE_POSITIVE"):
            assert f.created_at.date() < f.due_date, f.title
        assert f.updated_at >= f.created_at, f.title
    # The overdue critical finding has been open longer than its 30-day window.
    seg = next(f for f in findings if f.title == "Missing network segmentation")
    assert _days_ago(seg.created_at) > 30


def test_completed_assessment_report_window_has_findings(db):
    from services.assessment_report import findings_in_window
    org = _seed(db)
    scada = db.query(Assessment).filter_by(organization_id=org.id, framework_id="nist-800-82-r3").one()
    assert scada.created_at <= scada.started_at <= scada.completed_at
    assert len(findings_in_window(db, scada)) >= 3


def test_evidence_and_conmon_have_history(db):
    org = _seed(db)
    ev = {e.filename: e for e in db.query(EvidenceArtifact).filter_by(organization_id=org.id)}
    collected = {name: _days_ago(e.date_collected) for name, e in ev.items()}
    assert len(set(collected.values())) >= 5, collected
    scan = ev["quarterly-vuln-scan.pdf"]
    assert scan.expiration_date < date.today() < scan.date_collected + timedelta(days=120)
    for e in ev.values():
        assert _days_ago(e.created_at) == _days_ago(e.date_collected), e.filename

    entries = db.query(ConMonEntry).filter_by(organization_id=org.id).all()
    assert len(entries) >= 12
    assert max(_days_ago(e.entry_date) for e in entries) >= 180
    for e in entries:
        assert _days_ago(e.created_at) == _days_ago(e.entry_date)

    from services import conmon_cadence
    rows = conmon_cadence.list_cadences(db, org.id)
    overdue = [r for r in rows if r["status"] == "OVERDUE"]
    assert overdue, "the demo still has something overdue to show"
    # Nothing the demo logged reads "never logged".
    logged = {e.activity_type for e in entries}
    assert [r for r in overdue if r["last_done"] is None and r["activity_type"] in logged] == []
    pci_scan = next(r for r in rows if (r["framework_id"], r["activity_type"]) == ("pci-dss-v4", "VULNERABILITY_SCAN"))
    assert pci_scan["status"] == "OVERDUE" and pci_scan["last_done"]


def test_compliance_trend_has_past_snapshots(auth_client_demo):
    client, db, org = auth_client_demo
    days = {d for (d,) in db.query(ComplianceSnapshot.snapshot_date).filter(
        ComplianceSnapshot.organization_id == org.id, ComplianceSnapshot.snapshot_date < date.today())}
    assert len(days) >= 8
    hist = client.get("/api/dashboard/history").json()
    assert len(hist) >= 9
    # Today's point is live; the trend improves into it.
    assert hist[0]["avg_score"] <= hist[-1]["avg_score"]


def test_same_seed_time_same_data(db):
    from database import Base
    from tests.conftest import test_engine, TestSession

    def snapshot(session):
        org = _seed(session)
        f = sorted((x.title, _days_ago(x.created_at), _days_ago(x.updated_at), x.status)
                   for x in session.query(Finding).filter_by(organization_id=org.id))
        e = sorted((x.filename, _days_ago(x.date_collected), str(x.expiration_date - date.today()))
                   for x in session.query(EvidenceArtifact).filter_by(organization_id=org.id))
        c = sorted((x.activity_type, x.system_id, _days_ago(x.entry_date))
                   for x in session.query(ConMonEntry).filter_by(organization_id=org.id))
        s = sorted((x.system_id, x.framework_id, _days_ago(x.snapshot_date), x.score_percentage, x.open_findings)
                   for x in session.query(ComplianceSnapshot).filter_by(organization_id=org.id))
        return f, e, c, s

    first = snapshot(db)
    db.close()
    from services import demo_seed
    demo_seed.discard_demo_files()
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    second_db = TestSession()
    try:
        assert snapshot(second_db) == first
    finally:
        second_db.close()


@pytest.fixture
def auth_client_demo(client, db):
    org = _seed(db)
    r = client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert r.status_code == 200
    return client, db, org

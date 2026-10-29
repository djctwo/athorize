"""Daily compliance snapshots + /api/dashboard/history."""
from datetime import date, timedelta

from models import Control, ControlImplementation, FrameworkActivation, System
from models.compliance_snapshot import ComplianceSnapshot
from services.history import snapshot_org


def _setup_scored_system(db, org_id: int):
    system = System(organization_id=org_id, name="Sys", acronym="SYS")
    db.add(system)
    db.flush()
    db.add(FrameworkActivation(organization_id=org_id, framework_id="test-fw", is_active=True))
    for i, status in enumerate(["IMPLEMENTED", "NOT_IMPLEMENTED"]):
        db.add(Control(framework_id="test-fw", control_id=f"C-{i}", title=f"Control {i}"))
        db.add(ControlImplementation(
            system_id=system.id, framework_id="test-fw", control_id=f"C-{i}",
            implementation_status=status,
        ))
    db.commit()
    return system


class TestSnapshots:
    def test_snapshot_writes_and_scores(self, db, seeded):
        _setup_scored_system(db, seeded["org"].id)
        written = snapshot_org(db, seeded["org"].id)
        db.commit()
        assert written == 1
        row = db.query(ComplianceSnapshot).first()
        assert row.score_percentage == 50.0  # 1 of 2 implemented
        assert row.total_controls == 2

    def test_same_day_rerun_is_idempotent(self, db, seeded):
        _setup_scored_system(db, seeded["org"].id)
        snapshot_org(db, seeded["org"].id)
        snapshot_org(db, seeded["org"].id)
        db.commit()
        assert db.query(ComplianceSnapshot).count() == 1

    def test_history_endpoint_aggregates_and_scopes(self, auth_client, db):
        client, seeded, _csrf = auth_client
        system = _setup_scored_system(db, seeded["org"].id)
        for offset, score in ((2, 40.0), (1, 60.0), (0, 80.0)):
            db.add(ComplianceSnapshot(
                organization_id=seeded["org"].id, system_id=system.id,
                framework_id="test-fw", snapshot_date=date.today() - timedelta(days=offset),
                score_percentage=score, total_controls=2, implemented=1,
                open_findings=offset, overdue_findings=0, critical_findings=0,
            ))
        # A snapshot belonging to ANOTHER org must not leak into the series.
        from models import Organization
        other = Organization(name="Other", slug="other-hist")
        db.add(other)
        db.flush()
        db.add(ComplianceSnapshot(
            organization_id=other.id, system_id=system.id, framework_id="test-fw",
            snapshot_date=date.today(), score_percentage=1.0, total_controls=2,
            implemented=0, open_findings=99, overdue_findings=9, critical_findings=9,
        ))
        db.commit()

        rows = client.get("/api/dashboard/history").json()
        # Past days come from the stored snapshots; today's point is always the
        # live score (INTEGRITY-5) — 1 of 2 controls implemented = 50.0, not the
        # 80.0 written into today's snapshot row above.
        assert [r["avg_score"] for r in rows] == [40.0, 60.0, 50.0]
        assert rows[-1]["open_findings"] == 0  # not 99 — other org excluded


# --------------------------------------------------------------------------- averages over pairs with work
# With every framework activated, most system x framework pairs have never been
# touched. Averaging them in pinned the demo's "Avg compliance %" near 2-3%.
# Every average (trend points live and stored, Portfolio) now counts only the
# pairs with work: an assessed control or an open finding (metrics.pair_has_work).

def _untouched_framework(db, org_id: int, fw: str = "idle-fw"):
    """An active framework with a loaded catalog that nobody has started."""
    db.add(FrameworkActivation(organization_id=org_id, framework_id=fw, is_active=True))
    for i in range(3):
        db.add(Control(framework_id=fw, control_id=f"I-{i}", title=f"Idle {i}"))
    db.commit()


class TestAverageOverPairsWithWork:
    def test_todays_trend_point_ignores_pairs_nobody_started(self, auth_client, db):
        client, seeded, _csrf = auth_client
        _setup_scored_system(db, seeded["org"].id)        # 50%, 2 controls assessed
        _untouched_framework(db, seeded["org"].id)         # 0%, nothing assessed, no finding
        point = client.get("/api/dashboard/history").json()[-1]
        assert point["avg_score"] == 50.0                  # was 25.0 (mean with the untouched pair)
        assert point["active_pairs"] == 1

    def test_snapshots_record_assessed_and_past_points_use_the_same_rule(self, auth_client, db):
        client, seeded, _csrf = auth_client
        system = _setup_scored_system(db, seeded["org"].id)
        _untouched_framework(db, seeded["org"].id)
        snapshot_org(db, seeded["org"].id, on=date.today() - timedelta(days=1))
        db.commit()
        rows = {r.framework_id: r for r in db.query(ComplianceSnapshot).all()}
        assert rows["test-fw"].assessed_controls == 2
        assert rows["idle-fw"].assessed_controls == 0
        # A pre-upgrade row (assessed_controls NULL) counts when it had implemented controls.
        db.add(ComplianceSnapshot(
            organization_id=seeded["org"].id, system_id=system.id, framework_id="test-fw",
            snapshot_date=date.today() - timedelta(days=2), score_percentage=30.0, total_controls=2,
            implemented=1, open_findings=0, overdue_findings=0, critical_findings=0,
        ))
        db.add(ComplianceSnapshot(
            organization_id=seeded["org"].id, system_id=system.id, framework_id="idle-fw",
            snapshot_date=date.today() - timedelta(days=2), score_percentage=0.0, total_controls=3,
            implemented=0, open_findings=0, overdue_findings=0, critical_findings=0,
        ))
        db.commit()
        hist = client.get("/api/dashboard/history").json()
        assert [(p["avg_score"], p["active_pairs"]) for p in hist] == [(30.0, 1), (50.0, 1), (50.0, 1)]

    def test_a_pair_with_only_an_open_finding_counts_at_zero(self, auth_client, db):
        from models import Finding
        client, seeded, _csrf = auth_client
        system = _setup_scored_system(db, seeded["org"].id)
        _untouched_framework(db, seeded["org"].id)
        db.add(Finding(organization_id=seeded["org"].id, system_id=system.id, framework_id="idle-fw",
                       title="Open on an unstarted framework", severity="HIGH", status="OPEN"))
        db.commit()
        point = client.get("/api/dashboard/history").json()[-1]
        assert (point["avg_score"], point["active_pairs"]) == (25.0, 2)

    def test_no_pair_with_work_means_no_average(self, auth_client, db):
        client, seeded, _csrf = auth_client
        db.add(System(organization_id=seeded["org"].id, name="Sys", acronym="SYS"))
        _untouched_framework(db, seeded["org"].id)
        point = client.get("/api/dashboard/history").json()[-1]
        assert (point["avg_score"], point["active_pairs"]) == (None, 0)

    def test_compliance_pairs_carry_the_has_work_flag(self, auth_client, db):
        client, seeded, _csrf = auth_client
        _setup_scored_system(db, seeded["org"].id)
        _untouched_framework(db, seeded["org"].id)
        flags = {p["framework_id"]: p["has_work"] for p in client.get("/api/dashboard/compliance").json()}
        assert flags == {"test-fw": True, "idle-fw": False}

    def test_portfolio_average_uses_the_same_pairs(self, auth_client, db):
        from models import User
        client, seeded, _csrf = auth_client
        _setup_scored_system(db, seeded["org"].id)
        _untouched_framework(db, seeded["org"].id)
        db.query(User).filter(User.id == seeded["admin"].id).update({"is_operator": True})
        db.commit()
        port = {c["id"]: c for c in client.get("/api/orgs/portfolio").json()["companies"]}[seeded["org"].id]
        assert (port["avg_score"], port["active_pairs"]) == (50.0, 1)


def test_upgrade_adds_assessed_controls_to_existing_snapshots(tmp_path):
    """An install from before this change has compliance_snapshots without the
    column; startup adds it and keeps the old rows (NULL = legacy rule)."""
    import sqlalchemy as sa
    from database import Base
    from main import run_schema_migrations
    eng = sa.create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    Base.metadata.create_all(eng)
    with eng.begin() as c:
        c.execute(sa.text("ALTER TABLE compliance_snapshots DROP COLUMN assessed_controls"))
        c.execute(sa.text("INSERT INTO organizations (id, name, slug) VALUES (1, 'Acme', 'acme')"))
        c.execute(sa.text("INSERT INTO systems (id, organization_id, name, acronym) VALUES (1, 1, 'S', 'S')"))
        c.execute(sa.text("INSERT INTO compliance_snapshots (organization_id, system_id, framework_id, snapshot_date,"
                          " score_percentage, total_controls, implemented, open_findings, critical_findings,"
                          " overdue_findings) VALUES (1, 1, 'fw', '2026-01-01', 40, 10, 4, 0, 0, 0)"))
    run_schema_migrations(eng)
    assert "assessed_controls" in {c["name"] for c in sa.inspect(eng).get_columns("compliance_snapshots")}
    with eng.connect() as c:
        assert c.execute(sa.text("SELECT score_percentage, assessed_controls FROM compliance_snapshots")).one() == (40.0, None)
    eng.dispose()

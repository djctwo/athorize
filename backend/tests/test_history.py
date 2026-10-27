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

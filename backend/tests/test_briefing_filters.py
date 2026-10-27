"""Executive Briefing honours the Reports page System / Framework filters: the
numbers it reads from the backend must be filterable the same way."""
from models import Control, EvidenceArtifact, Finding, FrameworkActivation, System
from models.redteam import RedTeamReport
from datetime import date, timedelta


def _sys(db, org, acr):
    s = System(organization_id=org.id, name=acr, acronym=acr, description="", system_type="",
               environment="production", criticality="moderate")
    db.add(s)
    db.flush()
    return s


def test_snapshot_filters_by_framework(auth_client, db):
    client, seeded, _ = auth_client
    org = seeded["org"]
    for fw in ("x", "y"):
        db.add(FrameworkActivation(organization_id=org.id, framework_id=fw, is_active=True))
        db.add(Control(framework_id=fw, control_id="AC-2", title="x"))
    s = _sys(db, org, "S1")
    db.add(Finding(organization_id=org.id, system_id=s.id, framework_id="x", control_id="AC-2", title="a", severity="CRITICAL", status="OPEN"))
    db.add(Finding(organization_id=org.id, system_id=s.id, framework_id="y", control_id="AC-2", title="b", severity="HIGH", status="DELAYED",
                   due_date=date.today() - timedelta(days=1)))
    db.add(EvidenceArtifact(organization_id=org.id, system_id=s.id, filename="old.pdf", control_ids=["AC-2"],
                            framework_ids=["y"], expiration_date=date.today() - timedelta(days=2)))
    db.commit()
    x = client.get("/api/dashboard/snapshot?framework_id=x").json()
    y = client.get(f"/api/dashboard/snapshot?framework_id=y&system_id={s.id}").json()
    assert (x["open_findings"], x["critical_findings"], x["overdue_findings"], x["expired_evidence"]) == (1, 1, 0, 0)
    assert (y["open_findings"], y["delayed_findings"], y["overdue_findings"], y["expired_evidence"]) == (1, 1, 1, 1)


def test_exposure_summary_filters_by_system_and_framework(auth_client, db):
    client, seeded, _ = auth_client
    org = seeded["org"]
    a, b = _sys(db, org, "A"), _sys(db, org, "B")
    for sid, fw, hi in ((a.id, "x", 1000), (a.id, "y", 2000), (b.id, "x", 4000)):
        db.add(RedTeamReport(organization_id=org.id, system_id=sid, framework_id=fw, run_by="t", summary="",
                             total_findings=1, total_exposure_low=hi // 2, total_exposure_high=hi,
                             findings=[], attack_chains=[]))
    db.commit()
    all_ids = client.get("/api/redteam/exposure-summary").json()["report_ids"]
    only_a = client.get(f"/api/redteam/exposure-summary?system_id={a.id}").json()["report_ids"]
    a_x = client.get(f"/api/redteam/exposure-summary?system_id={a.id}&framework_id=x").json()
    assert len(all_ids) == 3 and len(only_a) == 2 and len(a_x["report_ids"]) == 1
    assert a_x["total_exposure_high"] <= 1000

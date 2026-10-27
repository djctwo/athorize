"""Assessment report (GET /api/reports/assessment/{id}) — content, scoping, 404s."""
from datetime import date, datetime, timedelta

from models import (
    AuditEntry, Assessment, Control, ControlImplementation, EvidenceArtifact,
    Finding, Organization, System, SystemAssignment, User,
)
from services.auth import hash_password


def _setup(db, org_id):
    """A completed assessment with a bounded window, controls in/out of
    narrative, linked + unlinked evidence, and findings in/after the window."""
    system = System(organization_id=org_id, name="Report System", acronym="REP")
    db.add(system)
    db.flush()
    db.add(Control(framework_id="rep-fw", control_id="AC-1", title="Access Policy"))
    db.add(Control(framework_id="rep-fw", control_id="AC-2", title="Account Mgmt"))
    db.add(ControlImplementation(
        system_id=system.id, framework_id="rep-fw", control_id="AC-1",
        implementation_status="IMPLEMENTED", narrative="MFA enforced via IdP.",
        assessment_result="SATISFIED",
    ))
    db.add(EvidenceArtifact(
        organization_id=org_id, system_id=system.id, filename="mfa-policy.pdf",
        artifact_type="policy", control_ids=["AC-1"], framework_ids=["rep-fw"],
        date_collected=date.today(),
    ))
    started = datetime(2026, 6, 1, 9, 0)
    completed = datetime(2026, 6, 30, 17, 0)
    assessment = Assessment(
        organization_id=org_id, system_id=system.id, framework_id="rep-fw",
        assessment_type="Annual Review", status="COMPLETE",
        started_at=started, completed_at=completed, notes="Q2 assessment cycle.",
    )
    db.add(assessment)
    db.flush()
    # Created inside the window, since closed → included (created in window).
    db.add(Finding(
        organization_id=org_id, system_id=system.id, framework_id="rep-fw",
        control_id="AC-2", title="Stale accounts found", severity="HIGH",
        status="CLOSED", created_at=started + timedelta(days=3),
    ))
    # Created before the window, still open at its end → included.
    db.add(Finding(
        organization_id=org_id, system_id=system.id, framework_id="rep-fw",
        control_id="AC-1", title="Legacy open weakness", severity="MEDIUM",
        status="OPEN", created_at=started - timedelta(days=30),
    ))
    # Created AFTER the assessment completed → excluded.
    db.add(Finding(
        organization_id=org_id, system_id=system.id, framework_id="rep-fw",
        control_id="AC-2", title="Post-window finding", severity="LOW",
        status="OPEN", created_at=completed + timedelta(days=5),
    ))
    db.commit()
    return system, assessment


def test_report_content(auth_client, db):
    client, seeded, _ = auth_client
    _, assessment = _setup(db, seeded["org"].id)

    r = client.get(f"/api/reports/assessment/{assessment.id}")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert "inline" in r.headers["content-disposition"]

    html = r.text
    # Cover / summary
    assert "Assessment Report" in html
    assert "Test Org" in html and "Report System" in html
    assert "Annual Review" in html and "COMPLETE" in html
    assert "Q2 assessment cycle." in html
    # Per-control results: status, narrative, linked evidence names
    assert "AC-1" in html and "AC-2" in html
    assert "MFA enforced via IdP." in html
    assert "Implemented" in html and "Not Assessed" in html
    assert "mfa-policy.pdf" in html
    # Findings window: in-window + still-open included, post-window excluded
    assert "Stale accounts found" in html
    assert "Legacy open weakness" in html
    assert "Post-window finding" not in html
    # Sign-off block
    assert "Sign-off" in html and "Signature" in html


def test_report_audit_logged(auth_client, db):
    client, seeded, _ = auth_client
    _, assessment = _setup(db, seeded["org"].id)
    assert client.get(f"/api/reports/assessment/{assessment.id}").status_code == 200
    entry = db.query(AuditEntry).filter(
        AuditEntry.organization_id == seeded["org"].id,
        AuditEntry.entity_type == "assessment_report",
        AuditEntry.entity_id == assessment.id,
    ).first()
    assert entry is not None
    assert entry.action == "EXPORT"
    assert "Annual Review" in entry.summary


def test_report_unknown_id_404(auth_client, db):
    client, _, _ = auth_client
    assert client.get("/api/reports/assessment/999999").status_code == 404


def test_report_org_isolation(auth_client, db):
    client, seeded, _ = auth_client
    _setup(db, seeded["org"].id)
    other = Organization(name="Foreign Org", slug="foreign-report")
    db.add(other)
    db.flush()
    foreign_sys = System(organization_id=other.id, name="Not Yours", acronym="NY")
    db.add(foreign_sys)
    db.flush()
    foreign_assessment = Assessment(
        organization_id=other.id, system_id=foreign_sys.id,
        framework_id="rep-fw", assessment_type="Foreign Review",
    )
    db.add(foreign_assessment)
    db.commit()
    r = client.get(f"/api/reports/assessment/{foreign_assessment.id}")
    assert r.status_code == 404


def test_report_scoped_user(client, db, seeded):
    org = seeded["org"]
    system_a, assessment_a = _setup(db, org.id)
    system_b = System(organization_id=org.id, name="Other System", acronym="OTH")
    db.add(system_b)
    db.flush()
    assessment_b = Assessment(
        organization_id=org.id, system_id=system_b.id, framework_id="rep-fw",
        assessment_type="Other Review",
    )
    db.add(assessment_b)
    db.flush()
    scoped = User(organization_id=org.id, username="scopedrep",
                  password_hash=hash_password("scopedpass123!"), role="assessor")
    db.add(scoped)
    db.flush()
    db.add(SystemAssignment(user_id=scoped.id, system_id=system_a.id))
    db.commit()

    r = client.post("/api/auth/login",
                    json={"username": "scopedrep", "password": "scopedpass123!"})
    assert r.status_code == 200
    # Assigned system's assessment → visible
    assert client.get(f"/api/reports/assessment/{assessment_a.id}").status_code == 200
    # Unassigned system's assessment → hidden (404, not 403)
    assert client.get(f"/api/reports/assessment/{assessment_b.id}").status_code == 404

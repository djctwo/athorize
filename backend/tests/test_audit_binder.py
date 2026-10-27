"""Audit Binder export — zip structure, content, and scoping."""
import io
import zipfile
from datetime import date, timedelta

from config import settings
from models import (
    Control, ControlImplementation, EvidenceArtifact, Finding,
    FrameworkActivation, System,
)


def _setup(db, org_id, tmp_path):
    system = System(organization_id=org_id, name="Binder System", acronym="BIND")
    db.add(system)
    db.flush()
    db.add(FrameworkActivation(organization_id=org_id, framework_id="test-fw", is_active=True))
    db.add(Control(framework_id="test-fw", control_id="AC-1", title="Access Policy"))
    db.add(Control(framework_id="test-fw", control_id="AC-2", title="Account Mgmt"))
    db.add(ControlImplementation(
        system_id=system.id, framework_id="test-fw", control_id="AC-1",
        implementation_status="IMPLEMENTED", narrative="Enforced via IdP policy.",
    ))
    db.add(Finding(
        organization_id=org_id, system_id=system.id, framework_id="test-fw",
        control_id="AC-2", title="Stale accounts", severity="HIGH", status="OPEN",
        due_date=date.today() + timedelta(days=10),
        milestones=[{"title": "Review IdP groups", "due": "2026-07-15", "complete": True}],
    ))
    # Stored the way the upload endpoint stores it: RELATIVE to EVIDENCE_DIR.
    real_dir = settings.evidence_dir / str(system.id)
    real_dir.mkdir(parents=True, exist_ok=True)
    (real_dir / "binder-policy.pdf").write_bytes(b"%PDF-1.4 fake")
    db.add(EvidenceArtifact(
        organization_id=org_id, system_id=system.id, filename="policy.pdf",
        artifact_type="policy", control_ids=["AC-1"], framework_ids=["test-fw"],
        file_path=f"{system.id}/binder-policy.pdf", date_collected=date.today(),
    ))
    db.add(EvidenceArtifact(
        organization_id=org_id, system_id=system.id, filename="ghost.pdf",
        artifact_type="log", control_ids=["AC-2"], framework_ids=["test-fw"],
        file_path="/nonexistent/ghost.pdf", date_collected=date.today(),
    ))
    db.commit()
    return system


def test_binder_zip_contents(auth_client, db, tmp_path):
    client, seeded, _ = auth_client
    system = _setup(db, seeded["org"].id, tmp_path)

    r = client.get(f"/api/reports/audit-binder?system_id={system.id}&framework_id=test-fw")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/zip"

    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = z.namelist()
    assert "binder.html" in names
    assert any(n.startswith("evidence/") and "policy" in n for n in names)  # real file archived
    assert not any("ghost" in n for n in names)  # missing file NOT archived

    html = z.read("binder.html").decode()
    assert "Audit Binder" in html and "Binder System" in html
    assert "AC-1" in html and "Enforced via IdP policy." in html
    assert "Stale accounts" in html and "Review IdP groups" in html  # POA&M + milestone
    assert "not archived" in html  # ghost.pdf marked


def test_binder_scoping(auth_client, db, tmp_path):
    client, seeded, _ = auth_client
    system = _setup(db, seeded["org"].id, tmp_path)
    # inactive framework → 404
    r = client.get(f"/api/reports/audit-binder?system_id={system.id}&framework_id=never-active")
    assert r.status_code == 404
    # foreign system → 404
    from models import Organization
    other = Organization(name="Foreign", slug="foreign-binder")
    db.add(other)
    db.flush()
    foreign_sys = System(organization_id=other.id, name="Not Yours", acronym="NY")
    db.add(foreign_sys)
    db.commit()
    r = client.get(f"/api/reports/audit-binder?system_id={foreign_sys.id}&framework_id=test-fw")
    assert r.status_code == 404


def test_rsaw_style_binder(auth_client, db, tmp_path):
    client, seeded, _ = auth_client
    system = _setup(db, seeded["org"].id, tmp_path)
    r = client.get(f"/api/reports/audit-binder?system_id={system.id}&framework_id=test-fw&style=rsaw")
    assert r.status_code == 200
    assert "rsaw_" in r.headers["content-disposition"]
    html = zipfile.ZipFile(io.BytesIO(r.content)).read("binder.html").decode()
    assert "Audit Worksheets (RSAW-style)" in html
    assert "Registered Entity" in html
    assert "Compliance Assessment Approach" in html
    assert "Registered Entity Response" in html
    # invalid style rejected
    assert client.get(f"/api/reports/audit-binder?system_id={system.id}&framework_id=test-fw&style=weird").status_code == 422


def test_nerc_catalog_depth():
    import json
    from pathlib import Path
    cat = json.loads((Path(__file__).resolve().parents[2] / "frameworks" / "nerc-cip" / "catalog.json").read_text())
    ids = {c["id"] for c in cat["controls"]}
    assert len(ids) >= 90                      # deepened from 38
    assert "CIP-012-1-R1" in ids               # previously missing standard
    assert "CIP-007-6-R2.2" in ids             # requirement-part granularity
    assert "CIP-005-5-R2.3" in ids             # MFA for remote access
    assert len(ids) == len(cat["controls"])    # no duplicate ids

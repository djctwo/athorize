"""SECLIVE-8: user-controlled text stored verbatim by the API (finding title,
system name, company name, evidence description, narratives) must be escaped
wherever the server itself renders HTML — the audit binder and the assessment
report are served/opened as HTML in the app's origin."""
import io
import zipfile

from models import Assessment, Control, ControlImplementation, EvidenceArtifact, Finding, FrameworkActivation, System

P = "<script>alert(1)</script><img src=x onerror=alert(2)>"


def _seed(db, org):
    org.name = f"Org {P}"
    s = System(organization_id=org.id, name=f"Sys {P}", acronym="X<b>")
    db.add(s)
    db.flush()
    db.add(FrameworkActivation(organization_id=org.id, framework_id="esc-fw", is_active=True))
    db.add(Control(framework_id="esc-fw", control_id="AC-1", title=f"T {P}", family="AC"))
    db.add(ControlImplementation(system_id=s.id, framework_id="esc-fw", control_id="AC-1",
                                 implementation_status="IMPLEMENTED", narrative=P, responsible_party=P))
    db.add(Finding(organization_id=org.id, system_id=s.id, framework_id="esc-fw", control_id="AC-1",
                   title=f"F {P}", description=P, severity="HIGH", status="OPEN", remediation_plan=P))
    db.add(EvidenceArtifact(organization_id=org.id, system_id=s.id, filename=f"{P}.pdf", description=P,
                            control_ids=["AC-1"], framework_ids=["esc-fw"]))
    a = Assessment(organization_id=org.id, system_id=s.id, framework_id="esc-fw", assessment_type=P)
    db.add(a)
    db.commit()
    return s, a


def _assert_inert(html: str):
    assert "<script>alert(1)" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;alert(1)" in html


def test_binder_escapes_user_text(auth_client, db):
    client, seeded, _ = auth_client
    s, _a = _seed(db, seeded["org"])
    r = client.get(f"/api/reports/audit-binder?system_id={s.id}&framework_id=esc-fw")
    assert r.status_code == 200
    _assert_inert(zipfile.ZipFile(io.BytesIO(r.content)).read("binder.html").decode())


def test_assessment_report_escapes_user_text(auth_client, db):
    client, seeded, _ = auth_client
    _s, a = _seed(db, seeded["org"])
    r = client.get(f"/api/reports/assessment/{a.id}")
    assert r.status_code == 200
    _assert_inert(r.text)

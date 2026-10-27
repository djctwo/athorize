"""Fix wave, team B (tenancy, scoping, frameworks, crosswalk).

Each test pins one hunt finding (ID in the test name/docstring). All were shown
RED on the unfixed code before the fix landed. Synthetic data only (Acme /
example.com).
"""
from __future__ import annotations

import pytest

from tests.conftest import activate_framework

from models import (
    AuditEntry, Control, ControlMapping, EvidenceArtifact, Finding, FrameworkActivation,
    Organization, System, User,
)
from models.system_assignment import SystemAssignment
from services.auth import hash_password

PW = "Tenancy-Test-Pass-91"


def _login(client, username, password=PW):
    client.cookies.clear()
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"X-CSRF-Token": client.cookies.get("universal_csrf")}


@pytest.fixture
def two_orgs(db):
    """Two companies, each with an admin; org A also has a scoped contributor."""
    a = Organization(name="Acme A", slug="acme-a")
    b = Organization(name="Acme B", slug="acme-b")
    db.add_all([a, b])
    db.flush()
    users = {
        "adminA": User(organization_id=a.id, username="adminA", password_hash=hash_password(PW),
                       email="a@example.com", role="admin"),
        "adminB": User(organization_id=b.id, username="adminB", password_hash=hash_password(PW),
                       email="b@example.com", role="admin"),
    }
    db.add_all(users.values())
    db.flush()
    sa = System(organization_id=a.id, name="ERP", acronym="ERP")
    sb = System(organization_id=b.id, name="Clinic", acronym="CLN")
    db.add_all([sa, sb])
    db.commit()
    return {"a": a, "b": b, "sysA": sa, "sysB": sb, **users}


# ---------------------------------------------------------------- SECCODE-3 / E2E-2 / INTEGRITY-2

def test_seccode3_deactivate_keeps_shared_catalog_and_mappings_and_is_audited(client, db, two_orgs):
    hA = _login(client, "adminA")
    assert client.post("/api/frameworks/hipaa-security/activate", json={}, headers=hA).status_code == 200
    controls = db.query(Control).filter(Control.framework_id == "hipaa-security").count()
    mappings = db.query(ControlMapping).filter(ControlMapping.source_framework_id == "hipaa-security").count()
    assert controls > 0
    hB = _login(client, "adminB")
    assert client.post("/api/frameworks/hipaa-security/activate", json={}, headers=hB).status_code == 200
    r = client.post("/api/frameworks/hipaa-security/deactivate", headers=hB)
    assert r.status_code == 200
    db.expire_all()
    assert db.query(Control).filter(Control.framework_id == "hipaa-security").count() == controls
    assert db.query(ControlMapping).filter(
        ControlMapping.source_framework_id == "hipaa-security").count() == mappings
    # deactivation is audit-logged in the acting company
    assert db.query(AuditEntry).filter(
        AuditEntry.organization_id == two_orgs["b"].id, AuditEntry.action == "DEACTIVATE",
        AuditEntry.entity_type == "framework").count() == 1
    # last company out unloads the shared catalog
    hA = _login(client, "adminA")
    assert client.post("/api/frameworks/hipaa-security/deactivate", headers=hA).status_code == 200
    db.expire_all()
    assert db.query(Control).filter(Control.framework_id == "hipaa-security").count() == 0


# ---------------------------------------------------------------- SECCODE-4

@pytest.fixture
def custom_dir(tmp_path, monkeypatch, request):
    from config import settings
    from routers.frameworks import loader
    monkeypatch.setattr(settings, "data_dir", tmp_path)
    monkeypatch.setattr(loader, "_custom_dir", tmp_path / "custom_frameworks")
    loader.discover()
    request.addfinalizer(lambda: loader.discover())
    return tmp_path / "custom_frameworks"


def test_seccode4_custom_framework_is_private_to_its_company(client, db, two_orgs, custom_dir):
    hA = _login(client, "adminA")
    fid = client.post("/api/custom-frameworks", json={"name": "Acme A Policy"}, headers=hA).json()["id"]
    assert client.put(f"/api/custom-frameworks/{fid}/controls", headers=hA,
                      json={"controls": [{"id": "POL-1", "title": "Original"}]}).status_code == 200
    assert client.post(f"/api/frameworks/{fid}/activate", json={}, headers=hA).status_code == 200

    hB = _login(client, "adminB")
    # company B cannot overwrite, read, delete, list, activate or browse it
    r = client.put(f"/api/custom-frameworks/{fid}/controls", headers=hB,
                   json={"controls": [{"id": "PWN-1", "title": "Overwritten by B"}]})
    assert r.status_code == 404
    assert client.get(f"/api/custom-frameworks/{fid}/controls").status_code == 404
    assert client.delete(f"/api/custom-frameworks/{fid}", headers=hB).status_code == 404
    assert fid not in {c["id"] for c in client.get("/api/custom-frameworks").json()}
    assert fid not in {f["id"] for f in client.get("/api/frameworks").json()}
    assert client.post(f"/api/frameworks/{fid}/activate", json={}, headers=hB).status_code == 404
    assert client.get(f"/api/frameworks/{fid}").status_code == 404
    assert client.get(f"/api/controls?framework_id={fid}").json() == []
    assert client.get(f"/api/controls/{fid}/POL-1").status_code == 404

    db.expire_all()
    titles = {c.control_id: c.title for c in db.query(Control).filter(Control.framework_id == fid)}
    assert titles == {"POL-1": "Original"}

    # the owner still manages it
    hA = _login(client, "adminA")
    assert [c["id"] for c in client.get(f"/api/custom-frameworks/{fid}/controls").json()] == ["POL-1"]
    assert len(client.get(f"/api/controls?framework_id={fid}").json()) == 1


def test_seccode4_legacy_ownerless_custom_framework_is_operator_only(client, db, two_orgs, custom_dir):
    import json as _json
    from routers.frameworks import loader
    d = custom_dir / "custom-legacy"
    d.mkdir(parents=True)
    (d / "metadata.json").write_text(_json.dumps({"id": "custom-legacy", "name": "Legacy"}))
    (d / "catalog.json").write_text(_json.dumps({"controls": [{"id": "L-1", "title": "x"}]}))
    loader.discover()
    hB = _login(client, "adminB")
    assert client.put("/api/custom-frameworks/custom-legacy/controls", headers=hB,
                      json={"controls": []}).status_code == 404
    db.query(User).filter(User.username == "adminB").update({"is_operator": True})
    db.commit()
    hB = _login(client, "adminB")
    assert client.put("/api/custom-frameworks/custom-legacy/controls", headers=hB,
                      json={"controls": [{"id": "L-1", "title": "y"}]}).status_code == 200


# ---------------------------------------------------------------- INTEGRITY-21

def test_integrity21_startup_refreshes_stale_catalog_without_losing_implementations(db, tmp_path):
    import json as _json
    import shutil
    from pathlib import Path
    from models import ControlImplementation, FrameworkCatalogState
    from services.framework_loader import FrameworkLoader

    bundled = Path(__file__).resolve().parents[3] / "frameworks"
    fw_dir = tmp_path / "frameworks"
    shutil.copytree(bundled / "sox", fw_dir / "sox")
    loader = FrameworkLoader(fw_dir, custom_dir=tmp_path / "custom")
    shipped = {c["id"]: c for c in _json.loads((fw_dir / "sox" / "catalog.json").read_text())["controls"]}
    some_id = sorted(shipped)[0]

    # An install upgraded from an older release: the catalog rows hold the old
    # text and no catalog-state row exists yet.
    org = Organization(name="Acme", slug="acme")
    db.add(org)
    db.flush()
    sysA = System(organization_id=org.id, name="ERP", acronym="ERP")
    db.add(sysA)
    db.add(FrameworkActivation(organization_id=org.id, framework_id="sox", is_active=True))
    for cid, c in shipped.items():
        db.add(Control(framework_id="sox", control_id=cid, title=c.get("title", ""),
                       description="OLD publisher text from a previous release"))
    db.flush()
    db.add(ControlImplementation(system_id=sysA.id, framework_id="sox", control_id=some_id,
                                 implementation_status="IMPLEMENTED", narrative="our narrative"))
    db.commit()

    assert loader.refresh_stale_catalogs(db) == ["sox"]
    db.expire_all()
    rows = {c.control_id: c.description for c in db.query(Control).filter(Control.framework_id == "sox")}
    assert rows == {cid: c.get("description", "") for cid, c in shipped.items()}
    impl = db.query(ControlImplementation).filter(ControlImplementation.control_id == some_id).one()
    assert impl.implementation_status == "IMPLEMENTED" and impl.narrative == "our narrative"
    assert db.get(FrameworkCatalogState, "sox").content_hash == loader.content_hash("sox")

    # unchanged release: no reload on the next start
    assert loader.refresh_stale_catalogs(db) == []

    # a new release ships changed catalog text: reloaded again
    cat = _json.loads((fw_dir / "sox" / "catalog.json").read_text())
    cat["controls"][0]["description"] = "Rewritten summary in the new release"
    (fw_dir / "sox" / "catalog.json").write_text(_json.dumps(cat))
    assert loader.refresh_stale_catalogs(db) == ["sox"]
    db.expire_all()
    assert db.get(Control, ("sox", cat["controls"][0]["id"])).description == "Rewritten summary in the new release"
    assert db.query(ControlImplementation).count() == 1


def test_integrity21_activation_records_catalog_state(client, db, two_orgs):
    from models import FrameworkCatalogState
    from routers.frameworks import loader
    hA = _login(client, "adminA")
    assert client.post("/api/frameworks/sox/activate", json={}, headers=hA).status_code == 200
    db.expire_all()
    assert db.get(FrameworkCatalogState, "sox").content_hash == loader.content_hash("sox")


# ---------------------------------------------------------------- SECCODE-2

def _scoped_user(db, org, system, username, role="assessor"):
    u = User(organization_id=org.id, username=username, password_hash=hash_password(PW),
             email=f"{username}@example.com", role=role)
    db.add(u)
    db.flush()
    db.add(SystemAssignment(user_id=u.id, system_id=system.id))
    db.commit()
    return u


def test_seccode2_assessment_rejects_foreign_or_out_of_scope_system(client, db, two_orgs):
    a, sysA, sysB = two_orgs["a"], two_orgs["sysA"], two_orgs["sysB"]
    hA = _login(client, "adminA")
    r = client.post("/api/assessments", headers=hA, json={
        "system_id": sysB.id, "framework_id": "sox", "assessment_type": "SELF"})
    assert r.status_code == 404  # another company's system
    r = client.post("/api/assessments", headers=hA, json={
        "system_id": sysA.id, "framework_id": "sox", "assessment_type": "SELF",
        "assessor_id": two_orgs["adminB"].id})
    assert r.status_code == 422  # another company's user as assessor

    # a scoped assessor cannot create an assessment on an unassigned system
    other = System(organization_id=a.id, name="SCADA", acronym="SCADA")
    db.add(other)
    db.commit()
    _scoped_user(db, a, other, "scopedA")
    h = _login(client, "scopedA")
    r = client.post("/api/assessments", headers=h, json={
        "system_id": sysA.id, "framework_id": "sox", "assessment_type": "SELF"})
    assert r.status_code == 404
    r = client.post("/api/assessments", headers=h, json={
        "system_id": other.id, "framework_id": "sox", "assessment_type": "SELF"})
    assert r.status_code == 200


def test_seccode2_report_never_renders_another_companys_system(client, db, two_orgs):
    from models import Assessment
    # a legacy row written before validation, pointing at company B's system
    bad = Assessment(organization_id=two_orgs["a"].id, system_id=two_orgs["sysB"].id,
                     framework_id="sox", assessment_type="SELF")
    db.add(bad)
    db.commit()
    _login(client, "adminA")
    r = client.get(f"/api/reports/assessment/{bad.id}")
    assert r.status_code == 404
    assert "Clinic" not in r.text


# ---------------------------------------------------------------- SECLIVE-7

def test_seclive7_create_paths_reject_cross_org_user_and_system_refs(client, db, two_orgs):
    sysA, foreign_user = two_orgs["sysA"], two_orgs["adminB"].id
    activate_framework(db, two_orgs["a"], "sox")  # findings need an active framework (R2DATA-6)
    hA = _login(client, "adminA")
    r = client.post("/api/findings", headers=hA, json={
        "system_id": sysA.id, "framework_id": "sox", "title": "x", "owner_id": foreign_user})
    assert r.status_code == 422
    r = client.post("/api/systems", headers=hA, json={"name": "S2", "owner_id": foreign_user})
    assert r.status_code == 422
    r = client.patch(f"/api/systems/{sysA.id}", headers=hA, json={"owner_id": foreign_user})
    assert r.status_code == 422
    r = client.post("/api/calendar", headers=hA, json={
        "title": "x", "event_date": "2026-12-01", "system_id": two_orgs["sysB"].id})
    assert r.status_code == 404
    # own-org references still work
    r = client.post("/api/findings", headers=hA, json={
        "system_id": sysA.id, "framework_id": "sox", "title": "ok", "owner_id": two_orgs["adminA"].id})
    assert r.status_code == 200
    db.expire_all()
    assert db.query(Finding).filter(Finding.owner_id == foreign_user).count() == 0


# ------------------------------------------- SECLIVE-1 / SECLIVE-3 / SECCODE-8 / E2E-7 (scope reads)

@pytest.fixture
def scoped(client, db, two_orgs):
    """Org A: ERP (out of scope) and SCADA; contributor `plant` sees SCADA only.
    Every surface gets one ERP-only record whose text contains 'Zebra'."""
    from models import IcsAdvisory, IcsAdvisoryMatch, OTAsset, RedTeamReport, RiskRegisterEntry
    from services import audit as audit_svc
    a, erp = two_orgs["a"], two_orgs["sysA"]
    scada = System(organization_id=a.id, name="SCADA plant", acronym="SCADA")
    db.add(scada)
    db.flush()
    _scoped_user(db, a, scada, "plant", role="evidence_contributor")
    f = Finding(organization_id=a.id, system_id=erp.id, framework_id="hipaa-security",
                control_id="164.308(a)(1)(i)", title="Zebra TLS weakness on ERP", severity="HIGH", status="OPEN")
    ev = EvidenceArtifact(organization_id=a.id, system_id=erp.id, filename="zebra-erp.pdf",
                          description="Zebra", control_ids=["AC-2"], framework_ids=["nist-800-53-r5"])
    risk = RiskRegisterEntry(organization_id=a.id, system_id=erp.id, title="Zebra risk")
    rt = RedTeamReport(organization_id=a.id, system_id=erp.id, framework_id="hipaa-security",
                       run_by="x", summary="Zebra gaps", findings=[], attack_chains=[])
    asset = OTAsset(organization_id=a.id, system_id=erp.id, asset_name="Zebra PLC")
    adv = IcsAdvisory(organization_id=a.id, advisory_id="DEMO-ICSA-00-001", title="Zebra PLC advisory")
    db.add_all([f, ev, risk, rt, asset, adv])
    db.flush()
    db.add(IcsAdvisoryMatch(advisory_id=adv.id, ot_asset_id=asset.id, system_id=erp.id, confidence="HIGH"))
    audit_svc.record(db, organization_id=a.id, actor_id=None, actor_username="seed", action="CREATE",
                     entity_type="finding", entity_id=f.id, system_id=erp.id, summary="Created finding: Zebra")
    audit_svc.record(db, organization_id=a.id, actor_id=None, actor_username="seed", action="CREATE",
                     entity_type="system", entity_id=erp.id, summary="Created system: Zebra ERP")
    audit_svc.record(db, organization_id=a.id, actor_id=None, actor_username="seed", action="CREATE",
                     entity_type="system", entity_id=scada.id, summary="Created system: SCADA plant")
    db.commit()
    return {"erp": erp, "scada": scada, "finding": f, "evidence": ev, "report": rt, "advisory": adv}


def _zebra_leaks(client, ids):
    leaks = {}
    s = client.get("/api/search", params={"q": "Zebra"}).json()
    s.update({"systems": client.get("/api/search", params={"q": "ERP"}).json()["systems"]})
    for k in ("findings", "systems", "evidence", "risks"):
        if s[k]:
            leaks[f"search.{k}"] = s[k]
    r = client.get(f"/api/crosswalk/evidence/{ids['evidence'].id}/suggestions")
    if r.status_code != 404:
        leaks["crosswalk.evidence_suggestions"] = r.status_code
    if "Zebra" in client.get("/api/audit").text:
        leaks["audit"] = True
    if "Zebra" in client.get("/api/dashboard/activity").text:
        leaks["dashboard.activity"] = True
    if "ERP" in client.get("/api/reports/compliance-summary").text:
        leaks["reports.compliance_summary"] = True
    if client.get("/api/redteam").json():
        leaks["redteam.list"] = True
    if client.get(f"/api/redteam/{ids['report'].id}").status_code != 404:
        leaks["redteam.get"] = True
    advs = client.get("/api/advisories").json()
    if any(a["matches"] or a["system_acronyms"] for a in advs):
        leaks["advisories.matches"] = True
    one = client.get(f"/api/advisories/{ids['advisory'].id}").json()
    if one.get("matches"):
        leaks["advisories.get.matches"] = True
    return leaks


def test_scoped_user_reads_nothing_from_unassigned_systems(client, db, two_orgs, scoped):
    db.add(FrameworkActivation(organization_id=two_orgs["a"].id, framework_id="hipaa-security", is_active=True))
    db.commit()
    _login(client, "plant")
    assert _zebra_leaks(client, scoped) == {}
    # still sees its own system's entries and the org-level advisory itself
    assert "SCADA plant" in client.get("/api/audit").text
    assert [a["advisory_id"] for a in client.get("/api/advisories").json()] == ["DEMO-ICSA-00-001"]


def test_unscoped_admin_still_sees_everything(client, db, two_orgs, scoped):
    db.add(FrameworkActivation(organization_id=two_orgs["a"].id, framework_id="hipaa-security", is_active=True))
    db.commit()
    _login(client, "adminA")
    leaks = _zebra_leaks(client, scoped)
    assert set(leaks) >= {"search.findings", "search.systems", "search.evidence", "search.risks",
                          "audit", "dashboard.activity", "reports.compliance_summary",
                          "redteam.list", "redteam.get", "advisories.matches"}


def test_e2e7_scoped_assessor_cannot_run_redteam_on_unassigned_system(client, db, two_orgs):
    a, erp = two_orgs["a"], two_orgs["sysA"]
    scada = System(organization_id=a.id, name="SCADA", acronym="SCADA")
    db.add(scada)
    db.add(FrameworkActivation(organization_id=a.id, framework_id="sox", is_active=True))
    db.commit()
    _scoped_user(db, a, scada, "rtassessor", role="assessor")
    h = _login(client, "rtassessor")
    assert client.post(f"/api/redteam/analyze/{erp.id}/sox", headers=h).status_code == 404


# ---------------------------------------------------------------- E2E-14 / KNOWN-5

def _org_user(db, org, username, role):
    u = User(organization_id=org.id, username=username, password_hash=hash_password(PW),
             email=f"{username}@example.com", role=role)
    db.add(u)
    db.commit()
    return u


def test_e2e14_assessor_cannot_create_finding_via_red_team(client, db, two_orgs):
    from models import RedTeamReport
    a, erp = two_orgs["a"], two_orgs["sysA"]
    rt = RedTeamReport(organization_id=a.id, system_id=erp.id, framework_id="sox", run_by="x",
                       findings=[{"id": "RT-001", "title": "t", "description": "d", "control_ids": [],
                                  "finding_language": {"title": "RT gap", "severity": "CRITICAL"}}],
                       attack_chains=[])
    db.add(rt)
    db.commit()
    _org_user(db, a, "assessorA", "assessor")
    h = _login(client, "assessorA")
    assert client.post("/api/findings", headers=h, json={
        "system_id": erp.id, "framework_id": "sox", "title": "x"}).status_code == 403
    assert client.post(f"/api/redteam/{rt.id}/findings/RT-001/create-finding", headers=h).status_code == 403
    assert db.query(Finding).count() == 0
    _org_user(db, a, "managerA", "compliance_manager")
    h = _login(client, "managerA")
    assert client.post(f"/api/redteam/{rt.id}/findings/RT-001/create-finding", headers=h).status_code == 200


def test_known5_finding_close_is_gated_by_approve_permission(client, db, two_orgs, monkeypatch):
    from services import permissions
    a, erp = two_orgs["a"], two_orgs["sysA"]
    f = Finding(organization_id=a.id, system_id=erp.id, framework_id="sox", title="t",
                severity="LOW", status="OPEN")
    db.add(f)
    db.commit()
    _org_user(db, a, "managerA", "compliance_manager")
    # narrow the approver set: managers may still edit but no longer close
    monkeypatch.setitem(permissions.MATRIX, "approve:finding_close", {"admin"})
    h = _login(client, "managerA")
    assert client.patch(f"/api/findings/{f.id}", headers=h, json={"description": "edit ok"}).status_code == 200
    r = client.patch(f"/api/findings/{f.id}", headers=h,
                     json={"status": "CLOSED", "actual_completion": "2026-10-01"})
    assert r.status_code == 403
    assert client.post("/api/findings/bulk", headers=h, json={"ids": [f.id], "status": "RISK_ACCEPTED"}).status_code == 403
    h = _login(client, "adminA")
    assert client.patch(f"/api/findings/{f.id}", headers=h,
                        json={"status": "CLOSED", "actual_completion": "2026-10-01"}).status_code == 200


def test_known5_finding_creating_routes_require_edit_finding():
    """Every route that creates a Finding row takes edit:finding."""
    from fastapi.routing import APIRoute
    from main import app
    from services.permissions import MATRIX
    from tests.test_permission_parity import _effective_roles
    creators = {
        ("POST", "/api/findings"),
        ("POST", "/api/redteam/{report_id}/findings/{finding_id}/create-finding"),
        ("POST", "/api/advisories/{advisory_id}/spawn-finding"),
        ("POST", "/api/risks/{risk_id}/spawn-finding"),
    }
    for r in app.routes:
        if isinstance(r, APIRoute):
            for m in r.methods:
                if (m, r.path) in creators:
                    assert _effective_roles(r) == MATRIX["edit:finding"], (m, r.path)


# ---------------------------------------------------------------- SECCODE-17

def test_seccode17_mentions_only_resolve_to_users_who_can_see_the_item(client, db, two_orgs, monkeypatch):
    a, erp = two_orgs["a"], two_orgs["sysA"]
    scada = System(organization_id=a.id, name="SCADA", acronym="SCADA")
    db.add(scada)
    db.commit()
    _scoped_user(db, a, scada, "plant", role="evidence_contributor")
    insider = _org_user(db, a, "insider", "assessor")
    f = Finding(organization_id=a.id, system_id=erp.id, framework_id="sox", title="ERP gap",
                severity="LOW", status="OPEN")
    db.add(f)
    db.commit()
    sent = []
    from services import email as email_svc
    monkeypatch.setattr(email_svc, "is_configured", lambda: True)
    monkeypatch.setattr(email_svc, "send_email", lambda to, *a, **k: sent.extend(to))
    h = _login(client, "adminA")
    r = client.post("/api/comments", headers=h, json={
        "entity_type": "finding", "entity_id": f.id, "body": "@plant @insider please look"})
    assert r.status_code == 200
    assert r.json()["mentions"] == [insider.id]
    assert sent == ["insider@example.com"]


def test_seccode17_auditor_reads_but_cannot_post_comments(client, db, two_orgs):
    a, erp = two_orgs["a"], two_orgs["sysA"]
    _org_user(db, a, "auditorA", "auditor")
    f = Finding(organization_id=a.id, system_id=erp.id, framework_id="sox", title="t",
                severity="LOW", status="OPEN")
    db.add(f)
    db.commit()
    h = _login(client, "auditorA")
    assert client.get("/api/comments", params={"entity_type": "finding", "entity_id": f.id}).status_code == 200
    r = client.post("/api/comments", headers=h, json={"entity_type": "finding", "entity_id": f.id, "body": "hi"})
    assert r.status_code == 403


# ---------------------------------------------------------------- SECCODE-13

def test_seccode13_connector_creds_only_usable_by_their_company(client, db, two_orgs, monkeypatch):
    import services.asset_connectors as C
    for var in ("TANIUM_URL", "TANIUM_API_TOKEN", "TANIUM_SAVED_QUESTION_ID"):
        monkeypatch.setenv(var, {"TANIUM_URL": "https://tanium.example.com"}.get(var, "42"))
    monkeypatch.delenv("ASSET_SYNC_ORG_SLUG", raising=False)  # target = first company (A)
    pulled = []
    monkeypatch.setattr(C, "fetch_connector", lambda key: pulled.append(key) or [
        {"asset_name": "ws-01", "hostname": "ws-01", "ip_address": "10.0.0.5"}])

    # company B's admin: connector reads as unavailable and pulls are refused
    hB = _login(client, "adminB")
    st = client.get("/api/asset-import/connectors").json()
    tan = next(c for c in st["connectors"] if c["key"] == "tanium")
    assert tan["configured"] is False and "another company" in tan["note"]
    for path in ("/api/asset-import/connectors/tanium/import",
                 "/api/asset-import/connectors/tanium/import/confirm"):
        r = client.post(path, headers=hB, data={"system_id": str(two_orgs["sysB"].id)})
        assert r.status_code == 403, path
    assert pulled == []

    # company A (the connector's company) still pulls
    hA = _login(client, "adminA")
    assert next(c for c in client.get("/api/asset-import/connectors").json()["connectors"]
                if c["key"] == "tanium")["configured"] is True
    r = client.post("/api/asset-import/connectors/tanium/import", headers=hA,
                    data={"system_id": str(two_orgs["sysA"].id)})
    assert r.status_code == 200 and pulled == ["tanium"]

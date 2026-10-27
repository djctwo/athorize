"""Regression tests for round-2 user-journey findings R2USER-5 and R2USER-7
(pre-release review)."""
from models import Control, FrameworkActivation


def _h(csrf):
    return {"X-CSRF-Token": csrf} if csrf else {}


# R2USER-7: evidence linkage silently accepts a control id that does not exist.
def test_evidence_link_rejects_unknown_control(auth_client, db):
    client, seeded, csrf = auth_client
    sid = client.post("/api/systems", json={"name": "EvSys"}, headers=_h(csrf)).json()["id"]
    db.add(FrameworkActivation(organization_id=seeded["org"].id, framework_id="test-fw", is_active=True))
    db.add(Control(framework_id="test-fw", control_id="AC-1", title="x"))
    db.commit()
    up = client.post("/api/evidence/upload", data={"system_id": str(sid), "artifact_type": "POLICY"},
                     files={"file": ("p.pdf", b"%PDF-1.4 x", "application/pdf")}, headers=_h(csrf))
    assert up.status_code == 200, up.text
    r = client.patch(f"/api/evidence/{up.json()['id']}",
                     json={"control_ids": ["AC-1", "AC-99"], "framework_ids": ["test-fw"]}, headers=_h(csrf))
    assert r.status_code in (400, 422), (r.status_code, r.text)


# R2USER-5: a standard Nessus CSV marks informational plugins Risk=None; they
# are not weaknesses and must not become OPEN findings.
def test_nessus_informational_rows_are_skipped_not_imported():
    from services import siem_import as S
    csv = ('"Plugin ID","CVE","CVSS v2.0 Base Score","Risk","Host","Protocol","Port","Name","Synopsis"\n'
           '"97833","CVE-2017-0143","9.3","Critical","10.0.0.5","tcp","445","MS17-010","x"\n'
           '"19506","","","None","10.0.0.5","tcp","0","Nessus Scan Information","x"\n'
           '"11219","","","None","10.0.0.5","tcp","22","Nessus SYN scanner","x"\n'
           '"10287","","","None","10.0.0.5","udp","0","Traceroute Information","x"\n')
    rep = S.parse_file_report(csv, "nessus_csv")
    assert [r["title"] for r in rep.rows] == ["MS17-010"]
    assert rep.summary()["skip_reasons"] == {"informational (Risk=None)": 3}
    assert any("informational" in w for w in rep.warnings())


def test_tenable_info_severity_rows_are_skipped_not_imported():
    from services import siem_import as S
    csv = ("Plugin ID,Plugin Name,Severity,IP Address,Port\n"
           "97833,MS17-010,4,10.0.0.5,445\n19506,Nessus Scan Information,0,10.0.0.5,0\n"
           "10287,Traceroute Information,Info,10.0.0.5,0\n")
    rep = S.parse_file_report(csv, "tenable_csv")
    assert [(r["title"], r["severity"]) for r in rep.rows] == [("MS17-010", "CRITICAL")]
    assert rep.summary()["skipped_rows"] == 2


# R2USER-7: a finding's Control ID must exist in its framework's catalog.
def test_finding_control_id_is_checked_against_the_catalog(auth_client, db):
    from tests.conftest import activate_framework
    client, seeded, csrf = auth_client
    activate_framework(db, seeded["org"], "cmmc-2.0", "AC.L2-3.1.1", "SI.L2-3.14.1")
    sid = client.post("/api/systems", json={"name": "CUI"}, headers=_h(csrf)).json()["id"]
    base = {"system_id": sid, "framework_id": "cmmc-2.0", "title": "t", "severity": "LOW"}
    r = client.post("/api/findings", json={**base, "control_id": "SI.L1-3.14.1"}, headers=_h(csrf))
    assert r.status_code == 422 and "SI.L1-3.14.1" in r.json()["detail"], r.text
    r = client.post("/api/findings", json={**base, "control_id": " ac.l2-3.1.1 "}, headers=_h(csrf))
    assert r.status_code == 200 and r.json()["control_id"] == "AC.L2-3.1.1"  # catalog spelling
    fid = r.json()["id"]
    assert client.patch(f"/api/findings/{fid}", json={"control_id": "AC-2"}, headers=_h(csrf)).status_code == 422
    assert client.patch(f"/api/findings/{fid}", json={"control_id": ""}, headers=_h(csrf)).status_code == 200
    # A finding under a framework that isn't active is refused (it would never be counted).
    r = client.post("/api/findings", json={**base, "framework_id": "nist-800-53-r5"}, headers=_h(csrf))
    assert r.status_code == 422 and "not active" in r.json()["detail"]


def test_finding_csv_import_reports_unknown_controls_and_frameworks(auth_client, db):
    from tests.conftest import activate_framework
    client, seeded, csrf = auth_client
    activate_framework(db, seeded["org"], "test-fw", "AC-1")
    sid = client.post("/api/systems", json={"name": "Imp"}, headers=_h(csrf)).json()["id"]
    rows = [{"title": "ok", "framework_id": "test-fw", "control_id": "ac-1"},
            {"title": "typo", "framework_id": "test-fw", "control_id": "AC-99"},
            {"title": "wrong fw", "framework_id": "nope", "control_id": "AC-1"}]
    r = client.post(f"/api/findings/bulk-import/{sid}", json={"rows": rows, "commit": True}, headers=_h(csrf))
    body = r.json()
    assert body["committed"] == 1, body
    assert {e["field"] for e in body["errors"]} == {"control_id", "framework_id"}


def test_evidence_upload_and_link_use_catalog_spelling(auth_client, db):
    client, seeded, csrf = auth_client
    sid = client.post("/api/systems", json={"name": "EvSys2"}, headers=_h(csrf)).json()["id"]
    db.add(FrameworkActivation(organization_id=seeded["org"].id, framework_id="test-fw", is_active=True))
    db.add(Control(framework_id="test-fw", control_id="AC-1", title="x"))
    db.commit()
    bad = client.post("/api/evidence/upload", data={"system_id": str(sid), "control_ids": '["AC-9"]',
                                                     "framework_ids": '["test-fw"]'},
                      files={"file": ("p.pdf", b"%PDF-1.4 x", "application/pdf")}, headers=_h(csrf))
    assert bad.status_code == 422 and "AC-9" in bad.json()["detail"]
    up = client.post("/api/evidence/upload", data={"system_id": str(sid), "control_ids": '["ac-1"]'},
                     files={"file": ("p.pdf", b"%PDF-1.4 x", "application/pdf")}, headers=_h(csrf))
    assert up.status_code == 200 and up.json()["control_ids"] == ["AC-1"]  # checked against active frameworks
    r = client.patch(f"/api/evidence/{up.json()['id']}", json={"framework_ids": ["ghost-fw"]}, headers=_h(csrf))
    assert r.status_code == 422 and "ghost-fw" in r.json()["detail"]

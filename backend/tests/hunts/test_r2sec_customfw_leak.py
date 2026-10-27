"""R2SEC: another company's private custom framework catalog leaks through
catalog reads that never check framework visibility."""
from tests.hunts.test_tenancy_fixes import _login, two_orgs, custom_dir  # noqa: F401


def _make_private_fw(client):
    hA = _login(client, "adminA")
    fid = client.post("/api/custom-frameworks", json={"name": "Acme A Secret Policy"}, headers=hA).json()["id"]
    r = client.put(f"/api/custom-frameworks/{fid}/controls", headers=hA, json={"controls": [
        {"id": "SEC-1", "title": "PRIVATE-TITLE-ONE", "baselines": ["TIER-GOLD"]},
        {"id": "SEC-2", "title": "PRIVATE-TITLE-TWO", "baselines": ["TIER-SILVER"]},
    ]})
    assert r.status_code == 200
    assert client.post(f"/api/frameworks/{fid}/activate", json={}, headers=hA).status_code == 200
    return fid


def test_baselines_leak(client, db, two_orgs, custom_dir):
    fid = _make_private_fw(client)
    _login(client, "adminB")
    r = client.get(f"/api/controls/baselines?framework_id={fid}")
    assert r.status_code == 404 or r.json() == [], r.json()


def test_inspection_prep_leaks_private_catalog(client, db, two_orgs, custom_dir):
    fid = _make_private_fw(client)
    _login(client, "adminB")
    sysB = two_orgs["sysB"].id
    r = client.get(f"/api/inspection/prep?framework_id={fid}&system_ids={sysB}")
    assert "PRIVATE-TITLE" not in r.text, r.text[:600]


def test_punch_list_csv_leaks_private_catalog(client, db, two_orgs, custom_dir):
    fid = _make_private_fw(client)
    _login(client, "adminB")
    sysB = two_orgs["sysB"].id
    r = client.get(f"/api/inspection/prep/punch-list.csv?framework_id={fid}&system_ids={sysB}")
    assert "PRIVATE-TITLE" not in r.text, r.text[:600]


def test_scope_writes_rows_for_invisible_framework(client, db, two_orgs, custom_dir):
    fid = _make_private_fw(client)
    hB = _login(client, "adminB")
    sysB = two_orgs["sysB"].id
    r = client.post(f"/api/controls/systems/{sysB}/scope", headers=hB,
                    json={"framework_id": fid, "baseline": "TIER-GOLD"})
    assert r.status_code == 404, r.text


def test_name_collision_reveals_other_company_framework(client, db, two_orgs, custom_dir):
    _make_private_fw(client)
    hB = _login(client, "adminB")
    r = client.post("/api/custom-frameworks", json={"name": "Acme A Secret Policy"}, headers=hB)
    assert r.status_code != 409, r.text


def test_assessment_report_leaks_private_catalog(client, db, two_orgs, custom_dir):
    fid = _make_private_fw(client)
    hB = _login(client, "adminB")
    sysB = two_orgs["sysB"].id
    r = client.post("/api/assessments", headers=hB, json={"system_id": sysB, "framework_id": fid,
                                                         "assessment_type": "SELF"})
    if r.status_code >= 400:
        assert r.status_code == 404, r.text   # refused as "not found": fine
        return
    aid = r.json()["id"]
    rep = client.get(f"/api/reports/assessment/{aid}")
    assert "PRIVATE-TITLE" not in rep.text


def test_assessment_report_for_legacy_row_does_not_render_hidden_catalog(client, db, two_orgs, custom_dir):
    """An assessment row created against another company's framework before
    the fix (create now refuses it) must not render that catalog."""
    from models.assessment import Assessment
    fid = _make_private_fw(client)
    _login(client, "adminB")
    a = Assessment(organization_id=two_orgs["sysB"].organization_id, system_id=two_orgs["sysB"].id,
                   framework_id=fid, assessment_type="SELF")
    db.add(a); db.commit()
    rep = client.get(f"/api/reports/assessment/{a.id}")
    assert rep.status_code == 404
    assert "PRIVATE-TITLE" not in rep.text


def test_ssp_import_and_crosswalk_refuse_invisible_framework(client, db, two_orgs, custom_dir):
    import io
    fid = _make_private_fw(client)
    hB = _login(client, "adminB")
    sysB = two_orgs["sysB"].id
    r = client.post("/api/migration/ssp", headers=hB, data={"system_id": str(sysB), "framework_id": fid},
                    files={"file": ("ssp.csv", io.BytesIO(b"control_id,status\nSEC-1,Implemented\n"), "text/csv")})
    assert r.status_code == 404, r.text
    assert client.get(f"/api/crosswalk/{fid}/SEC-1").status_code == 404
    r = client.put(f"/api/controls/systems/{sysB}/{fid}/SEC-1", headers=hB, json={"implementation_status": "IMPLEMENTED"})
    assert r.status_code == 404, r.text

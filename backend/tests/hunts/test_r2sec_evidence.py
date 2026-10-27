import io, zipfile
from config import settings
from models import FrameworkActivation
from services.evidence_store import resolve_evidence_path
from tests.test_evidence_download import _upload, _systems


def test_download_sandbox_csp_survives(auth_client, db):
    client, seeded, csrf = auth_client
    a, _ = _systems(db, seeded["org"])
    art = _upload(client, csrf, a.id)
    r = client.get(f"/api/evidence/{art['id']}/download")
    assert "sandbox" in r.headers["content-security-policy"], r.headers["content-security-policy"]


def test_binder_refuses_or_flags_tampered_file(auth_client, db):
    client, seeded, csrf = auth_client
    a, _ = _systems(db, seeded["org"])
    db.add(FrameworkActivation(organization_id=seeded["org"].id, framework_id="sox", is_active=True))
    db.commit()
    from routers.frameworks import loader
    loader.load_catalog("sox", db); db.commit()
    r = client.post("/api/evidence/upload",
        data={"system_id": str(a.id), "description": "d", "artifact_type": "LOG", "framework_ids": '["sox"]'},
        files={"file": ("orig.txt", b"GENUINE", "text/plain")}, headers={"X-CSRF-Token": csrf})
    art = r.json()
    p = resolve_evidence_path(art["file_path"])
    p.write_bytes(b"TAMPERED")
    assert client.get(f"/api/evidence/{art['id']}/download").status_code == 409
    z = client.get(f"/api/reports/audit-binder?system_id={a.id}&framework_id=sox")
    assert z.status_code == 200, z.text
    names = zipfile.ZipFile(io.BytesIO(z.content)).namelist()
    data = [zipfile.ZipFile(io.BytesIO(z.content)).read(n) for n in names if n.startswith("evidence/")]
    assert b"TAMPERED" not in data, names
    html = zipfile.ZipFile(io.BytesIO(z.content)).read("binder.html").decode()
    assert "HASH MISMATCH" in html

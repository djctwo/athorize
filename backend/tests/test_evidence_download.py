"""E2E-6 / INTEGRITY-24: a stored evidence file can be downloaded again — scoped,
org-checked, served as an attachment with nosniff, and refused when the file
on disk no longer matches the SHA-256 recorded at upload.
E2E-5 / SECCODE-7 / IMPORTS-17: the audit binder resolves the same relative path."""
import io
import zipfile

from config import settings
from models import Control, EvidenceArtifact, FrameworkActivation, Organization, System, SystemAssignment, User
from services.auth import hash_password

PAYLOAD = b"historian export\nline-2\t\xce\xb2-unicode\n"


def _h(csrf):
    return {"X-CSRF-Token": csrf} if csrf else {}


def _login(client, username, password):
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200
    return client.cookies.get("universal_csrf")


def _upload(client, csrf, system_id, name="historian.txt", data=PAYLOAD):
    r = client.post(
        "/api/evidence/upload",
        data={"system_id": str(system_id), "description": "d", "artifact_type": "LOG"},
        files={"file": (name, data, "text/plain")},
        headers=_h(csrf),
    )
    assert r.status_code == 200, r.text
    return r.json()


def _systems(db, org):
    a = System(organization_id=org.id, name="Alpha", acronym="A")
    b = System(organization_id=org.id, name="Bravo", acronym="B")
    db.add_all([a, b])
    db.commit()
    return a, b


def test_download_returns_identical_bytes_as_attachment(auth_client, db):
    client, seeded, csrf = auth_client
    a, _ = _systems(db, seeded["org"])
    art = _upload(client, csrf, a.id, name="policy.svg", data=b"<svg onload='alert(1)'/>")

    r = client.get(f"/api/evidence/{art['id']}/download")
    assert r.status_code == 200
    assert r.content == b"<svg onload='alert(1)'/>"
    assert r.headers["content-disposition"].startswith("attachment")
    assert "policy.svg" in r.headers["content-disposition"]
    assert r.headers["x-content-type-options"] == "nosniff"
    # never rendered inline as SVG/HTML in the app's origin
    assert r.headers["content-type"].startswith("application/octet-stream")


def test_download_is_scoped_and_org_checked(auth_client, db):
    client, seeded, csrf = auth_client
    org = seeded["org"]
    a, b = _systems(db, org)
    art_b = _upload(client, csrf, b.id)

    # A user scoped to system A cannot fetch B's file (404, not 403: don't reveal it).
    scoped = User(organization_id=org.id, username="scopedev", role="auditor",
                  password_hash=hash_password("scopedpass123!"))
    db.add(scoped)
    db.flush()
    db.add(SystemAssignment(user_id=scoped.id, system_id=a.id))
    # A user in another org cannot fetch it either.
    other = Organization(name="Other", slug="other-dl")
    db.add(other)
    db.flush()
    stranger = User(organization_id=other.id, username="strangerdl", role="admin",
                    password_hash=hash_password("strangerpass123!"))
    db.add(stranger)
    db.commit()

    _login(client, "scopedev", "scopedpass123!")
    assert client.get(f"/api/evidence/{art_b['id']}/download").status_code == 404
    _login(client, "strangerdl", "strangerpass123!")
    assert client.get(f"/api/evidence/{art_b['id']}/download").status_code == 404


def test_read_only_role_can_download(auth_client, db):
    client, seeded, csrf = auth_client
    a, _ = _systems(db, seeded["org"])
    art = _upload(client, csrf, a.id)
    db.add(User(organization_id=seeded["org"].id, username="auditdl", role="auditor",
                password_hash=hash_password("auditorpass123!")))
    db.commit()
    _login(client, "auditdl", "auditorpass123!")
    r = client.get(f"/api/evidence/{art['id']}/download")
    assert r.status_code == 200 and r.content == PAYLOAD


def test_tampered_file_is_refused(auth_client, db):
    client, seeded, csrf = auth_client
    a, _ = _systems(db, seeded["org"])
    art = _upload(client, csrf, a.id)
    (settings.evidence_dir / art["file_path"]).write_bytes(b"tampered")
    r = client.get(f"/api/evidence/{art['id']}/download")
    assert r.status_code == 409
    assert "SHA-256" in r.json()["detail"]


def test_path_outside_evidence_dir_is_never_served(auth_client, db, tmp_path):
    client, seeded, _ = auth_client
    a, _ = _systems(db, seeded["org"])
    secret = tmp_path / "secret.txt"
    secret.write_bytes(b"not evidence")
    rows = [
        EvidenceArtifact(organization_id=seeded["org"].id, system_id=a.id, filename="x.txt",
                         file_path=str(secret)),
        EvidenceArtifact(organization_id=seeded["org"].id, system_id=a.id, filename="y.txt",
                         file_path="../../" + secret.name),
    ]
    db.add_all(rows)
    db.commit()
    for row in rows:
        assert client.get(f"/api/evidence/{row.id}/download").status_code == 404


def test_missing_file_is_a_clear_404(auth_client, db):
    client, seeded, _ = auth_client
    a, _ = _systems(db, seeded["org"])
    row = EvidenceArtifact(organization_id=seeded["org"].id, system_id=a.id, filename="seed.pdf",
                           file_path=None)
    db.add(row)
    db.commit()
    r = client.get(f"/api/evidence/{row.id}/download")
    assert r.status_code == 404
    assert "No file" in r.json()["detail"]


def test_uploaded_evidence_lands_in_the_audit_binder(auth_client, db):
    client, seeded, csrf = auth_client
    a, _ = _systems(db, seeded["org"])
    db.add(FrameworkActivation(organization_id=seeded["org"].id, framework_id="bind-fw", is_active=True))
    db.add(Control(framework_id="bind-fw", control_id="AC-1", title="x"))  # linked ids must exist (R2USER-7)
    db.commit()
    art = _upload(client, csrf, a.id, name="access-policy.txt")
    client.patch(f"/api/evidence/{art['id']}", json={"framework_ids": ["bind-fw"], "control_ids": ["AC-1"]},
                 headers=_h(csrf))
    r = client.get(f"/api/reports/audit-binder?system_id={a.id}&framework_id=bind-fw")
    assert r.status_code == 200
    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = [n for n in z.namelist() if n.startswith("evidence/")]
    assert any("access-policy" in n for n in names), z.namelist()
    assert z.read(names[0]) == PAYLOAD
    assert "not archived" not in z.read("binder.html").decode()


def test_windows_made_rows_with_backslash_paths_still_resolve(auth_client, db):
    """R2INSTALL-12: the Windows desktop build stored '1\\abc.pdf'. Restored onto
    Linux/Docker (the tar archive always extracts to 1/abc.pdf) every download,
    the audit binder and freshness reported the file missing."""
    from services.evidence_store import resolve_evidence_path
    client, seeded, csrf = auth_client
    a, _ = _systems(db, seeded["org"])
    art = _upload(client, csrf, a.id)
    row = db.get(EvidenceArtifact, art["id"])
    assert "\\" not in row.file_path and row.file_path.startswith(f"{a.id}/")   # stored portably
    row.file_path = row.file_path.replace("/", "\\")                              # as Windows wrote it
    db.commit()
    assert resolve_evidence_path(row.file_path) == (settings.evidence_dir / str(a.id) /
                                                    row.file_path.split("\\")[-1]).resolve()
    r = client.get(f"/api/evidence/{art['id']}/download")
    assert r.status_code == 200, r.text
    assert r.content == PAYLOAD
    assert resolve_evidence_path("..\\..\\etc\\passwd") is None                    # still contained

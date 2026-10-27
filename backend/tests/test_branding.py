"""Per-company branding (logo) — upload validation (magic-byte sniff, size cap,
SVG rejection), org isolation under the operator org-switch, /auth/me exposure,
and the Audit Binder cover embed."""
import base64

import pytest

from models import Control, ControlImplementation, FrameworkActivation, Organization, System, User
from services.auth import hash_password
from services.branding import MAX_LOGO_BYTES

# A real, decodable 1x1 transparent PNG.
PNG_BYTES = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
)
# JPEG header bytes: SOI + APP0 + a SOF0 frame header (120x50 px). Validation
# sniffs magic bytes and reads the declared size — no decoder dependency.
JPEG_BYTES = (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
              b"\xff\xc0\x00\x11\x08\x00\x32\x00\x78\x03\x01\x22\x00\x02\x11\x01\x03\x11\x01"
              + b"\x00" * 64)
SVG_BYTES = b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>"
GIF_BYTES = b"GIF89a" + b"\x00" * 32


def data_uri(mime: str, raw: bytes) -> str:
    return f"data:{mime};base64,{base64.b64encode(raw).decode()}"


PNG_URI = data_uri("image/png", PNG_BYTES)


def _put(client, csrf, uri):
    return client.put("/api/orgs/branding", json={"logo_data_uri": uri},
                      headers={"X-CSRF-Token": csrf})


def _org_branding(db, org_id):
    db.expire_all()
    org = db.query(Organization).filter(Organization.id == org_id).first()
    return (org.settings or {}).get("branding")


# ---------------------------------------------------------------------------
# Upload validation
# ---------------------------------------------------------------------------

def test_upload_png_stores_canonical_branding(auth_client, db):
    client, seeded, csrf = auth_client
    r = _put(client, csrf, PNG_URI)
    assert r.status_code == 200, r.text
    branding = r.json()["branding"]
    assert branding["logo_data_uri"] == PNG_URI  # already canonical
    assert branding["updated_at"]

    stored = _org_branding(db, seeded["org"].id)
    assert stored["logo_data_uri"] == PNG_URI

    # /auth/me exposes the active company's logo (the payload the UI already fetches)
    assert client.get("/api/auth/me").json()["organization_logo"] == PNG_URI

    # Mutation is audit-logged
    entries = client.get("/api/audit").json()
    assert any("company logo" in e["summary"].lower() and e["action"] == "UPDATE" for e in entries)


def test_upload_jpeg_and_mime_canonicalized_by_sniff(auth_client, db):
    client, seeded, csrf = auth_client
    # Claimed PNG, actual JPEG bytes — the sniff wins and the stored URI says jpeg.
    r = _put(client, csrf, data_uri("image/png", JPEG_BYTES))
    assert r.status_code == 200
    assert r.json()["branding"]["logo_data_uri"].startswith("data:image/jpeg;base64,")


def test_svg_rejected(auth_client):
    client, _, csrf = auth_client
    # Honest SVG mime and SVG smuggled under an image/png claim — both refused.
    assert _put(client, csrf, data_uri("image/svg+xml", SVG_BYTES)).status_code == 422
    assert _put(client, csrf, data_uri("image/png", SVG_BYTES)).status_code == 422


def test_other_formats_and_garbage_rejected(auth_client):
    client, _, csrf = auth_client
    assert _put(client, csrf, data_uri("image/gif", GIF_BYTES)).status_code == 422
    assert _put(client, csrf, "not a data uri").status_code == 422
    assert _put(client, csrf, "data:image/png;base64,!!!not-base64!!!").status_code == 422
    assert _put(client, csrf, "").status_code == 422


def test_size_cap_enforced(auth_client):
    client, _, csrf = auth_client
    # Valid PNG magic but over the decoded cap.
    big = PNG_BYTES[:8] + b"\x00" * MAX_LOGO_BYTES
    assert _put(client, csrf, data_uri("image/png", big)).status_code == 422
    # Absurdly long URI is rejected before decoding.
    assert _put(client, csrf, "data:image/png;base64," + "A" * 500_000).status_code == 422


def test_remove_logo_idempotent(auth_client, db):
    client, seeded, csrf = auth_client
    _put(client, csrf, PNG_URI)
    r = client.delete("/api/orgs/branding", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    assert r.json()["branding"] is None
    assert _org_branding(db, seeded["org"].id) is None
    assert client.get("/api/auth/me").json()["organization_logo"] is None
    # Second delete is a harmless no-op.
    assert client.delete("/api/orgs/branding", headers={"X-CSRF-Token": csrf}).status_code == 200


def test_non_admin_forbidden(auth_client, db):
    client, seeded, _ = auth_client
    db.add(User(organization_id=seeded["org"].id, username="cm", role="compliance_manager",
                display_name="CM", password_hash=hash_password("cmpass123456!")))
    db.commit()
    r = client.post("/api/auth/login", json={"username": "cm", "password": "cmpass123456!"})
    assert r.status_code == 200
    csrf = client.cookies.get("universal_csrf")
    assert _put(client, csrf, PNG_URI).status_code == 403
    assert client.delete("/api/orgs/branding", headers={"X-CSRF-Token": csrf}).status_code == 403


# ---------------------------------------------------------------------------
# Org isolation (operator brands the ACTIVE org; non-operator their own only)
# ---------------------------------------------------------------------------

@pytest.fixture
def multi(db):
    orgA = Organization(name="Alpha Co", slug="alpha")
    orgB = Organization(name="Beta Co", slug="beta")
    db.add_all([orgA, orgB])
    db.flush()
    op = User(organization_id=orgA.id, username="op", role="admin",
              is_operator=True, display_name="Operator",
              password_hash=hash_password("oppass1234!"))
    adminA = User(organization_id=orgA.id, username="alphaadmin", role="admin",
                  display_name="Alpha Admin", password_hash=hash_password("apass1234!"))
    db.add_all([op, adminA])
    db.commit()
    return {"orgA": orgA, "orgB": orgB}


def _login(client, username, password):
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return client.cookies.get("universal_csrf")


def test_operator_brands_active_org_only(client, db, multi):
    csrf = _login(client, "op", "oppass1234!")
    r = client.post("/api/orgs/switch", json={"org_id": multi["orgB"].id},
                    headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200

    assert _put(client, csrf, PNG_URI).status_code == 200

    # Logo landed on the ACTIVE company (B); home company (A) untouched.
    assert _org_branding(db, multi["orgB"].id)["logo_data_uri"] == PNG_URI
    assert _org_branding(db, multi["orgA"].id) is None

    # /auth/me (still switched) shows B's logo.
    assert client.get("/api/auth/me").json()["organization_logo"] == PNG_URI

    # Multi-company invariant: the commit in the branding endpoint must NOT
    # have persisted the in-memory org-switch override to the users row.
    db.expire_all()
    op_row = db.query(User).filter(User.username == "op").first()
    assert op_row.organization_id == multi["orgA"].id

    # Back home, A has no logo.
    client.post("/api/orgs/switch", json={"org_id": multi["orgA"].id},
                headers={"X-CSRF-Token": csrf})
    assert client.get("/api/auth/me").json()["organization_logo"] is None


def test_non_operator_brands_own_org_only(client, db, multi):
    csrf = _login(client, "alphaadmin", "apass1234!")
    assert _put(client, csrf, PNG_URI).status_code == 200
    assert _org_branding(db, multi["orgA"].id)["logo_data_uri"] == PNG_URI
    assert _org_branding(db, multi["orgB"].id) is None


# ---------------------------------------------------------------------------
# Audit Binder cover
# ---------------------------------------------------------------------------

def _binder_setup(db, org_id):
    system = System(organization_id=org_id, name="Brand System", acronym="BRND")
    db.add(system)
    db.flush()
    db.add(FrameworkActivation(organization_id=org_id, framework_id="brand-fw", is_active=True))
    db.add(Control(framework_id="brand-fw", control_id="AC-1", title="Access Policy"))
    db.add(ControlImplementation(
        system_id=system.id, framework_id="brand-fw", control_id="AC-1",
        implementation_status="IMPLEMENTED", narrative="Done.",
    ))
    db.commit()
    return system


def test_binder_cover_contains_logo(auth_client, db):
    import io
    import zipfile

    client, seeded, csrf = auth_client
    system = _binder_setup(db, seeded["org"].id)

    # Without branding: no logo img on the cover.
    r = client.get(f"/api/reports/audit-binder?system_id={system.id}&framework_id=brand-fw")
    assert r.status_code == 200
    html = zipfile.ZipFile(io.BytesIO(r.content)).read("binder.html").decode()
    assert "class='logo'" not in html

    # With branding: the validated data URI is embedded on the cover.
    assert _put(client, csrf, PNG_URI).status_code == 200
    r = client.get(f"/api/reports/audit-binder?system_id={system.id}&framework_id=brand-fw")
    assert r.status_code == 200
    html = zipfile.ZipFile(io.BytesIO(r.content)).read("binder.html").decode()
    assert PNG_URI in html
    assert "class='logo'" in html

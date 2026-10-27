"""SystemAssignment enforcement — per-system visibility for scoped roles."""
import pytest

from models import EvidenceArtifact, Finding, System, SystemAssignment, User
from services.auth import hash_password
from tests.conftest import activate_framework


def _h(csrf):
    return {"X-CSRF-Token": csrf} if csrf else {}


@pytest.fixture
def scoped_env(db, seeded):
    """Two systems; an assessor assigned to only system A; data in both."""
    org = seeded["org"]
    sys_a = System(organization_id=org.id, name="Alpha Plant", acronym="ALP")
    sys_b = System(organization_id=org.id, name="Bravo Plant", acronym="BRV")
    db.add_all([sys_a, sys_b])
    db.flush()
    assessor = User(organization_id=org.id, username="scoped1",
                    password_hash=hash_password("scopedpass123!"), role="assessor")
    db.add(assessor)
    db.flush()
    db.add(SystemAssignment(user_id=assessor.id, system_id=sys_a.id))
    activate_framework(db, org, "test-fw", "AC-1")  # company numbers count active frameworks (R2DATA-6)
    fa = Finding(organization_id=org.id, system_id=sys_a.id, framework_id="test-fw",
                 control_id="AC-1", title="Alpha finding", severity="HIGH", status="OPEN")
    fb = Finding(organization_id=org.id, system_id=sys_b.id, framework_id="test-fw",
                 control_id="AC-1", title="Bravo finding", severity="HIGH", status="OPEN")
    db.add_all([
        fa, fb,
        EvidenceArtifact(organization_id=org.id, system_id=sys_b.id, filename="bravo.pdf"),
    ])
    db.commit()
    return {"sys_a": sys_a, "sys_b": sys_b, "assessor": assessor,
            "finding_a": fa, "finding_b": fb}


def _login(client, username, password):
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200
    return client.cookies.get("universal_csrf")


class TestScoping:
    def test_scoped_user_sees_only_assigned_systems(self, client, scoped_env):
        _login(client, "scoped1", "scopedpass123!")
        systems = client.get("/api/systems").json()
        assert [s["acronym"] for s in systems] == ["ALP"]
        findings = client.get("/api/findings").json()
        assert [f["title"] for f in findings] == ["Alpha finding"]
        assert client.get("/api/evidence").json() == []  # bravo.pdf hidden

    def test_scoped_user_direct_object_access_404(self, client, scoped_env):
        _login(client, "scoped1", "scopedpass123!")
        assert client.get(f"/api/findings/{scoped_env['finding_b'].id}").status_code == 404
        assert client.get(f"/api/systems/{scoped_env['sys_b'].id}").status_code == 404

    def test_scoped_contributor_cannot_upload_to_unassigned_system(self, client, db, scoped_env, seeded):
        # evidence_contributor is a scopeable role WITH write (upload) permission
        contrib = User(organization_id=seeded["org"].id, username="contrib1",
                       password_hash=hash_password("contribpass123!"), role="evidence_contributor")
        db.add(contrib)
        db.flush()
        db.add(SystemAssignment(user_id=contrib.id, system_id=scoped_env["sys_a"].id))
        db.commit()
        csrf = _login(client, "contrib1", "contribpass123!")

        files = {"file": ("proof.txt", b"evidence bytes", "text/plain")}
        r = client.post("/api/evidence/upload", headers=_h(csrf),
                        data={"system_id": str(scoped_env["sys_b"].id)}, files=files)
        assert r.status_code == 404  # unassigned system hidden
        r = client.post("/api/evidence/upload", headers=_h(csrf),
                        data={"system_id": str(scoped_env["sys_a"].id)}, files=files)
        assert r.status_code == 200  # assigned system works

    def test_admin_never_scoped(self, auth_client, db, scoped_env):
        client, seeded, _csrf = auth_client
        # even with assignment rows on the admin, visibility stays org-wide
        db.add(SystemAssignment(user_id=seeded["admin"].id, system_id=scoped_env["sys_a"].id))
        db.commit()
        acronyms = {s["acronym"] for s in client.get("/api/systems").json()}
        assert {"ALP", "BRV"} <= acronyms

    def test_unassigned_user_stays_org_wide(self, client, db, scoped_env, seeded):
        free = User(organization_id=seeded["org"].id, username="free1",
                    password_hash=hash_password("freepass1234!"), role="assessor")
        db.add(free)
        db.commit()
        _login(client, "free1", "freepass1234!")
        assert len(client.get("/api/systems").json()) >= 2  # no assignments = unrestricted

    def test_dashboard_scoped(self, client, scoped_env):
        _login(client, "scoped1", "scopedpass123!")
        snap = client.get("/api/dashboard/snapshot").json()
        assert snap["open_findings"] == 1  # only Alpha's finding counted


class TestAssignmentApi:
    def test_set_and_get_assignments(self, auth_client, db, scoped_env, seeded):
        client, _seeded, csrf = auth_client
        uid = scoped_env["assessor"].id
        r = client.put(f"/api/users/{uid}/systems", json={
            "system_ids": [scoped_env["sys_a"].id, scoped_env["sys_b"].id],
        }, headers=_h(csrf))
        assert r.status_code == 200
        got = client.get(f"/api/users/{uid}/systems").json()
        assert set(got["system_ids"]) == {scoped_env["sys_a"].id, scoped_env["sys_b"].id}
        # clearing restores org-wide
        client.put(f"/api/users/{uid}/systems", json={"system_ids": []}, headers=_h(csrf))
        assert client.get(f"/api/users/{uid}/systems").json()["system_ids"] == []

    def test_cross_org_system_rejected(self, auth_client, db, scoped_env):
        client, seeded, csrf = auth_client
        from models import Organization
        other = Organization(name="OtherScope", slug="other-scope")
        db.add(other)
        db.flush()
        foreign = System(organization_id=other.id, name="Foreign", acronym="FRN")
        db.add(foreign)
        db.commit()
        r = client.put(f"/api/users/{scoped_env['assessor'].id}/systems", json={
            "system_ids": [foreign.id],
        }, headers=_h(csrf))
        assert r.status_code == 422

    def test_non_admin_cannot_manage_assignments(self, client, scoped_env):
        csrf = _login(client, "scoped1", "scopedpass123!")
        r = client.put(f"/api/users/{scoped_env['assessor'].id}/systems",
                       json={"system_ids": []}, headers=_h(csrf))
        assert r.status_code == 403

"""Evidence list: refresh-owner display name + owner (mine) filter."""
from models import EvidenceArtifact, System, User
from services.auth import hash_password


def _mk_system(db, org_id, name="EvSys"):
    s = System(organization_id=org_id, name=name, acronym=name[:4].upper())
    db.add(s)
    db.flush()
    return s


class TestEvidenceOwnerColumn:
    def test_list_includes_owner_display_name(self, auth_client, db):
        client, seeded, _ = auth_client
        s = _mk_system(db, seeded["org"].id)
        db.add(EvidenceArtifact(organization_id=seeded["org"].id, system_id=s.id,
                                filename="scan.pdf", owner_id=seeded["admin"].id))
        db.add(EvidenceArtifact(organization_id=seeded["org"].id, system_id=s.id,
                                filename="policy.docx"))
        db.commit()

        rows = client.get("/api/evidence").json()
        by_file = {r["filename"]: r for r in rows}
        assert by_file["scan.pdf"]["owner_id"] == seeded["admin"].id
        assert by_file["scan.pdf"]["owner_name"] == "Test Admin"
        assert by_file["policy.docx"]["owner_name"] is None

    def test_owner_name_falls_back_to_username(self, auth_client, db):
        client, seeded, _ = auth_client
        s = _mk_system(db, seeded["org"].id)
        nameless = User(organization_id=seeded["org"].id, username="nodisplay",
                        password_hash=hash_password("x" * 12), role="assessor")
        db.add(nameless)
        db.flush()
        db.add(EvidenceArtifact(organization_id=seeded["org"].id, system_id=s.id,
                                filename="log.txt", owner_id=nameless.id))
        db.commit()

        rows = client.get("/api/evidence").json()
        assert rows[0]["owner_name"] == "nodisplay"

    def test_owner_id_filter_returns_only_theirs(self, auth_client, db):
        client, seeded, _ = auth_client
        s = _mk_system(db, seeded["org"].id)
        other = User(organization_id=seeded["org"].id, username="teammate",
                     password_hash=hash_password("x" * 12), role="assessor",
                     display_name="Teammate")
        db.add(other)
        db.flush()
        db.add(EvidenceArtifact(organization_id=seeded["org"].id, system_id=s.id,
                                filename="mine.pdf", owner_id=seeded["admin"].id))
        db.add(EvidenceArtifact(organization_id=seeded["org"].id, system_id=s.id,
                                filename="theirs.pdf", owner_id=other.id))
        db.add(EvidenceArtifact(organization_id=seeded["org"].id, system_id=s.id,
                                filename="unowned.pdf"))
        db.commit()

        rows = client.get(f"/api/evidence?owner_id={seeded['admin'].id}").json()
        assert [r["filename"] for r in rows] == ["mine.pdf"]

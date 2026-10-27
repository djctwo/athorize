"""The demo seed is a backend module (services.demo_seed), so every
distribution can load it — including the in-app "Explore with demo data"
choice on the Setup screen. It seeds inside the CALLER's transaction: nothing
is committed by the seed itself, so a failure can be rolled back to an empty
instance."""
import pytest

from config import settings
from models import EvidenceArtifact, Organization, User
from services.demo_marker import DEMO_KEY


@pytest.fixture(autouse=True)
def _no_demo_files_left_behind():
    """The suite shares one data dir: start and end without demo files."""
    from services import demo_seed
    demo_seed.discard_demo_files()
    yield
    demo_seed.discard_demo_files()


def test_seed_loads_every_demo_company_and_marks_them_demo(db):
    from services import demo_seed
    demo_seed.seed_demo(db)
    db.commit()
    orgs = db.query(Organization).order_by(Organization.id).all()
    assert [o.slug for o in orgs] == ["acme-industrial-corp", "northwind-health", "contoso-energy"]
    assert all((o.settings or {}).get(DEMO_KEY) for o in orgs)
    admin = db.query(User).filter_by(username="admin").one()
    assert admin.role == "admin" and admin.is_operator
    assert {u.username for u in db.query(User)} >= {
        "admin", "operator", "analyst", "manager", "owner", "contributor", "auditor", "northwind", "contoso"}
    assert db.query(EvidenceArtifact).count() >= 5


def test_seed_never_commits_on_its_own(db):
    from services import demo_seed
    demo_seed.seed_demo(db)
    db.rollback()
    assert db.query(Organization).count() == 0
    assert db.query(User).count() == 0
    demo_seed.discard_demo_files()
    assert not (settings.evidence_dir / "demo").exists()
    assert not (settings.custom_frameworks_dir / demo_seed.CUSTOM_FW_ID).exists()


@pytest.mark.parametrize("what", ["org", "user"])
def test_seed_refuses_a_database_that_is_not_empty(db, what):
    from services import demo_seed
    org = Organization(name="Real Co", slug="real-co")
    db.add(org)
    db.flush()
    if what == "user":
        db.add(User(organization_id=org.id, username="realadmin", password_hash="x", role="admin"))
    db.commit()
    with pytest.raises(demo_seed.DemoSeedRefused):
        demo_seed.seed_demo(db)
    assert db.query(Organization).filter_by(slug="acme-industrial-corp").count() == 0

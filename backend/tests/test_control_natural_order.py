"""E2E-25: controls are listed in natural order (AC-2 before AC-10)."""
import io
import zipfile

from models import Control, FrameworkActivation, System
from services.natural_sort import control_sort_key

IDS = ["AC-10", "AC-2(1)", "AC-1", "AC-2", "AC-11", "1.10", "1.2", "AU-3"]
NATURAL = ["1.2", "1.10", "AC-1", "AC-2", "AC-2(1)", "AC-10", "AC-11", "AU-3"]


def test_sort_key():
    assert sorted(IDS, key=control_sort_key) == NATURAL


def test_unicode_digits_never_raise_and_order_is_stable():
    ids = ["AC-²", "AC-١٢", "AC-10", "AC-2", "1²2", "AC-³1", "AC-٣"]
    first = sorted(ids, key=control_sort_key)
    assert sorted(reversed(ids), key=control_sort_key) == first
    # ASCII numbers still order naturally among them
    assert first.index("AC-2") < first.index("AC-10")


def test_catalog_with_unicode_digit_ids_is_not_a_500(auth_client, db):
    client, _seeded, _csrf = auth_client
    for cid in ["AC-²", "1²2", "AC-١٢", "AC-10", "AC-2"]:
        db.add(Control(framework_id="uni-fw", control_id=cid, family="AC", title=cid))
    db.commit()
    r = client.get("/api/controls?framework_id=uni-fw")
    assert r.status_code == 200
    got = [c["control_id"] for c in r.json()]
    assert got.index("AC-2") < got.index("AC-10")


def test_catalog_endpoint_is_naturally_ordered(auth_client, db):
    client, _seeded, _csrf = auth_client
    for cid in IDS:
        db.add(Control(framework_id="nat-fw", control_id=cid, family=cid.split("-")[0], title=cid))
    db.commit()
    got = [c["control_id"] for c in client.get("/api/controls?framework_id=nat-fw").json()]
    assert got == NATURAL


def test_binder_lists_controls_naturally(auth_client, db):
    client, seeded, _csrf = auth_client
    org = seeded["org"]
    s = System(organization_id=org.id, name="Nat", acronym="NAT")
    db.add(s)
    db.add(FrameworkActivation(organization_id=org.id, framework_id="nat-fw", is_active=True))
    for cid in ["AC-10", "AC-2", "AC-1"]:
        db.add(Control(framework_id="nat-fw", control_id=cid, family="AC", title=f"title {cid}"))
    db.commit()
    r = client.get(f"/api/reports/audit-binder?system_id={s.id}&framework_id=nat-fw")
    html = zipfile.ZipFile(io.BytesIO(r.content)).read("binder.html").decode()
    assert html.index("title AC-1") < html.index("title AC-2") < html.index("title AC-10")

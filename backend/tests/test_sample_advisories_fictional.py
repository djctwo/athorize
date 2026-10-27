"""Bundled sample advisories must be fictional.

Athorize ships offline/demo threat advisories (the offline ICS feed, the KEV /
NVD / AA / PSIRT fixtures and the demo seed). Publishing invented
vulnerabilities about real vendors' products — or invented IDs in the real
CVE / CISA namespaces, which can collide with genuine records — is not
acceptable. Every bundled advisory must name only fictional vendors/products,
use the reserved DEMO- id namespace, carry no link to a real advisory site,
and be flagged as sample data by the API.
"""
import re

import pytest

# Real vendors / products / agencies the bundled samples used to name.
# Case-insensitive, whole-word.
REAL_NAMES_CI = [
    r"siemens", r"simatic", r"s7-?\d{3,4}", r"s7comm", r"carrier", r"tridium", r"niagara",
    r"ifix", r"proficy", r"osisoft", r"aveva", r"pi (?:system|server|data archive|network manager)",
    r"honeywell", r"cisco", r"ios-?xe", r"palo alto", r"pan-?os", r"globalprotect",
    r"vertx", r"milestone", r"xprotect", r"microsoft", r"windows", r"smartscreen",
    r"sql server", r"red ?hat", r"rhel", r"canonical", r"ubuntu", r"needrestart", r"linux",
    r"rockwell", r"schneider", r"emerson", r"yokogawa", r"fortinet", r"juniper", r"vmware",
    r"lockbit", r"alphv", r"akira",
]
# Short acronyms that are also ordinary letter pairs — match case-sensitively.
REAL_NAMES_CS = [r"GE", r"HID", r"ABB", r"CISA", r"FBI", r"NSA", r"PRC", r"PAN-SA", r"SSA"]
_DENY_CI = re.compile(r"\b(?:" + "|".join(REAL_NAMES_CI) + r")\b", re.IGNORECASE)
_DENY_CS = re.compile(r"\b(?:" + "|".join(REAL_NAMES_CS) + r")\b")

TEXT_FIELDS = ("title", "summary", "affected_vendor", "affected_product",
               "affected_firmware_range", "recommended_mitigations")
REAL_ID = re.compile(r"^(?:CVE-|ICSA-|KEV-CVE-|NVD-CVE-|AA\d{2}-|SSA-|PAN-SA-)")


def _real_names(text: str) -> list[str]:
    return [m.group(0) for m in _DENY_CI.finditer(text or "")] + \
           [m.group(0) for m in _DENY_CS.finditer(text or "")]


def _offline_items() -> list[tuple[str, dict]]:
    from services.feeds_aa import fetch_aa
    from services.feeds_kev import fetch_kev
    from services.feeds_nvd import fetch_nvd
    from services.feeds_psirt import fetch_psirt
    from services.ics_advisory_mock import mock_advisories
    items = [("ICS mock", a) for a in mock_advisories()]
    for name, fetch in (("KEV", fetch_kev), ("NVD", fetch_nvd), ("AA", fetch_aa), ("PSIRT", fetch_psirt)):
        items += [(name, a) for a in fetch(live=False)]
    return items


def _problems(label: str, adv: dict) -> list[str]:
    out = []
    aid = adv.get("advisory_id") or ""
    for field in TEXT_FIELDS:
        hits = _real_names(str(adv.get(field) or ""))
        if hits:
            out.append(f"{label} {aid}: {field} names real {hits}")
    if REAL_ID.match(aid) or "DEMO-" not in aid:
        out.append(f"{label} {aid}: advisory id is not in the DEMO- namespace")
    for cve in adv.get("cve_ids") or []:
        if not re.match(r"^DEMO-\d{4}-\d{4,}$", cve):
            out.append(f"{label} {aid}: vulnerability id {cve!r} is not a DEMO- id")
    if adv.get("source_url"):
        out.append(f"{label} {aid}: links to {adv['source_url']!r}")
    return out


def test_offline_feed_items_are_fictional():
    items = _offline_items()
    assert len(items) >= 20
    problems = [p for label, adv in items for p in _problems(label, adv)]
    assert problems == [], "\n".join(problems)


@pytest.fixture
def _clean_demo_files():
    from services import demo_seed
    demo_seed.discard_demo_files()
    yield
    demo_seed.discard_demo_files()


def test_demo_seed_advisories_and_matched_assets_are_fictional(db, _clean_demo_files):
    from models import IcsAdvisory, IcsAdvisoryMatch
    from services import demo_seed
    demo_seed.seed_demo(db)
    db.flush()

    rows = db.query(IcsAdvisory).all()
    assert len(rows) >= 10
    problems = [p for r in rows for p in _problems(f"seed[{r.source}]",
                                                   {c.name: getattr(r, c.name) for c in r.__table__.columns})]

    # The demo story still works: advisories land on (fictional) inventory.
    matches = db.query(IcsAdvisoryMatch).all()
    assert len(matches) >= 10
    for m in matches:
        asset = m.ot_asset or m.it_asset
        hits = _real_names(f"{asset.vendor} {asset.model}")
        if hits:
            problems.append(f"matched asset {asset.asset_name} names real {hits}")
    assert problems == [], "\n".join(problems)

    # Every seeded advisory is flagged as sample data in the API payload.
    from routers.ics_advisories import _serialize_advisory
    assert all(_serialize_advisory(r)["is_sample"] for r in rows)
    db.rollback()


def test_live_normalizers_keep_real_links_but_never_link_demo_ids():
    from services.feeds_kev import normalize_kev
    from services.feeds_nvd import normalize_nvd
    real = normalize_kev([{"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2"}])[0]
    assert real["source_url"].startswith("https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
    assert real["advisory_id"] == "KEV-CVE-2021-44228"
    demo = normalize_kev([{"cveID": "DEMO-2026-0101"}])[0]
    assert demo["source_url"] == ""

    real_nvd = normalize_nvd([{"cve": {"id": "CVE-2021-44228"}}])[0]
    assert real_nvd["source_url"] == "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    assert normalize_nvd([{"cve": {"id": "DEMO-2026-0201"}}])[0]["source_url"] == ""


def test_live_aa_parsing_ignores_demo_ids():
    """The DEMO- namespace is recognized only for the bundled fixture."""
    from services.feeds_aa import _parse_rss
    rss = ("<rss><channel><item><title>DEMO-AA26-901A: x</title><description>DEMO-2026-0102</description>"
           "</item><item><title>AA24-131A: real</title><description>CVE-2021-44228</description></item>"
           "</channel></rss>")
    live = {i["advisory_id"]: i for i in _parse_rss(rss)}
    assert "DEMO-AA26-901A" not in live
    assert live["AA24-131A"]["cve_ids"] == ["CVE-2021-44228"]
    sample = {i["advisory_id"]: i for i in _parse_rss(rss, sample=True)}
    assert sample["DEMO-AA26-901A"]["cve_ids"] == ["DEMO-2026-0102"]


def test_spawned_finding_never_presents_demo_ids_as_cves(auth_client, db):
    from models import Finding, IcsAdvisory
    from tests.conftest import activate_framework
    client, seeded, csrf = auth_client
    activate_framework(db, seeded["org"], "nist-800-82-r3")
    adv = IcsAdvisory(organization_id=seeded["org"].id, advisory_id="DEMO-ICSA-2026-001",
                      title="VanArsdel Controls VC-1500 Firmware Vulnerability", summary="Sample.",
                      severity="CRITICAL", cve_ids=["DEMO-2026-0001", "CVE-2021-44228"], source="MOCK")
    db.add(adv)
    db.commit()
    h = {"X-CSRF-Token": csrf} if csrf else {}
    sid = client.post("/api/systems", json={"name": "Plant"}, headers=h).json()["id"]
    listed = client.get("/api/advisories").json()
    assert [a["is_sample"] for a in listed] == [True]
    r = client.post(f"/api/advisories/{adv.id}/spawn-finding", json={"system_id": sid}, headers=h)
    assert r.status_code == 200, r.text
    weakness = db.get(Finding, r.json()["finding_id"]).weakness_description
    assert "CVE(s): CVE-2021-44228" in weakness
    assert "Reference ID(s): DEMO-2026-0001" in weakness
    assert "CVE(s): DEMO" not in weakness and "DEMO-2026-0001, CVE" not in weakness

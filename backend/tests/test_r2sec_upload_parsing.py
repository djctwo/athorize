"""R2SEC-4: a malformed Snort line must parse in linear time, and upload
parsing must not run on the event loop (one upload froze every request)."""
import asyncio
import io
import time

import pytest

from services.siem_import import parse_snort_fast


@pytest.mark.parametrize("line", [
    "01/01-00:00:00.0 [**] [1:1:1] " + "a [**] [Classification: x" * 4000,   # ~100 KB, many [**]
    "01/01-00:00:00.0 [**] [1:1:1] x" + " " * 50000 + "y",                 # long whitespace run
    "01/01-00:00:00.0 [**] [1:1:1] " + "a [**] [Classification: x" * 300,  # < 8 KB, still pathological
], ids=["many-separators", "whitespace-run", "under-line-cap"])
def test_malformed_snort_line_is_linear(line):
    t = time.perf_counter()
    for _ in range(20):
        parse_snort_fast(line)
    assert time.perf_counter() - t < 1.0


def test_valid_snort_alerts_still_parse():
    rows = parse_snort_fast(
        "10/22-01:02:03.456 [**] [1:2003:8] ET SCAN [x] probe [**] [Classification: Attempted Recon] "
        "[Priority: 2] {TCP} 10.0.0.1:1234 -> 10.0.0.2:80\n"
        "10/22-01:02:04.000 [**] [1:9:1] No class [**] [Priority: 1] {UDP} [fe80::1]:53 -> [fe80::2]:5353\n")
    assert [r["title"] for r in rows] == ["ET SCAN [x] probe", "No class"]
    assert rows[0]["extra_data"]["classification"] == "Attempted Recon"
    assert rows[1]["severity"] == "CRITICAL" and rows[1]["extra_data"]["dst_port"] == 5353


def _off_loop(fn, seen):
    def wrapper(*a, **kw):
        try:
            asyncio.get_running_loop()
            seen.append("event-loop")
        except RuntimeError:
            seen.append("worker")
        return fn(*a, **kw)
    return wrapper


def test_upload_parsers_run_off_the_event_loop(auth_client, db, monkeypatch):
    from models import System
    client, seeded, csrf = auth_client
    from models import FrameworkActivation
    from routers.frameworks import loader
    system = System(organization_id=seeded["org"].id, name="ERP", acronym="ERP")
    db.add(system)
    # imports need an active framework (R2DATA-6)
    db.add(FrameworkActivation(organization_id=seeded["org"].id, framework_id="sox", is_active=True))
    loader.load_catalog("sox", db)
    db.commit()
    from routers import asset_import, migration, siem_import
    seen: list[str] = []
    monkeypatch.setattr(siem_import, "parse_file_report", _off_loop(siem_import.parse_file_report, seen))
    monkeypatch.setattr(asset_import, "parse_assets_report", _off_loop(asset_import.parse_assets_report, seen))
    monkeypatch.setattr(migration, "parse_poam", _off_loop(migration.parse_poam, seen))
    h = {"X-CSRF-Token": csrf}
    form = {"system_id": str(system.id), "framework_id": "sox"}
    client.post("/api/siem/import", headers=h, data={**form, "format_override": "splunk_csv"},
                files={"file": ("a.csv", io.BytesIO(b"alert_name,severity\nx,high\n"), "text/csv")})
    client.post("/api/asset-import/import", headers=h, data={**form, "source_override": "tanium_csv"},
                files={"file": ("a.csv", io.BytesIO(b"Computer Name,IP Address\nws1,10.0.0.1\n"), "text/csv")})
    client.post("/api/migration/poam", headers=h, data=form,
                files={"file": ("p.csv", io.BytesIO(b"Weakness Name,Severity\nx,High\n"), "text/csv")})
    assert seen == ["worker", "worker", "worker"], seen

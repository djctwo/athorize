"""Fix-wave regressions for the import paths (team E) that the H4 hunt suite
does not already pin: what every import response reports (imported / skipped
and why / merged / truncated), streaming size limits, encodings, format
auto-detection that must not misfire, and the evidence / feed edge cases."""
from __future__ import annotations

import asyncio
import io
import json

import pytest

from config import settings
from services import siem_import as S
from tests.hunts.test_import_hunt import FIX, FW, GOOD_SIEM, H, MALFORMED_CSAF, fixture_bytes  # noqa: F401


# ---------------------------------------------------------------------------
# SIEM response accounting


def test_siem_truncation_is_counted_in_preview_and_confirm(H):
    content = "alert_name,_time\n" + "".join(f"Alert {i},2026-10-20T09:00:{i % 60:02d}Z\n" for i in range(5003))
    pv = H.siem("big.csv", content).json()
    assert pv["total_parsed"] == S.MAX_ROWS
    assert pv["truncated"] is True and pv["truncated_count"] == 3 and pv["max_rows"] == S.MAX_ROWS
    assert any("row limit" in w for w in pv["warnings"])
    cf = H.siem("big.csv", content, confirm=True).json()
    assert cf["created"] == S.MAX_ROWS and cf["truncated_count"] == 3
    assert any("row limit" in w for w in cf["warnings"])
    hist = H.c.get("/api/siem/import/history").json()
    assert "3 not imported (row limit)" in hist[0]["summary"]


def test_siem_skipped_rows_report_reasons(H):
    lines = [
        '{"event_type":"flow","src_ip":"10.0.0.1"}',
        "this is not json",
        '[1, 2]',
        json.dumps({"timestamp": "2026-10-20T09:00:00Z", "event_type": "alert", "src_ip": "10.0.0.1",
                    "dest_ip": "10.0.0.2", "alert": {"signature": "ET TEST", "signature_id": 1, "severity": 1}}),
    ]
    body = H.siem("eve.json", "\n".join(lines) + "\n", confirm=True).json()
    assert body["created"] == 1
    assert body["skipped_rows"] == 3
    assert body["skip_reasons"] == {
        "not an alert event (flow, dns, http, stats, …)": 1,
        "line is not valid JSON": 1,
        "record is not a JSON object": 1,
    }
    assert any("3 row(s) skipped" in w for w in body["warnings"])


def test_siem_no_rows_error_explains_what_was_skipped(H):
    r = H.siem("eve.json", '{"event_type":"flow"}\n{"event_type":"dns"}\n', confirm=True)
    assert r.status_code == 422
    assert "2 row(s) skipped: not an alert event" in r.json()["detail"]


def test_siem_in_file_duplicates_merged_and_reported(H):
    hdr = '"Plugin ID","CVE","Risk","Host","Protocol","Port","Name"\n'
    rows = "".join(f'"97833","CVE-2017-014{i}","Critical","10.0.0.5","tcp","445","MS17-010"\n' for i in range(3, 6))
    pv = H.siem("scan.csv", hdr + rows).json()
    assert pv["new_count"] == 1 and pv["merged_duplicates"] == 2
    assert any("merged" in w for w in pv["warnings"])
    H.siem("scan.csv", hdr + rows, confirm=True)
    (f,) = H.findings()
    assert f["extra_data"]["cve"] == "CVE-2017-0143, CVE-2017-0144, CVE-2017-0145"


def test_siem_binary_upload_is_a_clear_422(H):
    r = H.siem("junk.csv", bytes(range(256)) * 8, confirm=True)
    assert r.status_code == 422 and "binary" in r.json()["detail"]


def test_siem_unparseable_json_says_why(H):
    r = H.siem("y.json", '[{"rule": "x"', fmt="yara_json", confirm=True)
    assert r.status_code == 422 and "not valid YARA JSON" in r.json()["detail"]


# ---------------------------------------------------------------------------
# Format detection — new rules must not misfire


def test_formats_declare_the_source_type_their_findings_carry():
    from services import import_common as ic
    for fname, fmt, _ in GOOD_SIEM:
        content = ic.decode_text(fixture_bytes("siem", fname))
        rows = S.parse_file(content, fmt)
        declared = next(f["source_type"] for f in S.SUPPORTED_FORMATS if f["key"] == fmt)
        assert rows and {r["extra_data"]["source_type"] for r in rows} == {declared}, fmt


@pytest.mark.parametrize("name,content,fmt", [
    # a QID/Title pair inside DATA rows must not turn a Splunk export into Qualys
    ("a.csv", "alert_name,severity,note\nx,high,QID\ny,low,Title\n", "splunk_csv"),
    ("a.csv", "alert_name,severity\nx,high\n", "splunk_csv"),
    # pretty-printed (multi-line) JSON is sniffed by its first record
    ("e.json", json.dumps([{"timestamp": "t", "alert": {"signature": "s"}}], indent=2), "suricata_eve"),
    ("w.json", json.dumps({"rule": {"level": 5, "description": "d"}, "agent": {"name": "a"}}, indent=2), "wazuh_json"),
    ("y.json", json.dumps([{"rule": "R", "strings": ["$a"]}], indent=2), "yara_json"),
    ("e.csv", "#TYPE System.Diagnostics.Eventing.Reader.EventLogRecord\nMessage,Id,ProviderName,LevelDisplayName\n", "winevent_csv"),
])
def test_detect_format_cases(name, content, fmt):
    assert S.detect_format(name, content) == fmt


def test_cef_fixture_and_text_severities():
    rows = S.parse_file("CEF:0|V|P|1|1|a|0|src=1.1.1.1\nCEF:0|V|P|1|2|b|Unknown|\n"
                        "CEF:0|V|P|1|3|c|High|\nCEF:0|V|P|1|4|d|10|\n", "generic_cef")
    assert [r["severity"] for r in rows] == ["LOW", "LOW", "HIGH", "CRITICAL"]


@pytest.mark.parametrize("line,src,sport,dst,dport", [
    ("{TCP} [2001:db8::10]:52000 -> [2001:db8::20]:22", "2001:db8::10", 52000, "2001:db8::20", 22),
    ("{ICMP} 2001:db8::10 -> 2001:db8::20", "2001:db8::10", None, "2001:db8::20", None),
    ("{TCP} 10.0.0.1:1234 -> 10.0.0.2:80", "10.0.0.1", 1234, "10.0.0.2", 80),
    ("{ICMP} 10.0.0.1 -> 10.0.0.2", "10.0.0.1", None, "10.0.0.2", None),
])
def test_snort_address_forms(line, src, sport, dst, dport):
    prefix = "10/20-09:15:02.123456  [**] [1:1:1] X [**] [Priority: 2] "
    (row,) = S.parse_file(prefix + line + "\n", "snort_fast")
    ed = row["extra_data"]
    assert (ed["src_ip"], ed["src_port"], ed["dst_ip"], ed["dst_port"]) == (src, sport, dst, dport)


# ---------------------------------------------------------------------------
# Decoding


@pytest.mark.parametrize("raw,text", [
    ("a,b\nü,1\n".encode("utf-16-le"), "a,b\nü,1\n"),                  # BOM-less UTF-16
    ("a,b\n“q”,1\n".encode("cp1252"), "a,b\n“q”,1\n"),                 # Windows-1252 smart quotes
    (b"\xef\xbb\xbfa,b\n", "a,b\n"),                                    # UTF-8 BOM
    ("a,b\n".encode("utf-32"), "a,b\n"),                                # UTF-32 with BOM
])
def test_decode_text(raw, text):
    from services import import_common as ic
    assert ic.decode_text(raw) == text


# ---------------------------------------------------------------------------
# Upload size: checked while streaming


class _ChunkedUpload:
    """UploadFile stand-in that yields an endless stream and records reads."""

    size = None

    def __init__(self):
        self.served = 0

    async def read(self, n: int = -1) -> bytes:
        assert n and n > 0, "upload read without a bound"
        self.served += n
        return b"x" * n


def test_read_upload_capped_stops_at_the_limit():
    from services import import_common as ic
    up = _ChunkedUpload()
    with pytest.raises(Exception) as exc:
        asyncio.run(ic.read_upload_capped(up, 3 * 1024 * 1024))
    assert getattr(exc.value, "status_code", None) == 413
    assert up.served <= 4 * 1024 * 1024


def test_save_upload_capped_leaves_nothing_on_overflow(tmp_path):
    from services import import_common as ic
    up = _ChunkedUpload()
    dest = tmp_path / "e.bin"
    with pytest.raises(Exception):
        asyncio.run(ic.save_upload_capped(up, dest, 2 * 1024 * 1024))
    assert list(tmp_path.iterdir()) == []


def _asgi_call(path: str, chunks: int, chunk_size: int = 1024 * 1024, content_length: int | None = None):
    from services import import_common as ic
    """Drive an ASGI app with a streamed body; returns (status, chunks consumed, app reached)."""
    consumed = 0
    sent: list[dict] = []
    reached = []

    async def receive():
        nonlocal consumed
        consumed += 1
        return {"type": "http.request", "body": b"x" * chunk_size, "more_body": consumed < chunks}

    async def send(msg):
        sent.append(msg)

    async def inner(scope, rcv, snd):
        reached.append(True)
        while (await rcv()).get("more_body"):
            pass
        await snd({"type": "http.response.start", "status": 200, "headers": []})
        await snd({"type": "http.response.body", "body": b"ok"})

    headers = [(b"content-length", str(content_length).encode())] if content_length is not None else []
    scope = {"type": "http", "path": path, "method": "POST", "headers": headers}
    asyncio.run(ic.UploadSizeLimitMiddleware(inner, lambda p: 4 * 1024 * 1024)(scope, receive, send))
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    return status, consumed, bool(reached)


def test_body_limit_middleware_cuts_off_a_streamed_body():
    status, consumed, _ = _asgi_call("/api/siem/import", chunks=10_000)
    assert status == 413
    assert consumed <= 7  # 4 MiB cap + 1 MiB slack, 1 MiB chunks — not the 10 GB the client wanted to send


def test_body_limit_middleware_refuses_declared_oversize_before_the_app_runs():
    status, consumed, reached = _asgi_call("/api/evidence/upload", chunks=1,
                                           content_length=50 * 1024 ** 3)
    assert status == 413 and consumed == 0 and not reached


def test_body_limit_middleware_passes_small_bodies():
    status, _, reached = _asgi_call("/api/siem/import", chunks=2)
    assert status == 200 and reached


def test_app_has_body_limits_for_every_upload_endpoint():
    from services import import_common as ic
    import main
    for path, mib in (("/api/siem/import/confirm", 16), ("/api/asset-import/import", 16),
                      ("/api/migration/poam", 16), ("/api/evidence/upload", 100)):
        assert main._request_body_limit(path) == mib * 1024 * 1024
    assert main._request_body_limit("/api/findings") == 32 * 1024 * 1024
    assert any(m.cls is ic.UploadSizeLimitMiddleware for m in main.app.user_middleware)


# ---------------------------------------------------------------------------
# Asset import accounting


def test_asset_import_reports_skips_and_tolerates_extra_cells(H):
    content = ("Computer Name,Operating System\n"
               "WS-1,Windows 11,extra-cell,another\n"   # more cells than headers
               ",Linux\n")                               # no name
    r = H.assets_import("inv.csv", content, source="tanium_csv", confirm=True)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["created"] == 1 and body["skipped_rows"] == 1
    assert body["skip_reasons"] == {"no computer name / hostname": 1}


# ---------------------------------------------------------------------------
# POA&M / SSP


def test_poam_template_title_rows_above_header(H):
    raw = ("FedRAMP POA&M Template,,,\nCSP: Acme Cloud,,,\n,,,\n"
           + fixture_bytes("migration", "poam_fedramp_template.csv").decode())
    assert H.migrate("poam", "fedramp.csv", raw, commit=True).json()["created"] == 3
    assert {f["control_id"] for f in H.findings()} == {"AC-2", "RA-5", "SC-8"}


def _poam_twice(H, raw: str) -> tuple[dict, dict, dict]:
    """preview, first commit, second commit (re-import of the identical file)."""
    pv = H.migrate("poam", "p.csv", raw, commit=False).json()
    first = H.migrate("poam", "p.csv", raw, commit=True).json()
    again = H.migrate("poam", "p.csv", raw, commit=True).json()
    return pv, first, again


def test_poam_same_title_distinct_poam_ids_stay_separate(H):
    # (a) FedRAMP/eMASS list one weakness per asset with its own POA&M ID.
    raw = ("POAM ID,Weakness Name,Asset Identifier,Original Risk Rating\n"
           "V-0001,Missing OS patches,web-01.example.com,High\n"
           "V-0002,Missing OS patches,web-02.example.com,High\n"
           "V-0003,Missing OS patches,db-01.example.com,Moderate\n")
    pv, first, again = _poam_twice(H, raw)
    assert pv["new"] == 3 and pv["merged_in_file"] == 0
    assert first["created"] == 3
    rows = H.findings()
    assert len(rows) == 3 and {r["title"] for r in rows} == {"Missing OS patches"}
    assert sorted(r["extra_data"]["poam_id"] for r in rows) == ["V-0001", "V-0002", "V-0003"]
    # (d) re-import is idempotent
    assert again["created"] == 0 and again["duplicates"] == 3
    assert len(H.findings()) == 3


def test_poam_repeated_poam_id_merges(H):
    # (b) the same item listed twice (ID normalised: case/whitespace) is one finding.
    raw = ("POA&M Item ID,Weakness,Severity\n"
           "V-0007,Stale admin accounts,High\n"
           " v-0007 ,Stale admin accounts (dup row),High\n"
           "V-0008,Weak TLS,Low\n")
    pv, first, again = _poam_twice(H, raw)
    assert pv["new"] == 2 and pv["merged_in_file"] == 1
    assert any("same POA&M ID as row 2" in i for i in pv["issues"])
    assert first["created"] == 2
    assert {r["title"] for r in H.findings()} == {"Stale admin accounts", "Weak TLS"}
    assert again["created"] == 0 and again["duplicates"] == 2
    assert len(H.findings()) == 2


def test_poam_without_id_column_merges_by_title(H):
    # (c) no POA&M ID column: title stays the identity, as before.
    raw = "Weakness,Severity\nSame title,High\nOther,Low\nsame TITLE,Low\n"
    pv, first, again = _poam_twice(H, raw)
    assert pv["new"] == 2 and pv["merged_in_file"] == 1
    assert any("same title as row 2" in i for i in pv["issues"])
    assert first["created"] == 2
    assert again["created"] == 0 and again["duplicates"] == 2
    assert len(H.findings()) == 2


def test_poam_blank_id_cells_fall_back_to_title(H):
    raw = ("POAM ID,Weakness,Severity\n"
           "V-1,Shared title,High\n"
           ",Untracked item,Low\n"
           ",untracked ITEM,Low\n")
    pv, first, again = _poam_twice(H, raw)
    assert pv["new"] == 2 and pv["merged_in_file"] == 1
    assert first["created"] == 2
    assert again["created"] == 0 and again["duplicates"] == 2


def test_poam_first_id_row_adopts_a_pre_id_finding_once(H):
    # A finding imported before POA&M IDs were stored (or entered by hand) has
    # no poam_id. On the first import after upgrade the FIRST ID-bearing row with
    # that title adopts it (gets the ID, no new row); further rows with other IDs
    # are distinct per-asset items and create their own findings.
    from models import Finding
    legacy = Finding(organization_id=H.org.id, system_id=H.system.id, framework_id=FW,
                     title="X", severity="HIGH", status="OPEN")
    H.db.add(legacy)
    H.db.commit()
    raw = "POAM ID,Weakness,Severity\n1,X,High\n2,X,High\n"
    pv = H.migrate("poam", "p.csv", raw, commit=False).json()
    assert pv["new"] == 1 and pv["adopted"] == 1 and pv["duplicates"] == 0
    first = H.migrate("poam", "p.csv", raw, commit=True).json()
    assert first["created"] == 1 and first["adopted"] == 1
    rows = H.findings()
    assert len(rows) == 2
    by_id = {r["extra_data"].get("poam_id"): r for r in rows}
    assert set(by_id) == {"1", "2"} and by_id["1"]["id"] == legacy.id
    # re-import is idempotent: the adopted finding now carries ID 1
    again = H.migrate("poam", "p.csv", raw, commit=True).json()
    assert again["created"] == 0 and again["adopted"] == 0 and again["duplicates"] == 2
    assert len(H.findings()) == 2


def test_poam_unrecognized_severity_and_missing_columns_are_reported(H):
    pv = H.migrate("poam", "p.csv", "Weakness,Severity\nA,Extreme\n", commit=False).json()
    assert any("unrecognized severity 'Extreme'" in i for i in pv["issues"])
    assert any("No control column" in i for i in pv["issues"])


def test_poam_severity_falls_back_to_original_rating_when_adjusted_blank(H):
    raw = "Weakness Name,Controls,Original Risk Rating,Adjusted Risk Rating\nA,AC-2,High,\nB,AC-3,High,Low\n"
    H.migrate("poam", "p.csv", raw, commit=True)
    assert {f["title"]: f["severity"] for f in H.findings()} == {"A": "HIGH", "B": "LOW"}


# ---------------------------------------------------------------------------
# API bulk import


def test_bulk_import_counts_every_error_and_flags_the_capped_list(H):
    bad = [{"title": f"bad {i}", "framework_id": FW, "severity": "SEVERE"} for i in range(600)]
    body = H.c.post(f"/api/findings/bulk-import/{H.system.id}", json={"rows": bad, "commit": False}).json()
    assert body["error_count"] == 600 and body["invalid_rows"] == 600
    assert len(body["errors"]) == 500 and body["errors_truncated"] is True


# ---------------------------------------------------------------------------
# Evidence upload


def _evidence_files() -> list:
    return sorted(p for p in settings.evidence_dir.rglob("*") if p.is_file())


@pytest.mark.parametrize("form", [
    {"control_ids": "not json"},
    {"control_ids": '{"a": 1}'},
    {"framework_ids": "[1]"},
    {"expiration_days": 0},
    {"expiration_days": -5},
])
def test_evidence_rejected_upload_leaves_no_orphan_file(H, form):
    before = _evidence_files()
    r = H.upload_evidence("log.txt", b"hello", **form)
    assert r.status_code == 422, r.text
    assert _evidence_files() == before


def test_evidence_upload_streams_hash_and_ids(H):
    import hashlib
    payload = b"%PDF-1.4 " + b"z" * (3 * 1024 * 1024)
    r = H.upload_evidence("big.pdf", payload, control_ids='[" HUNT-1 ", "HUNT-1", ""]')
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["file_hash"] == hashlib.sha256(payload).hexdigest()
    assert body["control_ids"] == ["HUNT-1"]
    assert (settings.evidence_dir / body["file_path"]).read_bytes() == payload
    assert not list(settings.evidence_dir.rglob("*.part"))


def test_evidence_patch_expiration_days_bounded(H):
    eid = H.upload_evidence("log.txt", b"hello").json()["id"]
    assert H.c.patch(f"/api/evidence/{eid}", json={"expiration_days": 10 ** 9}).status_code == 422
    assert H.c.patch(f"/api/evidence/{eid}", json={"expiration_days": 30}).status_code == 200


# ---------------------------------------------------------------------------
# CSAF (CISA path shares parse_csaf_document)


@pytest.mark.parametrize("doc", MALFORMED_CSAF + [None, "s", {"document": {"title": 5, "tracking": {"id": "X"}}}])
def test_parse_csaf_document_never_raises(doc):
    from services.ics_advisory_cisa import parse_csaf_document
    assert parse_csaf_document(doc) is None or isinstance(parse_csaf_document(doc), dict)


def test_custom_feed_with_malformed_rolie_feed_is_isolated(monkeypatch):
    from services import feeds_custom as fc
    provider = {"distributions": [{"rolie": {"feeds": [{"tlp_label": "WHITE", "url": "https://csaf.example.com/feed.json"}]}}]}

    def fake_fetch(client, url, host):
        return provider if url.endswith("provider-metadata.json") else {"feed": {"entry": ["x", 1, None]}}

    monkeypatch.setattr(fc, "_fetch_locked_json", fake_fetch)
    monkeypatch.setattr(fc, "assert_public_host", lambda host: None)
    results, errors = fc.fetch_custom_feeds([
        {"name": "Acme PSIRT", "format": "csaf", "url": "https://csaf.example.com/.well-known/csaf/provider-metadata.json"},
    ])
    assert results == [] and errors == []

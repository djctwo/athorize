"""A changed or unrecognised scanner/SIEM export layout must end in a clear
error — never a silent partial import (rows with the host, severity or source
quietly lost) and never a guess at a different tool's format.

The error names the missing field and lists the file's column NAMES, so the
user can report the new layout; it never echoes a data row.
All data is synthetic (Acme / RFC 5737 addresses)."""
from __future__ import annotations

import random
import string

import pytest

from services import siem_import as S
from services.import_common import ImportFileError
from tests.hunts.test_import_hunt import H  # noqa: F401 — logged-in API harness fixture


# --- changed layouts of a recognised format --------------------------------

CHANGED = [
    # (format, header, data row, missing field named in the error)
    ("nessus_csv", "Plugin ID,CVE,Risk,Hostname,Port,Name", "10001,CVE-2024-0001,High,192.0.2.10,443,Acme TLS", "host"),
    ("nessus_csv", "Plugin ID,CVE,Risk Level,Host,Port,Name", "10001,,High,192.0.2.10,443,Acme TLS", "risk"),
    ("tenable_csv", "Plugin ID,Plugin Name,Sev,IP Address,Port", "1,Acme TLS,4,192.0.2.11,443", "severity"),
    ("tenable_csv", "Plugin ID,Plugin Name,Severity,Target,Port", "1,Acme TLS,4,192.0.2.11,443", "host"),
    ("qualys_csv", "QID,Title,Sev,IP", "38170,Acme cert,4,192.0.2.12", "severity"),
    ("qualys_csv", "QID,Title,Severity,Address", "38170,Acme cert,4,192.0.2.12", "IP"),
    ("sentinel_csv", "TimeGenerated [UTC],AlertName,Level", "2026-01-01T00:00:00Z,Acme alert,High", "severity"),
    ("crowdstrike_csv", "DetectId,DetectName,Criticality,ComputerName", "ldt:1,Acme detect,High,ACME-WS1", "severity"),
    ("splunk_csv", "_time,title,urgency", "2026-01-01,Acme notable,high", "alert name"),
    ("winevent_csv", "TimeCreated,Level,Message", "2026-01-01,Error,Acme service stopped", "event id or provider"),
]


@pytest.mark.parametrize("fmt,header,row,field", CHANGED, ids=[f"{c[0]}-{c[3]}" for c in CHANGED])
def test_changed_layout_is_a_clear_error_naming_the_missing_column(fmt, header, row, field):
    with pytest.raises(ImportFileError) as exc:
        S.parse_file_report(f"{header}\n{row}\n", fmt)
    msg = str(exc.value)
    assert f"no {field} column" in msg
    assert "Nothing was imported" in msg
    for col in header.split(","):
        assert f'"{col.strip()}"' in msg or f'"{col.split(" [")[0]}"' in msg
    # never a data value
    for value in row.split(","):
        if value and value not in header:
            assert value not in msg


@pytest.mark.parametrize("fmt,header", [
    ("nessus_csv", "Plugin ID,CVE,Risk,Host,Port,Name"),
    ("tenable_csv", "Plugin ID,Plugin Name,Severity,IP Address,Port"),
    ("qualys_csv", "IP,DNS,QID,Title,Severity"),
    ("sentinel_csv", "TimeGenerated [UTC],AlertName,AlertSeverity"),
    ("crowdstrike_csv", "DetectId,DetectName,SeverityName,ComputerName"),
    ("splunk_csv", "_time,alert_name,severity"),
    ("winevent_csv", "TimeCreated,Id,LevelDisplayName,ProviderName,Message"),
])
def test_current_layouts_still_pass_the_check(fmt, header):
    S.check_csv_layout(f"{header}\n", fmt)  # no exception


def test_qualys_metadata_rows_above_header_are_skipped_by_the_check():
    content = '"Scan Results","Acme"\n"Generated","2026-01-01"\n\nIP,DNS,QID,Title,Severity\n192.0.2.1,a,1,T,4\n'
    assert len(S.parse_file_report(content, "qualys_csv").rows) == 1


def test_type_line_is_skipped_by_the_check():
    content = "#TYPE System.Diagnostics.Eventing.Reader.EventLogRecord\nId,ProviderName,Message\n7036,SCM,ok\n"
    assert len(S.parse_file_report(content, "winevent_csv").rows) == 1


# --- unrecognised CSV is not guessed as Splunk -------------------------------

@pytest.mark.parametrize("header", [
    "Name,Severity,Hostname,PluginID",        # scanner export with a renamed key column
    "Asset,QID Number,Vuln Title,Level",       # Qualys-like, Title renamed
    "Name,CVSS v3 Score,Target",               # scanner columns, no full signature
    "foo,bar,baz",                             # nothing recognisable
])
def test_unrecognised_csv_is_not_detected_as_splunk(header):
    assert S.detect_format("export.csv", f"{header}\nx,y,z,w\n") is None


def test_splunk_csv_still_detected():
    assert S.detect_format("notables.csv", "_time,search_name,urgency\n1,x,high\n") == "splunk_csv"
    assert S.detect_format("generic.csv", "name,severity,src_ip\nx,high,192.0.2.1\n") == "splunk_csv"


# --- the column list is safe ---------------------------------------------------

def test_describe_columns_caps_and_strips():
    header = ["  ok  ", "bad\x00\x1b[31mname\x7f", "x" * 500] + [f"c{i}" for i in range(100)]
    out = S.describe_columns(header)
    assert '"ok"' in out
    assert "\x00" not in out and "\x1b" not in out and "\x7f" not in out
    assert '"' + "x" * 64 + '"' in out and "x" * 65 not in out
    assert "(+73 more)" in out


@pytest.mark.parametrize("seed", range(25))
def test_error_never_contains_data_values(seed):
    rnd = random.Random(seed)
    def tok(n=12):
        return "".join(rnd.choice(string.ascii_letters + string.digits) for _ in range(n))
    header = ["Plugin ID", "Risk", "Name", "Target"]  # Host renamed → layout error
    rows = [[tok() for _ in header] for _ in range(rnd.randint(1, 20))]
    content = ",".join(header) + "\n" + "\n".join(",".join(r) for r in rows) + "\n"
    with pytest.raises(ImportFileError) as exc:
        S.parse_file_report(content, "nessus_csv")
    msg = str(exc.value)
    for r in rows:
        for value in r:
            assert value not in msg


# --- end to end: nothing is imported, the user sees why -----------------------

def test_api_changed_layout_imports_nothing(H):  # noqa: F811
    csv = "Plugin ID,CVE,Risk,Hostname,Port,Name\n10001,CVE-2024-0001,High,192.0.2.10,443,Acme TLS\n"
    for confirm in (False, True):
        r = H.siem("scan.csv", csv, fmt="nessus_csv", confirm=confirm)
        assert r.status_code == 422, r.text
        assert "no host column" in r.json()["detail"]
    assert H.findings() == []


def test_api_unrecognised_csv_lists_columns_not_data(H):  # noqa: F811
    csv = "Name,Severity,Hostname,PluginID\nAcme TLS,High,192.0.2.10,10001\n"
    r = H.siem("scan.csv", csv, confirm=True)
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    assert "Could not detect the file format" in detail
    assert '"Hostname"' in detail and "192.0.2.10" not in detail and "Acme TLS" not in detail
    assert H.findings() == []

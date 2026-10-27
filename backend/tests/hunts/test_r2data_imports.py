"""Round-2 data-path hunt (team r2data): imports. Each test is a minimal
reproduction of one defect; they FAIL on main @ 32fe7d0."""
from __future__ import annotations

import io

import pytest

from services.import_common import decode_text
from services.migration_import import parse_poam
from tests.hunts.test_import_hunt import FW, H  # noqa: F401


# R2DATA-1 -------------------------------------------------------------------
# eMASS POA&M "Status" values Not Applicable / Archived (and common free-text
# variants) are imported as OPEN with no issue line -> inflated open/overdue.
@pytest.mark.parametrize("status", ["Not Applicable", "Archived", "Completed - Pending Verification",
                                    "Closed - Verified", "Cancelled"])
def test_poam_unrecognized_status_is_not_silently_open(status):
    raw = f"POA&M Item ID,Control Vulnerability Description,Status,Raw Severity Value\n1,A,{status},II\n".encode()
    out = parse_poam(raw)
    (row,) = out["rows"]
    assert row["status"] != "OPEN" or any("status" in i.lower() for i in out["issues"]), (
        f"'{status}' imported as OPEN with no issue reported")


# R2DATA-2 -------------------------------------------------------------------
# FedRAMP POA&M: Adjusted Risk Rating "N/A" (no adjustment) wins over the
# Original Risk Rating, so a High/Critical item is imported as Medium.
def test_poam_adjusted_rating_na_falls_back_to_original():
    raw = b"POAM ID,Weakness Name,Original Risk Rating,Adjusted Risk Rating\nV-1,A,High,N/A\nV-2,B,Critical,n/a\n"
    out = parse_poam(raw)
    assert {r["title"]: r["severity"] for r in out["rows"]} == {"A": "HIGH", "B": "CRITICAL"}


# R2DATA-3 -------------------------------------------------------------------
# One stray Windows-1252 byte in an otherwise UTF-8 export makes decode_text
# re-read the WHOLE file as cp1252: every non-ASCII character is silently
# mojibake'd (and re-importing the cleaned file creates duplicates, because
# titles feed the dedup hash for title-keyed formats).
def test_one_bad_byte_does_not_mojibake_the_whole_file():
    raw = "alert_name,_time\nMüller café alert,2026-10-01\n".encode("utf-8") + b"Stray \x96 dash,2026-10-02\n"
    text = decode_text(raw)
    assert "Müller café" in text


def test_utf8_bom_file_with_bad_byte_is_not_silently_replaced():
    raw = b"\xef\xbb\xbf" + "alert_name\nMüller\n".encode() + b"caf\xe9\n"
    text = decode_text(raw)
    assert "�" not in text  # silently replaced today


def test_mixed_encoding_is_reported_to_the_user(H):  # noqa: F811
    raw = "alert_name,_time\nMüller café alert,2026-10-01\n".encode("utf-8") + b"Stray \x96 dash,2026-10-02\n"
    r = H.siem("mixed.csv", raw, fmt="splunk_csv")
    assert r.status_code == 200, r.text
    assert any("Windows-1252" in w and "line 3" in w for w in r.json()["warnings"]), r.json()["warnings"]
    assert "Müller café alert" in [p["title"] for p in r.json()["preview"]]
    p = H.migrate("poam", "p.csv", "Weakness,Status\nMüller,Open\n".encode() + b"caf\xe9,Open\n", commit=False)
    assert any("Windows-1252" in i for i in p.json()["issues"]), p.json()["issues"]


# R2DATA-11 ------------------------------------------------------------------
# POA&M import creates findings directly in terminal statuses without the
# rules every other path enforces: RISK_ACCEPTED needs risk_rationale, CLOSED
# needs actual_completion (PATCH -> 422; bulk -> auto-fill/skip), and neither
# checks approve:finding_close. Imported rows carry none of it.
def test_poam_import_terminal_statuses_follow_the_finding_rules(H):  # noqa: F811
    raw = "POAM ID,Weakness,Status\nP-1,Accepted thing,Risk Accepted\nP-2,Closed thing,Completed\n"
    assert H.migrate("poam", "p.csv", raw, commit=True).status_code == 200
    by = {f["title"]: f for f in H.findings()}
    ra, cl = by["Accepted thing"], by["Closed thing"]
    assert ra["status"] != "RISK_ACCEPTED" or ra.get("risk_rationale"), "RISK_ACCEPTED without risk_rationale"
    assert cl["status"] != "CLOSED" or cl.get("actual_completion"), "CLOSED without actual_completion"


def test_poam_import_keeps_a_given_rationale_and_completion_date(H):  # noqa: F811
    raw = ("POAM ID,Weakness,Status,Risk Acceptance Rationale,Actual Completion Date\n"
           "P-1,Accepted thing,Risk Accepted,Compensating control CC-4,\nP-2,Closed thing,Closed,,2026-03-01\n")
    assert H.migrate("poam", "p.csv", raw, commit=True).status_code == 200
    by = {f["title"]: f for f in H.findings()}
    assert (by["Accepted thing"]["status"], by["Accepted thing"]["risk_rationale"]) == (
        "RISK_ACCEPTED", "Compensating control CC-4")
    assert (by["Closed thing"]["status"], by["Closed thing"]["actual_completion"]) == ("CLOSED", "2026-03-01")


def test_poam_import_of_terminal_items_needs_close_approval(H, monkeypatch):  # noqa: F811
    from routers import migration as mig
    real = mig.can
    monkeypatch.setattr(mig, "can", lambda role, action: action != "approve:finding_close" and real(role, action))
    raw = "POAM ID,Weakness,Status\nP-1,Open thing,Open\nP-2,Closed thing,Completed\n"
    r = H.migrate("poam", "p.csv", raw, commit=True)
    assert r.status_code == 403 and "approve:finding_close" in r.text, r.text
    assert H.findings() == []
    assert H.migrate("poam", "p.csv", "Weakness,Status\nOnly open,Open\n", commit=True).status_code == 200


# R2DATA-13 ------------------------------------------------------------------
# CEF header fields may contain an escaped pipe ("\|", CEF spec). _CEF_RE
# splits on every '|', so the Name is cut at the backslash and the rest of the
# name lands in the Severity field: a severity-10 event is imported as MEDIUM.
def test_cef_escaped_pipe_in_name_keeps_severity():
    from services import siem_import as S
    (row,) = S.parse_generic_cef(
        r"CEF:0|Acme|IDS|1.0|100|Exploit attempt \| CVE-2021-44228|10|src=10.0.0.1 dst=10.0.0.2")
    assert row["severity"] == "CRITICAL", row["severity"]
    assert row["title"] == "Exploit attempt | CVE-2021-44228", row["title"]


# R2DATA-14 ------------------------------------------------------------------
# Asset dedup keys each asset by ONE identity (MAC if present, else hostname).
# A host first imported from a Tanium export without a MAC column is keyed by
# hostname; the same host from Cisco ISE (always has a MAC) is keyed by MAC, so
# the second source creates a duplicate asset instead of recognising it.
def test_asset_seen_by_two_sources_is_not_duplicated(H):  # noqa: F811
    tanium = "Computer Name,IP Address,Operating System\nWS01,10.0.0.5,Windows 11 Enterprise\n"
    ise = "MACAddress,HostName,IPAddress,EndPointPolicy\nAA:BB:CC:00:11:22,WS01,10.0.0.5,Windows11-Workstation\n"
    assert H.assets_import("tanium.csv", tanium, confirm=True).status_code == 200
    r = H.assets_import("ise.csv", ise, confirm=True)
    assert r.status_code == 200, r.text
    assert len(H.assets()) == 1, [a["asset_name"] for a in H.assets()]


def test_second_source_fills_in_the_missing_mac_and_distinct_macs_stay_distinct(H):  # noqa: F811
    tanium = "Computer Name,IP Address,Operating System\nWS01,10.0.0.5,Windows 11 Enterprise\n"
    ise = ("MACAddress,HostName,IPAddress,EndPointPolicy\nAA:BB:CC:00:11:22,WS01,10.0.0.5,Windows11-Workstation\n"
           "AA:BB:CC:00:11:99,WS02,10.0.0.6,Windows11-Workstation\n")
    H.assets_import("tanium.csv", tanium, confirm=True)
    r = H.assets_import("ise.csv", ise, confirm=True).json()
    assert (r["created"], r["skipped"], r["mac_added"]) == (1, 1, 1), r
    by = {a["asset_name"]: a for a in H.assets()}
    assert by["WS01"]["mac_address"] == "AA:BB:CC:00:11:22"
    # A different device that reuses the hostname (different MAC) is a new asset.
    again = "MACAddress,HostName,IPAddress,EndPointPolicy\nDD:EE:FF:00:00:01,WS01,10.0.0.9,Windows11-Workstation\n"
    pv = H.assets_import("ise2.csv", again).json()
    assert pv["new_count"] == 1, pv

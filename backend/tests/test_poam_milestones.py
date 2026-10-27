"""eMASS POA&M exports carry a "Milestone with Completion Dates" column; the
import dropped it. It now becomes the finding's milestones (title + due date)."""
from services.migration_import import parse_poam

EMASS = b"""System Name:,Fictional Test System,,,,,,,,,
Date Exported:,10/27/2026,,,,,,,,,
,,,,,,,,,,
POA&M Item ID,Control Vulnerability Description,Security Control Number (NC/NA controls only),Office/Org,Security Checks,Resources Required,Scheduled Completion Date,Milestone with Completion Dates,Source Identifying Control Vulnerability,Status,Raw Severity Value,Comments
1001,Account reviews not performed quarterly,AC-2,Fictional Org,,Staff hours,12/31/2026,M1 Review procedure updated 11/30/2026,Self-assessment,Ongoing,CAT II,
1002,Audit logs not reviewed weekly,AU-6,Fictional Org,,SIEM tuning,01/15/2027,"M1: Weekly review assigned (12/01/2026)
M2: First weekly review signed off - 2027-01-08",SCA assessment,Ongoing,CAT III,
1003,Default SNMP community strings,CM-6,Fictional Org,V-12345,None,11/30/2026,,STIG checklist,Completed,CAT I,
"""


def test_emass_milestone_column_becomes_milestones():
    out = parse_poam(EMASS)
    rows = {r["poam_id"]: r for r in out["rows"]}
    assert "Milestone with Completion Dates" in out["mapped_columns"]
    assert rows["1001"]["milestones"] == [
        {"title": "M1 Review procedure updated", "due": "2026-11-30", "complete": False}]
    assert rows["1002"]["milestones"] == [
        {"title": "M1: Weekly review assigned", "due": "2026-12-01", "complete": False},
        {"title": "M2: First weekly review signed off", "due": "2027-01-08", "complete": False},
    ]
    # No milestone text: none invented.
    assert rows["1003"]["milestones"] == []


def test_milestone_without_a_date_keeps_its_text():
    csv = (b"POA&M Item ID,Weakness,Milestone with Completion Dates,Scheduled Completion Date\n"
           b"7,Weak ciphers,Replace TLS config on the load balancer,03/01/2027\n")
    row = parse_poam(csv)["rows"][0]
    assert row["milestones"] == [{"title": "Replace TLS config on the load balancer", "due": "", "complete": False}]

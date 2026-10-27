"""Demo data for Athorize: three fictional companies (Acme Industrial Corp,
Northwind Health, Contoso Energy) with users, systems, findings, evidence,
assets, risks, advisories and more. All data is made up.

Every distribution ships this module (it is part of the backend), so a demo can
be loaded wherever Athorize runs:
  * the Setup screen's "Explore with demo data" (POST /api/auth/setup/demo),
  * demo builds / ATHORIZE_DEMO_SEED=1, which auto-seed an empty database at
    startup (main._maybe_seed_demo),
  * the command line: scripts/seed_demo.py.

Demo logins: the password is the username — admin, operator (cross-company),
analyst, manager, owner, contributor (SCADA only), auditor, plus northwind and
contoso (one company each) and their -assessor accounts.

``seed_demo(db)`` only ever seeds an EMPTY database (no companies, no users)
and works inside the caller's transaction: it flushes but never commits, so a
failure rolls back to an empty instance. It also writes small placeholder
evidence files and the demo custom framework to the data folder;
``discard_demo_files()`` removes them again after a rollback.
"""
from __future__ import annotations

import shutil
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from config import settings
from models import (
    Organization, User, System, Finding, EvidenceArtifact,
    ConMonEntry, ITAsset, OTAsset, RiskRegisterEntry,
    IcsAdvisory, IcsAdvisoryMatch, FrameworkActivation,
)
from models.control import Control
from models.control_implementation import ControlImplementation
from models.assessment import Assessment, ASSESSMENT_COMPLETE, ASSESSMENT_IN_PROGRESS, ASSESSMENT_PLANNED
from models.calendar_event import CalendarEvent
from services.auth import hash_password
from services.demo_marker import mark_demo
from services.framework_loader import FrameworkLoader

CUSTOM_FW_ID = "custom-acme-security-policy"
DEMO_EVIDENCE_SUBDIR = "demo"

# Shown on the Setup screen and in the demo banner (password = username).
DEMO_LOGINS = ("admin", "operator", "manager", "analyst", "owner", "contributor", "auditor",
               "northwind", "contoso")


class DemoSeedRefused(Exception):
    """The database is not empty; demo data is never mixed into real data."""


def instance_is_empty(db: Session) -> bool:
    return db.query(Organization.id).first() is None and db.query(User.id).first() is None


def seed_demo(db: Session) -> None:
    """Load the full demo into an EMPTY database, in the caller's transaction
    (flushes, never commits). Raises DemoSeedRefused when anything is there."""
    if not instance_is_empty(db):
        raise DemoSeedRefused("Demo data can only be loaded into an empty instance "
                              "(no companies and no users).")
    _reset_clock()
    _seed_acme(db)
    seed_extra_companies(db)
    db.flush()


def demo_file_paths() -> list[Path]:
    """Files and folders the seed writes outside the database."""
    return [settings.evidence_dir / DEMO_EVIDENCE_SUBDIR, settings.custom_frameworks_dir / CUSTOM_FW_ID]


def discard_demo_files() -> None:
    """Remove what the seed wrote to disk (after its transaction rolled back)."""
    for p in demo_file_paths():
        shutil.rmtree(p, ignore_errors=True)
    _refresh_framework_registry()


def _refresh_framework_registry() -> None:
    try:
        from routers.frameworks import loader as app_loader
        app_loader.discover()
    except Exception:
        pass


def _demo_file(fname: str) -> dict:
    """Write a small placeholder file for a demo evidence row, so its download
    works and backups/restores don't report the demo records as missing files.
    Returns the EvidenceArtifact file_path/file_hash fields."""
    import hashlib
    label = f"Athorize demo evidence placeholder: {fname} (sample data, not a real document)"
    if fname.endswith(".pdf"):
        stream = f"BT /F1 11 Tf 40 760 Td ({label}) Tj ET".encode()
        objs = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
                b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
                b"/Resources << /Font << /F1 5 0 R >> >> >>",
                b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
                b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
        data, offsets = b"%PDF-1.4\n", []
        for i, body in enumerate(objs, 1):
            offsets.append(len(data))
            data += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
        xref = len(data)
        data += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
        data += b"".join(f"{o:010d} 00000 n \n".encode() for o in offsets)
        data += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    else:
        data = (label + "\n").encode()
    target = settings.evidence_dir / DEMO_EVIDENCE_SUBDIR / fname
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return {"file_path": f"{DEMO_EVIDENCE_SUBDIR}/{fname}", "file_hash": hashlib.sha256(data).hexdigest()}

# Dates are relative to "now" so the demo always looks current. Set at the
# start of every seed (a server imports this module once and may seed later).
now = datetime.now(timezone.utc)
# Demo systems have been under monitoring for over a year, so cadences that were
# never logged read as overdue (the ConMon clock starts with the first system).
SYSTEMS_SINCE = now - timedelta(days=400)
today = date.today()


def _reset_clock() -> None:
    global now, SYSTEMS_SINCE, today
    now = datetime.now(timezone.utc)
    SYSTEMS_SINCE = now - timedelta(days=400)
    today = date.today()


# A demo created "now" reads wrong to an assessor: every finding DAYS OPEN 0, an
# assessment window with no findings, a ConMon log that starts today, an empty
# trend. Records are backdated relative to the seed time (deterministic: the
# same seed time gives the same data), so aging, overdue counts, the trend and
# report windows look like a program that has been running for a year.
def _ago(days: int, hour: int = 14) -> datetime:
    """A UTC timestamp `days` before the seed day, at a fixed working hour."""
    d = today - timedelta(days=days)
    return datetime(d.year, d.month, d.day, hour, 0, tzinfo=timezone.utc)


def _seed_acme(db: Session) -> None:
    org = Organization(name="Acme Industrial Corp", slug="acme-industrial-corp")
    db.add(org)
    db.flush()

    # Demo admin is an operator so the documented admin/admin login immediately
    # shows the company switcher across all demo companies. (Per-company admins
    # like northwind/contoso stay non-operator to demo the locked view.)
    admin = User(
        organization_id=org.id, username="admin",
        password_hash=hash_password("admin"),
        email="admin@acme-industrial.com",
        display_name="Admin User", role="admin",
        is_operator=True,
    )
    # Operator: a cross-company account (home org = Acme) that can switch between
    # every company in this install and create new ones. Demonstrates the
    # consultant/MSP company-switcher. Regular admins below stay locked to Acme.
    operator = User(
        organization_id=org.id, username="operator",
        password_hash=hash_password("operator"),
        email="operator@athorize.example",
        display_name="Managed Services Operator", role="admin",
        is_operator=True,
    )
    analyst = User(
        organization_id=org.id, username="analyst",
        password_hash=hash_password("analyst"),
        email="analyst@acme-industrial.com",
        display_name="Jane Analyst", role="assessor",
    )
    # One user per remaining role so the permission matrix is demonstrable
    extra_users = [
        ("manager", "Maria Manager", "compliance_manager"),
        ("owner", "Owen Owner", "system_owner"),
        ("contributor", "Cathy Contributor", "evidence_contributor"),
        ("auditor", "Andre Auditor", "auditor"),
    ]
    role_users = [
        User(
            organization_id=org.id, username=uname,
            password_hash=hash_password(uname),
            email=f"{uname}@acme-industrial.com",
            display_name=dname, role=role,
        )
        for uname, dname, role in extra_users
    ]
    db.add_all([admin, operator, analyst, *role_users])
    db.flush()

    sys_erp = System(
        organization_id=org.id, name="Enterprise Resource Planning",
        acronym="ERP", description="Core business ERP system",
        system_type="General Support System", environment="production",
        criticality="high", impact_level="HIGH",
        authorization_status="AUTHORIZED", is_ot_enabled=False,
        created_at=SYSTEMS_SINCE,
    )
    sys_scada = System(
        organization_id=org.id, name="Plant Floor SCADA",
        acronym="SCADA", description="SCADA system for manufacturing floor",
        system_type="Industrial Control System", environment="production",
        criticality="high", impact_level="HIGH",
        authorization_status="AUTHORIZED", is_ot_enabled=True,
        created_at=SYSTEMS_SINCE,
    )
    sys_dev = System(
        organization_id=org.id, name="Development Environment",
        acronym="DEV", description="Software development and CI/CD",
        system_type="General Support System", environment="development",
        criticality="low", impact_level="LOW",
        authorization_status="NOT_AUTHORIZED", is_ot_enabled=False,
        created_at=SYSTEMS_SINCE,
    )
    sys_corp = System(
        organization_id=org.id, name="Corporate Security Program",
        acronym="CORP", description="Org-wide security program assessed against multiple frameworks simultaneously — the crosswalk showcase",
        system_type="General Support System", environment="production",
        criticality="high", impact_level="MODERATE",
        authorization_status="AUTHORIZED", is_ot_enabled=False,
        created_at=SYSTEMS_SINCE,
    )
    db.add_all([sys_erp, sys_scada, sys_dev, sys_corp])
    db.flush()

    # Demo custom framework (Framework Builder showcase): written to the DATA
    # dir like a real customer-authored framework, then activated below.
    custom_fw_id = _write_demo_custom_framework()

    loader = FrameworkLoader(settings.frameworks_dir)
    # All 18 shipped frameworks are activated so the "implement once, comply many"
    # crosswalk story is visible end-to-end.
    ACTIVE_FRAMEWORKS = [
        "pci-dss-v4", "nist-800-53-r5", "nist-800-82-r3",
        "cmmc-2.0", "fedramp", "iso-27001-2022",
        "hipaa-security", "nist-csf-2.0",
        "stateramp", "cjis", "irs-1075",
        "nerc-cip", "gdpr", "ccpa-cpra", "sox", "glba", "dora",
        "iec-62443",
    ]
    for fw_id in ACTIVE_FRAMEWORKS + ([custom_fw_id] if custom_fw_id else []):
        db.add(FrameworkActivation(
            organization_id=org.id, framework_id=fw_id, is_active=True,
            activated_at=SYSTEMS_SINCE,
        ))
        loader.load_catalog(fw_id, db)
        loader.load_mappings(fw_id, db)
    db.flush()

    # Control implementations — each system tells a different compliance story:
    #   ERP × PCI-DSS: mature program (~80% implemented)
    #   SCADA × 800-82: mid-maturity (~60% implemented, some partial)
    #   DEV × 800-53: early days (only first 30 controls touched)
    impl_count = 0

    def seed_impls(system_id, framework_id, pattern):
        nonlocal impl_count
        controls = db.query(Control).filter(
            Control.framework_id == framework_id
        ).order_by(Control.control_id).all()
        for i, ctrl in enumerate(controls):
            status = pattern(i, len(controls))
            if status is None:
                continue
            db.add(ControlImplementation(
                system_id=system_id, framework_id=framework_id,
                control_id=ctrl.control_id,
                implementation_status=status,
                narrative=(f"Control {ctrl.control_id} is implemented via documented policy and enforced technical configuration; responsibility sits with the IT Security team and the implementation is reviewed on the standard cadence." if status == "IMPLEMENTED" else ""),
                responsible_party="IT Security" if status != "NOT_APPLICABLE" else "",
                assessed_date=today - timedelta(days=30),
                assessment_result="SATISFIED" if status == "IMPLEMENTED" else "NOT_ASSESSED",
            ))
            impl_count += 1

    seed_impls(sys_erp.id, "pci-dss-v4",
               lambda i, n: "IMPLEMENTED" if i % 10 < 8 else ("PARTIALLY" if i % 10 == 8 else "NOT_IMPLEMENTED"))
    seed_impls(sys_scada.id, "nist-800-82-r3",
               lambda i, n: "IMPLEMENTED" if i % 10 < 6 else ("PARTIALLY" if i % 10 < 8 else "NOT_IMPLEMENTED"))
    seed_impls(sys_dev.id, "nist-800-53-r5",
               lambda i, n: "IMPLEMENTED" if i < 30 else None)
    # CORP × 800-53: 60 implemented → the Crosswalk Review queue fills with
    # FedRAMP + StateRAMP + IRS-1075 suggestions (all `equivalent` identity
    # mappings to the 800-53 hub). CORP × CMMC and the HIPAA/CJIS/regulation
    # mappings are intersects/related — present in control crosswalk views and
    # evidence suggestions but never auto-suggested for status propagation.
    seed_impls(sys_corp.id, "nist-800-53-r5",
               lambda i, n: "IMPLEMENTED" if i < 60 else ("PARTIALLY" if i < 70 else None))
    seed_impls(sys_corp.id, "cmmc-2.0",
               lambda i, n: "IMPLEMENTED" if i < 25 else None)
    db.flush()

    # Inspection-prep demo: link fresh evidence to a band of CORP's implemented
    # 800-53 controls so readiness shows a realistic ~40% (not 0%).
    corp_53 = db.query(ControlImplementation).filter(
        ControlImplementation.system_id == sys_corp.id,
        ControlImplementation.framework_id == "nist-800-53-r5",
        ControlImplementation.implementation_status == "IMPLEMENTED",
    ).order_by(ControlImplementation.control_id).all()
    covered = [c.control_id for c in corp_53[:40]]
    if covered:
        db.add(EvidenceArtifact(
            organization_id=org.id, system_id=sys_corp.id,
            filename="corp-800-53-control-evidence-bundle.pdf", artifact_type="attestation",
            description="Consolidated control evidence bundle for the corporate security program",
            control_ids=covered, framework_ids=["nist-800-53-r5"],
            **_demo_file("corp-bundle.pdf"),
            date_collected=today - timedelta(days=20),
            expiration_date=today + timedelta(days=160),
            created_at=_ago(20),
        ))
        db.flush()

    # Findings span the full state machine, aging buckets, and sources so
    # every Findings-page filter/KPI and the lifecycle UI have real data.
    # (title, system, severity, framework, control, status, due_offset_days, extras)
    # extras "_opened" = days ago the finding was filed (due dates follow the
    # usual windows: Critical/High 30 days, Medium 90); "_resolved" = days ago a
    # Closed / Risk Accepted / False Positive finding reached that status. The
    # SCADA findings were filed during the Annual OT assessment (45-30 days ago).
    findings_data = [
        ("Unpatched SQL Server", "ERP", "CRITICAL", "pci-dss-v4", "6.3.3", "IN_PROGRESS", 14, {
            "_opened": 16,
            "owner_name": "Owen Owner", "owner_email": "owner@acme-industrial.com",
            "remediation_plan": "Apply CU patch bundle during the next maintenance window; verify with authenticated scan.",
            "milestones": [
                {"title": "Patch staged in test", "due": str(today - timedelta(days=4)), "complete": True},
                {"title": "Production maintenance window", "due": str(today + timedelta(days=10)), "complete": False},
                {"title": "Verification scan", "due": str(today + timedelta(days=14)), "complete": False},
            ]}),
        ("Weak password policy", "ERP", "HIGH", "pci-dss-v4", "8.3.6", "CLOSED", -10, {
            "_opened": 40, "_resolved": 12,
            "actual_completion": today - timedelta(days=12), "closed_date": today - timedelta(days=12),
            "remediation_plan": "IdP policy updated to 14-char minimum with breached-password screening."}),
        ("Missing network segmentation", "SCADA", "CRITICAL", "nist-800-82-r3", "OT-SC-7", "OPEN", -8, {
            "_opened": 38, "owner_name": "Maria Manager"}),  # OVERDUE — due date in the past
        ("Default credentials on HMI", "SCADA", "CRITICAL", "nist-800-82-r3", "OT-IA-2", "IN_PROGRESS", 7, {
            "_opened": 41, "owner_name": "Owen Owner",
            "reopen_reason": "Verification found two HMIs still on vendor defaults after the first remediation pass."}),
        ("Firewall rules not reviewed", "ERP", "MEDIUM", "pci-dss-v4", "1.2.5", "DELAYED", 45, {
            "_opened": 120,
            "scheduled_completion": today + timedelta(days=45),
            "remediation_plan": "Review deferred to Q3 — network team committed to the firewall audit sprint."}),
        ("Incomplete access logs", "ERP", "MEDIUM", "pci-dss-v4", "10.2.1", "OPEN", 30, {"_opened": 60}),
        ("No incident response plan for OT", "SCADA", "HIGH", "nist-800-82-r3", "OT-IR-1", "OPEN", 21, {"_opened": 36}),
        ("Unencrypted Modbus traffic", "SCADA", "HIGH", "nist-800-82-r3", "OT-SC-8", "RISK_ACCEPTED", 0, {
            "_opened": 44, "_resolved": 21,
            "risk_rationale": "Legacy PLC fleet cannot terminate TLS; compensating controls: network segmentation + passive monitoring. Re-evaluate at fleet refresh (2027)."}),
        ("Dev database uses prod data", "DEV", "HIGH", "nist-800-53-r5", "MP-6", "OPEN", 60, {"_opened": 25}),
        ("No code review process", "DEV", "MEDIUM", "nist-800-53-r5", "SA-11", "FALSE_POSITIVE", 0, {
            "_opened": 52, "_resolved": 45,
            "risk_rationale": "GitHub branch protection requires two approving reviews — finding was based on stale documentation."}),
        ("Stale privileged accounts not disabled", "CORP", "HIGH", "cmmc-2.0", "AC.L2-3.1.1", "OPEN", 30, {"_opened": 9}),
        ("Account reviews skipped two quarters", "CORP", "MEDIUM", "nist-800-53-r5", "AC-2", "IN_PROGRESS", 20, {
            "_opened": 70, "owner_name": "Maria Manager"}),
        ("Audit log retention below 1 year", "CORP", "MEDIUM", "cmmc-2.0", "AU.L2-3.3.1", "OPEN", 30, {"_opened": 60}),
        # SIEM-sourced findings — exercise the Source column/filter and import KPI
        ("Suricata: ET EXPLOIT attempted RCE against ERP web tier", "ERP", "HIGH", "pci-dss-v4", "6.4.1", "OPEN", 14, {
            "_opened": 16,
            "extra_data": {"source_type": "suricata", "rule_id": "2034567",
                           "src_ip": "203.0.113.50", "dest_ip": "10.10.20.15",
                           "dedup_hash": "demo-suricata-0001"}}),
        ("Nessus: TLS 1.0 enabled on legacy app server", "ERP", "MEDIUM", "pci-dss-v4", "4.2.1", "IN_PROGRESS", 30, {
            "_opened": 60,
            "extra_data": {"source_type": "nessus", "plugin_id": "104743",
                           "host": "10.10.20.31", "dedup_hash": "demo-nessus-0001"}}),
    ]
    sys_map = {"ERP": sys_erp.id, "SCADA": sys_scada.id, "DEV": sys_dev.id, "CORP": sys_corp.id}

    # Real user assignment (owner_id) so "My Work", the assignee reminder
    # emails, and per-user filters are populated the moment anyone logs in.
    manager, owner_user = role_users[0], role_users[1]
    OWNER_ID_BY_NAME = {"Maria Manager": manager.id, "Owen Owner": owner_user.id}
    ADMIN_OWNED_TITLES = {"Audit log retention below 1 year", "Incomplete access logs"}
    for title, sys_key, sev, fw, ctrl, status, due_off, extras in findings_data:
        extra_data = extras.pop("extra_data", None)
        opened = _ago(extras.pop("_opened"), hour=9)
        resolved = extras.pop("_resolved", None)
        # Last touched: when it reached its terminal status, else a few days ago.
        touched = _ago(resolved, hour=16) if resolved is not None else max(opened, _ago(2, hour=16))
        owner_id = OWNER_ID_BY_NAME.get(extras.get("owner_name", ""))
        if title in ADMIN_OWNED_TITLES:
            owner_id = admin.id
            extras.setdefault("owner_name", "Admin User")
        db.add(Finding(
            organization_id=org.id, system_id=sys_map[sys_key],
            framework_id=fw, control_id=ctrl,
            title=title, severity=sev, status=status,
            due_date=today + timedelta(days=due_off),
            extra_data=extra_data,
            owner_id=owner_id,
            created_at=opened, updated_at=touched,
            **extras,
        ))
    db.flush()

    # expires_off: -10 = EXPIRED, +12 = expiring soon, rest fresh — so the
    # dashboard freshness donut and Evidence-page badges show all three states.
    # collected_ago: when the artifact was produced (validity = collected →
    # expires: a quarterly scan 90 days, policies and diagrams a year).
    evidence_data = [
        ("quarterly-vuln-scan.pdf", "scan_result", sys_erp.id, ["6.3.3"], -10, 100),
        ("password-policy-v3.docx", "policy", sys_erp.id, ["8.3.6"], 12, 353),
        ("network-diagram-2026.vsdx", "configuration", sys_scada.id, ["OT-SC-7"], 75, 290),
        ("firewall-review-q2.xlsx", "log", sys_erp.id, ["1.2.5"], 75, 105),
        ("access-log-export.csv", "log", sys_erp.id, ["10.2.1"], 75, 15),
        ("ir-plan-ot-draft.docx", "procedure", sys_scada.id, ["OT-IR-1"], 75, 46),
    ]
    for fname, atype, sid, cids, expires_off, collected_ago in evidence_data:
        db.add(EvidenceArtifact(
            organization_id=org.id, system_id=sid,
            filename=fname, artifact_type=atype,
            description=f"Demo evidence: {fname}",
            control_ids=cids, framework_ids=["pci-dss-v4"],
            **_demo_file(fname),
            date_collected=today - timedelta(days=collected_ago),
            expiration_date=today + timedelta(days=expires_off),
            created_at=_ago(collected_ago, hour=11),
        ))

    # Crosswalk-aware evidence: linked to 800-53 controls, so the detail panel
    # suggests the mapped CMMC + FedRAMP linkage one click away.
    crosswalk_evidence = [
        ("mfa-config-export.json", "configuration", sys_corp.id,
         ["IA-2"], ["nist-800-53-r5"], "IdP MFA configuration export"),
        ("account-review-2026q2.pdf", "attestation", sys_corp.id,
         ["AC-2"], ["nist-800-53-r5"], "Quarterly account review sign-off"),
        ("audit-retention-policy.pdf", "policy", sys_corp.id,
         ["AU-11", "AU-2"], ["nist-800-53-r5"], "Audit record retention policy"),
    ]
    for fname, atype, sid, cids, fwids, desc in crosswalk_evidence:
        db.add(EvidenceArtifact(
            organization_id=org.id, system_id=sid,
            filename=fname, artifact_type=atype, description=desc,
            control_ids=cids, framework_ids=fwids,
            **_demo_file(fname),
            date_collected=today - timedelta(days=8),
            expiration_date=today + timedelta(days=82),
            created_at=_ago(8, hour=11),
        ))
    db.flush()

    # A year of continuous-monitoring history. Most cadences are current; the
    # gaps are the demo's story: the quarterly ASV scan slipped (its scan
    # evidence is expired too), the monthly patch review missed this month (next
    # to the unpatched SQL Server finding), account reviews stopped two quarters
    # ago (the AC-2 finding), and annual training is a couple of weeks late.
    # (system, activity, framework ("" = org-wide), description, performed_by, days ago...)
    conmon_data = [
        (sys_erp.id, "VULNERABILITY_SCAN", "pci-dss-v4", "Quarterly ASV vulnerability scan completed",
         "Owen Owner", (100, 190, 280, 370)),
        (sys_erp.id, "LOG_REVIEW", "", "Reviewed access logs for anomalies", "Jane Analyst", (6, 36, 66, 96, 126)),
        (sys_erp.id, "PATCH_REVIEW", "", "Monthly patch compliance review", "Owen Owner", (45, 75, 105, 135)),
        (sys_scada.id, "NETWORK_SCAN", "", "Scanned OT network for unauthorized devices", "Jane Analyst", (20, 110, 200)),
        (sys_scada.id, "CONFIG_REVIEW", "", "Reviewed firewall rules and ACLs", "Owen Owner", (40, 130, 220)),
        (sys_corp.id, "ACCESS_REVIEW", "", "Quarterly privileged access review across IdP groups", "Maria Manager", (7, 97, 187)),
        (sys_corp.id, "ACCOUNT_REVIEW", "", "Quarterly user account review (last one before the reviews lapsed)",
         "Maria Manager", (200, 290)),
        (sys_corp.id, "POLICY_REVIEW", "", "Annual security policy suite review", "Maria Manager", (7, 372)),
        (sys_corp.id, "BACKUP_VERIFICATION", "", "Restored a nightly backup to a scratch host and verified checksums",
         "Owen Owner", (60, 150, 240)),
        (sys_corp.id, "RISK_ASSESSMENT", "", "Annual enterprise risk assessment", "Maria Manager", (355,)),
        (sys_corp.id, "CONTINUITY_TEST", "", "Business continuity tabletop with leadership", "Maria Manager", (300,)),
        (sys_corp.id, "USER_TRAINING", "", "Annual security awareness training campaign", "Maria Manager", (380,)),
    ]
    for sid, atype, fw, desc, who, days_list in conmon_data:
        for days in days_list:
            db.add(ConMonEntry(
                organization_id=org.id, system_id=sid, framework_id=fw,
                entry_date=today - timedelta(days=days),
                activity_type=atype, description=desc,
                performed_by=who,
                created_at=_ago(days, hour=15),
            ))
    db.flush()

    # (name, role, vendor, model, os_family, os_version, ip, env, patch, connected_to, system_id)
    # The bundled sample advisories are fictional (services/sample_advisories.py),
    # so every vendor/product/OS they MATCH on is fictional too (Woodgrove SQL,
    # Adatum Networks AN-5200 / AdatumOS, LitwareOS). Plain hardware and OS
    # inventory that no sample advisory targets (Dell servers, a Lenovo laptop,
    # Windows) stays ordinary — it makes no vulnerability claim.
    it_assets = [
        ("ERP-DB-01", "SERVER", "Woodgrove Software", "Woodgrove SQL 2019", "WINDOWS", "Server 2022", "10.10.1.21", "PRODUCTION", "CURRENT", ["ERP-APP-01"], sys_erp.id),
        ("ERP-APP-01", "SERVER", "Dell", "PowerEdge R750", "LINUX", "LitwareOS 9.3", "10.10.1.11", "PRODUCTION", "CURRENT", ["FW-CORE-01", "ERP-DB-01"], sys_erp.id),
        ("FW-CORE-01", "NETWORK_DEVICE", "Adatum Networks", "AN-5200", "OTHER", "AdatumOS 11.1", "10.10.0.1", "PRODUCTION", "BEHIND", [], sys_erp.id),
        ("DEV-WS-01", "WORKSTATION", "Lenovo", "ThinkPad T14", "WINDOWS", "11 23H2", "10.20.5.34", "DEVELOPMENT", "CURRENT", ["DEV-CI-01"], sys_dev.id),
        ("DEV-CI-01", "SERVER", "Dell", "PowerEdge R650", "LINUX", "LitwareOS 24.04", "10.20.5.10", "DEVELOPMENT", "CURRENT", [], sys_dev.id),
    ]
    for name, role, vendor, model, osf, osv, ip, env, patch, conn, sid in it_assets:
        db.add(ITAsset(
            organization_id=org.id, system_id=sid,
            asset_name=name, asset_role=role,
            vendor=vendor, model=model,
            os_family=osf, os_version=osv, ip_address=ip,
            environment=env, criticality="HIGH" if env == "PRODUCTION" else "LOW",
            patch_status=patch, connected_to=conn,
        ))

    # (name, type, vendor, model, firmware, purdue, ip, patch, connected_to, system_id)
    ot_assets = [
        # Fictional OT vendors (the sample advisories target them).
        ("PLC-LINE1", "PLC", "VanArsdel Controls", "VC-1500", "2.9.4", "LEVEL_1", "192.168.10.21", "BEHIND", ["HMI-CTRL-01"], sys_scada.id),
        ("HMI-CTRL-01", "HMI", "Fabrikam Automation", "FabView Operator Station", "R520", "LEVEL_2", "192.168.10.11", "CURRENT", ["HIST-SVR-01"], sys_scada.id),
        ("RTU-SUBST-01", "RTU", "Lamna Grid Systems", "R25 RTU", "8.1.0", "LEVEL_1", "192.168.10.22", "NOT_PATCHABLE", ["HMI-CTRL-01"], sys_scada.id),
        ("HIST-SVR-01", "HISTORIAN", "Proseware", "ProHistorian", "2023", "LEVEL_3", "192.168.10.5", "CURRENT", [], sys_scada.id),
    ]
    for name, atype, vendor, model, fw_ver, purdue, ip, patch, conn, sid in ot_assets:
        db.add(OTAsset(
            organization_id=org.id, system_id=sid,
            asset_name=name, asset_type=atype,
            vendor=vendor, model=model,
            firmware_version=fw_ver, purdue_level=purdue,
            ip_address=ip, patch_status=patch, connected_to=conn,
            protocols=["Modbus", "OPC-UA"] if atype != "HISTORIAN" else ["OPC-UA"],
        ))
    db.flush()

    # Risks span statuses and treatments so the register filters have data.
    risks = [
        ("Ransomware impact on ERP", "TECH", "HIGH", "HIGH", sys_erp.id, "MITIGATING", "MITIGATE"),
        ("Supply chain firmware compromise", "SUPPLY_CHAIN", "MODERATE", "HIGH", sys_scada.id, "OPEN", "MITIGATE"),
        ("Regulatory fine for PCI non-compliance", "COMPLIANCE", "MODERATE", "MODERATE", sys_erp.id, "TRANSFERRED", "TRANSFER"),
        ("Insider threat to OT network", "OPS", "LOW", "HIGH", sys_scada.id, "ACCEPTED", "ACCEPT"),
        ("CMMC certification slip delays DoD contract", "COMPLIANCE", "MODERATE", "HIGH", sys_corp.id, "OPEN", "MITIGATE"),
        ("Legacy VPN concentrator EOL", "TECH", "MODERATE", "MODERATE", sys_erp.id, "CLOSED", "AVOID"),
    ]
    for title, cat, likelihood, impact, sid, status, treatment in risks:
        db.add(RiskRegisterEntry(
            organization_id=org.id, system_id=sid,
            title=title, category=cat,
            likelihood=likelihood, impact=impact,
            status=status, treatment=treatment,
            mitigation="Cyber insurance policy covers regulatory fines tier" if treatment == "TRANSFER" else "",
            review_date=today + timedelta(days=90),
        ))
    db.flush()

    advisory = IcsAdvisory(
        organization_id=org.id,
        advisory_id="DEMO-ICSA-2026-001",
        title="VanArsdel Controls VC-1500 Firmware Vulnerability",
        summary="Sample advisory (fictional). Critical vulnerability in VC-1500 firmware allows remote code execution",
        severity="CRITICAL", cvss_score=9.8,
        cve_ids=["DEMO-2026-0001"],
        affected_vendor="VanArsdel Controls", affected_product="VC-1500",
        affected_firmware_range="< 3.0.0",
        recommended_mitigations="Update firmware to version 3.0.0 or later",
        published_date=today - timedelta(days=5),
        source="MOCK", status="NEW",
    )
    db.add(advisory)
    db.flush()

    plc = db.query(OTAsset).filter(OTAsset.asset_name == "PLC-LINE1").first()
    if plc:
        db.add(IcsAdvisoryMatch(
            advisory_id=advisory.id,
            ot_asset_id=plc.id,
            system_id=sys_scada.id,
            confidence="FIRMWARE_RANGE",
        ))

    # Seeded advisory gets inferred controls too
    from services.control_inference import infer_controls
    advisory.related_controls = infer_controls({
        "title": advisory.title, "summary": advisory.summary,
        "recommended_mitigations": advisory.recommended_mitigations,
    })

    # Threat feeds (bundled FICTIONAL fixtures) — IT + OT asset matching + control inference
    from services.feeds_aa import fetch_aa
    from services.feeds_kev import fetch_kev
    from services.feeds_nvd import fetch_nvd
    from services.feeds_psirt import fetch_psirt
    from services.ics_advisories import match_advisory, match_advisory_it
    it_assets_all = db.query(ITAsset).filter(ITAsset.organization_id == org.id).all()
    ot_assets_all = db.query(OTAsset).filter(OTAsset.organization_id == org.id).all()
    kev_count = 0
    kev_matches = 0
    feed_items = (
        [(a, "CISA_KEV") for a in fetch_kev(live=False)]
        + [(a, "NVD") for a in fetch_nvd(live=False)]
        + [(a, "CISA_AA") for a in fetch_aa(live=False)]
        + [(a, "PSIRT") for a in fetch_psirt(live=False)]
    )
    for adv, feed_tag in feed_items:
        row = IcsAdvisory(
            **adv, organization_id=org.id, source=feed_tag, status="NEW",
            related_controls=infer_controls(adv),
        )
        db.add(row)
        db.flush()
        kev_count += 1
        for m in match_advisory(adv, ot_assets_all):
            db.add(IcsAdvisoryMatch(
                advisory_id=row.id, ot_asset_id=m["ot_asset_id"],
                system_id=m["system_id"], confidence=m["confidence"],
            ))
            kev_matches += 1
        for m in match_advisory_it(adv, it_assets_all):
            db.add(IcsAdvisoryMatch(
                advisory_id=row.id, it_asset_id=m["it_asset_id"],
                system_id=m["system_id"], confidence=m["confidence"],
            ))
            kev_matches += 1
    db.flush()

    # (system, framework, type, status, created, started, completed) — created is
    # when it was scheduled, ahead of the start.
    assessments = [
        (sys_scada.id, "nist-800-82-r3", "Annual OT Security Assessment", ASSESSMENT_COMPLETE,
         _ago(60), _ago(45), _ago(30)),
        (sys_erp.id, "pci-dss-v4", "PCI-DSS Self-Assessment Q2", ASSESSMENT_IN_PROGRESS,
         _ago(24), _ago(10), None),
        (sys_dev.id, "nist-800-53-r5", "Initial Controls Assessment", ASSESSMENT_PLANNED,
         _ago(3), None, None),
        (sys_corp.id, "cmmc-2.0", "CMMC Level 2 Readiness Assessment", ASSESSMENT_IN_PROGRESS,
         _ago(30), _ago(20), None),
    ]
    for sid, fw, atype, status, created, started, completed in assessments:
        db.add(Assessment(
            organization_id=org.id, system_id=sid, framework_id=fw,
            assessment_type=atype, status=status,
            assessor_id=analyst.id,
            started_at=started, completed_at=completed,
            created_at=created,
            notes="Demo assessment seeded for walkthroughs.",
        ))

    calendar_events = [
        # Upcoming
        ("PCI-DSS QSA on-site assessment", "ASSESSMENT", sys_erp.id, "pci-dss-v4", 21),
        ("Quarterly vulnerability scan due", "DEADLINE", sys_erp.id, "pci-dss-v4", 14),
        ("PLC-LINE1 firmware update window", "MAINTENANCE", sys_scada.id, "nist-800-82-r3", 9),
        ("Evidence refresh: network diagram", "REVIEW", sys_scada.id, "nist-800-82-r3", 60),
        ("Annual security policy review", "REVIEW", None, "", 75),
        ("CMMC C3PAO assessment window", "ASSESSMENT", sys_corp.id, "cmmc-2.0", 45),
        # Past-due — these drive Deadline Management findings, completing the
        # "Assessment Program Failure" attack chain on each analyzed system.
        ("CMMC SSP submission deadline", "DEADLINE", sys_corp.id, "cmmc-2.0", -18),
        ("CMMC POA&M remediation milestone", "DEADLINE", sys_corp.id, "cmmc-2.0", -7),
        ("Annual control review (AC family)", "REVIEW", sys_corp.id, "nist-800-53-r5", -25),
        ("800-53 SSP annual update deadline", "DEADLINE", sys_corp.id, "nist-800-53-r5", -12),
        ("PCI ASV scan submission deadline", "DEADLINE", sys_erp.id, "pci-dss-v4", -9),
        ("PCI quarterly firewall review", "REVIEW", sys_erp.id, "pci-dss-v4", -33),
        ("OT firmware patch deadline (RTU)", "DEADLINE", sys_scada.id, "nist-800-82-r3", -15),
        ("OT network segmentation review", "REVIEW", sys_scada.id, "nist-800-82-r3", -40),
    ]
    for title, etype, sid, fw, days_out in calendar_events:
        db.add(CalendarEvent(
            organization_id=org.id, system_id=sid, framework_id=fw,
            event_type=etype, title=title,
            description="Demo calendar event.",
            event_date=today + timedelta(days=days_out),
        ))

    # Org risk context → dollar-denominated red team exposure estimates
    org.settings = {
        "risk_context": {
            "industry": "industrial",
            "annual_revenue": 120_000_000,
            "largest_contract_value": 18_000_000,
            "record_count": 250_000,
            "employee_count": 850,
        }
    }
    db.flush()

    # Advisory triage variety: the seeded PLC advisory is triaged, one feed item
    # dismissed, one asset match dismissed — exercises the triage workflow UI.
    advisory.status = "TRIAGED"
    advisory.triaged_by = "manager"
    advisory.triaged_at = now - timedelta(days=2)
    dismissable = db.query(IcsAdvisory).filter(
        IcsAdvisory.organization_id == org.id, IcsAdvisory.source == "CISA_AA",
    ).first()
    if dismissable:
        dismissable.status = "DISMISSED"
        dismissable.triaged_by = "manager"
        dismissable.triaged_at = now - timedelta(days=1)
    dismissed_match = db.query(IcsAdvisoryMatch).join(
        IcsAdvisory, IcsAdvisoryMatch.advisory_id == IcsAdvisory.id,
    ).filter(IcsAdvisory.organization_id == org.id, IcsAdvisoryMatch.confidence == "VENDOR_ONLY").first()
    if dismissed_match:
        dismissed_match.dismissed = True

    # Implementation status variety: INHERITED (common-control story) and
    # PLANNED (what a crosswalk accept produces) so both render in the UI.
    corp_inherited = db.query(ControlImplementation).filter(
        ControlImplementation.system_id == sys_corp.id,
        ControlImplementation.framework_id == "nist-800-53-r5",
        ControlImplementation.control_id.in_(["IA-2", "IA-5", "AU-6"]),
    ).all()
    for impl in corp_inherited:
        impl.implementation_status = "INHERITED"
        impl.inherited_from = "Enterprise SSO platform (corporate common controls)"
    db.add(ControlImplementation(
        system_id=sys_corp.id, framework_id="fedramp", control_id="AC-2",
        implementation_status="PLANNED",
        narrative="Accepted from crosswalk: satisfied by nist-800-53-r5 AC-2 on this system. Pending assessor confirmation.",
        responsible_party="IT Security",
        owner_id=admin.id,
    ))

    # --- Feature showcase seeds (so evaluators SEE the workflow features) ---
    # Control ownership: a few unfinished CORP controls assigned to real users
    # → their "My Work" fills in.
    corp_todo = db.query(ControlImplementation).filter(
        ControlImplementation.system_id == sys_corp.id,
        ControlImplementation.framework_id == "nist-800-53-r5",
        ControlImplementation.implementation_status == "PARTIALLY",
    ).order_by(ControlImplementation.control_id).limit(4).all()
    for i, impl in enumerate(corp_todo):
        impl.owner_id = admin.id if i < 2 else owner_user.id

    # Evidence refresh ownership: the expired + expiring artifacts get owners
    # → refresh tasks in My Work + assignee reminder emails have content.
    ev_owner_map = {
        "quarterly-vuln-scan.pdf": role_users[2].id,   # contributor owns the EXPIRED scan
        "password-policy-v3.docx": admin.id,           # admin owns the expiring policy
    }
    for e in db.query(EvidenceArtifact).filter(
        EvidenceArtifact.organization_id == org.id,
        EvidenceArtifact.filename.in_(list(ev_owner_map.keys())),
    ).all():
        e.owner_id = ev_owner_map[e.filename]

    # Per-system access: the evidence contributor is scoped to SCADA only —
    # the "plant contractor sees only the plant" story. Log in as
    # contributor/contributor to see the app narrowed to one system.
    from models import SystemAssignment
    db.add(SystemAssignment(user_id=role_users[2].id, system_id=sys_scada.id))

    # A saved filter view for the admin (Views dropdown on Findings).
    from models import SavedView
    db.add(SavedView(
        organization_id=org.id, user_id=admin.id, page="findings",
        name="Critical & overdue", params={
            "filterFramework": "", "filterSeverity": "CRITICAL",
            "filterStatus": "OPEN", "filterSource": "", "mineOnly": False,
        },
    ))
    # SavedViews on the pages that gained them 2026-07-29, so no Views dropdown
    # is empty in the demo. Params mirror each page's filter state verbatim.
    db.add(SavedView(
        organization_id=org.id, user_id=admin.id, page="evidence",
        name="Assigned to me", params={"mineOnly": True},
    ))
    db.add(SavedView(
        organization_id=org.id, user_id=admin.id, page="controls",
        name="CORP · 800-53 access controls", params={
            "selectedFramework": "nist-800-53-r5",
            "selectedSystem": str(sys_corp.id), "selectedFamily": "AC",
        },
    ))
    db.add(SavedView(
        organization_id=org.id, user_id=admin.id, page="assets",
        name="OT estate", params={"search": "", "filterKind": "OT"},
    ))
    db.flush()

    # Comment threads with @mentions (2026-07-29 feature) — a realistic
    # discussion on the flagship finding and one on a control implementation,
    # so FindingDetailPanel and the Controls impl editor open with live threads.
    from models import Comment
    sql_finding = db.query(Finding).filter(
        Finding.organization_id == org.id,
        Finding.title == "Unpatched SQL Server",
    ).first()
    manager_user = role_users[0]
    db.add(Comment(
        organization_id=org.id, entity_type="finding", entity_id=sql_finding.id,
        author_id=manager_user.id, mentions=[admin.id],
        body="Patch window approved for Saturday 02:00 UTC. @admin can you "
             "confirm the rollback snapshot is in place before we start?",
        created_at=now - timedelta(hours=26),
    ))
    db.add(Comment(
        organization_id=org.id, entity_type="finding", entity_id=sql_finding.id,
        author_id=admin.id, mentions=[manager_user.id],
        body="Confirmed @manager — snapshot taken and restore-tested against DEV "
             "this morning. Go for Saturday.",
        created_at=now - timedelta(hours=3),
    ))
    if corp_todo:
        db.add(Comment(
            organization_id=org.id, entity_type="control_implementation",
            entity_id=corp_todo[0].id, author_id=analyst.id, mentions=[],
            body="Narrative drafted from the current SSP language; needs the "
                 "screenshot evidence refreshed before this can move to IMPLEMENTED.",
            created_at=now - timedelta(days=2),
        ))
    db.flush()

    # Per-company branding (2026-07-29 feature): Acme ships with a logo so the
    # sidebar mark + Audit Binder cover demonstrate it out of the box.
    org_settings = dict(org.settings or {})
    org_settings["branding"] = {
        "logo_data_uri": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAPAAAABQCAYAAAAnSfh8AAAAOnRFWHRTb2Z0d2FyZQBNYXRwbG90bGliIHZlcnNpb24zLjExLjEsIGh0dHBzOi8vbWF0cGxvdGxpYi5vcmcvctoD+AAAAAlwSFlzAAAPYQAAD2EBqD+naQAADCRJREFUeJztnQvQFWUZx//cEg20i5mlGEJKJlpNvqsWRBpdEE0pE6yELLewRUlrWycTGDFy5+2qraUraZlGRhkGahexESJ5tyAok/ESTnmpARQFjJvSPMxzvjkcz+6+ey7fd/b7nt/MmfnOt7f3nLP/9/Lctt+ePXsgCEI56d/TDRAEoXFEwIJQYkTAglBiRMCCUGJEwIJQYkTAglBiRMCCUGJEwIJQYkTAglBiRMCCUGJEwIJQYkTAglBiRMCCUGJEwIJQYkTAglBiRMCCUGJEwIJQYkTAglBiBqKXo4w+CMA7AIwAcDiAAwEMBrAdwBYAzwBYB+DBxPGf6un2CkIR+rWiJpYy+t0AzrPc/YeJ45umL5rdnmMAfBLAGQBG0+e0PJQEfDeAuwAsSRx/h8W1vg7g1ZbnvzNxfDp3YZTRdI15BT6LThz/sRa2vSjbE8f/QpvOLbR4BP4ygA9b7vsqAFPQBpTRJwK4CsD4Bk/xRgCf4dcGZfR8FgKN0mlQx3WY5fnHcOfQCJ8FML3A/j8BkCnggm0vyjYAIuBOXwMro18HYEKBQ85URpOIW4Yyeqgy+kYADzQh3lroc10GwEHrOFYZ/f6iBymjqaOd0cJ2CL2EVhixPgFgUIH9af05GS1CGf1mAH/hUbMMzGzgmLN5/S4ILRfwtG465mUoo98K4E8AjkJ5OE0ZfXTBY2QqKrR+DayMPh7A2xs49GS6iRPHf7iJa9N69bcADi5w2BoAfwTwHwCbAZCF+jUARgE4if9uN2SEuth2SqyMPhkAre0FoeVGrE81cSyNwpc3cqAymmYOt1oaYF4iyzeAuYnj/yvjnCSs47hdZME+BO1jmjL68sTxn7PY9xL0HDuaGP13tbgtQisFzIYVWv82ynnK6CsSxyeBFcUF8F6L/Z4lV1Li+DTqZpI4PvnT1gL4ojL6Mrb4zkJ7GALgAgDfzNpJGX0EgEnoOXYnjv+DHry+0MY18IScUYpGu39nbB8G4NSiF1VG70+jqcWuNEUeZyPeWhLH35U4/rUARgJYjfYwQxk9IGefi/pCsI3QOAPbOH2+DQDdoH7OOX5f8LpT2cWTx8WJ4/8NTZA4/vMA6NUMG1PW6cPJpQbgl/UOUka/kkfpemyw/A6EXk5DI7Ay+rUATrcQMK1Ts5ikjKbQxiKcb7HP0sTxb0FnQO14oQGXEnVuaf7y61vQLqEPT6HPBfCKjO1rafRLHJ+svg9m7HcAgI8VtDzbBFbQ9LdToCiutM7kPcpoitOuZ1CbmTH65nWMQh+hf5umz7fWjMTNnKs2FDEvFngTgF+js/gOgLSg83pW3okZvu3rORFDEIoLWBl9LIB3ZuxCN+pPCwh4jDKajEU2nGCxzwOJ47+IDiJx/HXss67HFGX06y1dRzsBXNfi5gl9zIiVN2Lenzh+l/U5cfzHldErALwr45hpli4bSgnMo62ZTk2Owh+s839ailwIYA69UUYfl2Gdvz1x/KeV0WQA6w72U0Y36ka6JHH8/7W4PUIzAma3R57vt9767LYcAU9VRs9mX2wWNoEbT6Az+Q2AhwBQqmMt05XR8xLH35kTuEGdQHffH59r8FjypYuAO2wKTSPIGzK20w24sM7/b6eggIzj3mQZmEEBEDb+346DO6fvpmymKfS5ymjyq388ZZ9lieNT0oYgNCzgvCSEuxLHp+infUgcnyynv2vy3MixfFfnoXYqP2ardD1m8lR6vw4ZfYXeJGDO4c1L2s9yb+S5Ps5WRueNsLkVMrhkTkfCa8IbUjaTOylI2fY4gEVtbJrQB0bgKZzLmwZFLC3O2P6rjIAGgiKPPprTBpuoqJYWC2gD38tYTlCYaD2u7TTLulA+I1ae9fkXieOn+icTx9+mjF7EQSBZ1/hRxvas2OoKR6KDSRz/SWX0wgJlhbYCoNI+ZctGyuqsmyKOwgGc0LLA9YLNVe8fc72ga6kWRyGliA5yvWBZ1T4EdYa01FvtekFX2aE4CivlnmLXC7o6zDgKqcrLFtcLVlb9j9I8qZjEegArXC94KY7CQwGcldF0sgWdw39TEs/TAO5zvWBrvc9V85mpCMZG1wvurf4erASsjB5lkZM63MLlkGdFHkcuEnI9pWx/BPmUIXf22wUEfJNl2mFfykaiCjDfB/AHNlpW3m+Jo3CE6wUUf16pZELLsmVV+/yMq5FSMs2JcRQmlBnnesF/ARzK+9zMIq9AMel0T66Mo3AgBwqRN+F+Ps+QOArP5BlUJT9+KBskb2LjLrgeWqUNz3PBxfnU0bhe8M86n2svcRQezjXONsRROKyqcxlkOwLbREudwq9m6MfJClembKcvOw9HGX1A4vhtGwGahapyKqOpfheNEFlQL31NNzWrN/B3tiNkJdDMcb1gHQuDYvrvYPuMbS21D3Ag04iqkfNtlLjDo/newoNxFA5nAV9aGU3jKBxcpw0ruIP4Sk7xwSUA6DpUU+0e6zUwJ89Tgnt3QQJOY5lFoviQdlW9bMMonMfixPEf7Ya29BbmkN86jsIsV2cXrhds4iXC+2jktrwG3V80OHQNEK4XrHG9wGZ5V4/NnBOQ56FZwFPwqUWNWOO7uaDaSGX02HobEsenD3ufxTlmWuTa9jSURpj3o4vrqBgPky2mYKWXtWxUpGWiDTQNpvtwVRyFc+MonFA1stoyOY7CC+MovI6XfFRRtS68jj+Cp+009T4rjsIDiwi4JQXoCpJ1zTQ3TDXHcyRQx5I4/m62SGdldNl0VsK+0PJrWhyFdNPb8CK/rDp8njYrALN5zUvF9tfFUfgW2HMMT8M/BODnrhfQ1D9LC4tdL9jmesEqAE9WGcKyBcy5uj1R0uUcWsdmuKNsiuHNUkbn5SxnoowerYxuZ8XLOCPwREbfBnC9YD2vaW3LIY3g4BkyIj2XEktwULVRyfWCXa4XLHK94EuuF5D/flXOGrYWWgNfwMk5k+IorOs+jaOQ2kXW551xFE6nFz89pGsanWfEmpzhmwT3XBRBVNRHOYDDCtN6PbLgfYQtb/tA/lBl9KU5PudK1NYdyujP0xTFIs66C04W+CoXD5hoaf0uDEWtKaOpN60dLfZYZHEJ6VzFcedL2VVTlzgK+/OITZVbHnK9YE8chZs4bXVvpZQ4Cvfn0TLi98PYnVMd572hkYqmrhc8E0fh1dzZ0NS/FgqcojZurbJuk03kfF6zPzWwyenz8sTx936woiijqXMYm3PtlwmYSBx/iTL6Zgvr+ECecn9aGf01Kt+T5qtWRpOLaxxfd3x3Pbmx0WcllSAbiViYOH7RkklN43rBE3EUzufyvTfUWX+S4IZxXTd6NtREEi9vp6VXHEfhCTzqkivqH2wFJmhGtjSOQvrd1rMriEbE05uYhc2itXQd+w7di7e4XnDRPgdE4Si+5tUDc554QA8ty4Kms42yKEfApyqjh1WnJtYwg788mxzhk9gI8IIyenWdutBH8Q8qtC4bqTJatEPAu7mwwbM178m/W4Ee3DaYfbXV+5CF+hD+/ak44hLXC7o6ddcLboyjcC0n7hzMbrwFFYG7XkDiHcOVZEbyZxztekHtsm4LX29HRrv3rqnjKKRZ7GHV29nfvD7FTjKb1+G7U59OqIyey9PILI7MCLrIhDuIvKkp1U6el3EO+oLvZaNVu5iQOP49GW14IidAhUrn0pSuZfAUn37cLMYmjr885zx5bW8WP3H8b7Tx/H2eutNErsmU97jQNY2Kl2D/Jk1NGp7CJ46/kUfxVIEJQm8mbZ13Cufotmv6XCEvw+ZofrRIXunX09iYVj2FEoQ+K2Cb0MlWCPhOi31y20IW5sTxr+E1ybdalNS/nBMvuoLHBaHTSDNiUUYHxWhmBbn/tQXXX8lGkiyLr3UgPxcOoEejXMFWwTN4ip03mwAn2v8ZwN0FQxjJajmkm2t0beLk/ywebUHbm4WeHCm0kVQjVm9CGU2W5hEcEjqUrZPbecpNwn2EisX1dDsFoSh9QsCC0FvplmAFQRDagwhYEEqMCFgQSowIWBBKjAhYEEqMCFgQSowIWBBKjAhYEEqMCFgQSowIWBBKjAhYEEqMCFgQSowIWBBKjAhYEEqMCFgQSowIWBBKjAhYEEqMCFgQSowIWBBKjAhYEEqMCFgQSowIWBBKjAhYEFBe/g86WYNZzH3YvwAAAABJRU5ErkJggg==",
        "updated_at": now.isoformat(),
    }
    org.settings = org_settings
    db.flush()

    # Org-level ConMon cadence override (beats framework metadata + defaults)
    from models.conmon_cadence import ConMonCadence
    db.add(ConMonCadence(
        organization_id=org.id, framework_id="",
        activity_type="VULNERABILITY_SCAN", interval_days=30, enabled=True,
    ))

    # Audit-log activity: reseed wipes the chain, so record a representative
    # day-in-the-life so the Audit Log page (and SIEM import history, which
    # reads action=SIEM_IMPORT) isn't empty in demos/screenshots.
    from services import audit as audit_svc
    demo_audit = [
        (admin.id, "admin", "LOGIN", "session", None, None, "Signed in"),
        (admin.id, "admin", "CREATE", "user", role_users[0].id, None, "Created user manager (compliance_manager)"),
        (role_users[0].id, "manager", "LOGIN", "session", None, None, "Signed in"),
        (role_users[0].id, "manager", "UPDATE", "finding", 1, sys_erp.id, "Finding 'Unpatched SQL Server' moved OPEN → IN_PROGRESS"),
        (role_users[0].id, "manager", "SIEM_IMPORT", "finding", None, sys_erp.id, "Imported 2 findings from suricata (1 skipped as duplicate)"),
        (analyst.id, "analyst", "LOGIN", "session", None, None, "Signed in"),
        (analyst.id, "analyst", "UPDATE", "control_implementation", None, sys_corp.id, "Crosswalk accept: fedramp AC-2 set to PLANNED from nist-800-53-r5 AC-2"),
        (role_users[0].id, "manager", "UPDATE", "advisory", advisory.id, sys_scada.id, "Advisory DEMO-ICSA-2026-001 triaged"),
    ]
    for actor_id, uname, action, etype, eid, sid, summary in demo_audit:
        audit_svc.record(
            db, organization_id=org.id, actor_id=actor_id, actor_username=uname,
            action=action, entity_type=etype, entity_id=eid, system_id=sid,
            summary=summary,
        )
    db.flush()

    # Red team reports with quantified exposure (feeds the Red Team page and
    # the Executive Briefing risk-exposure slide)
    from models.redteam import RedTeamReport
    from services.redteam_analyzer import analyze_system

    redteam_runs = [
        (sys_corp.id, "nist-800-53-r5"),
        (sys_erp.id, "pci-dss-v4"),
        (sys_scada.id, "nist-800-82-r3"),
    ]
    for sid, fw in redteam_runs:
        result = analyze_system(db, sid, fw, organization_id=org.id, run_by="Demo Seed")
        db.add(RedTeamReport(
            organization_id=org.id, system_id=sid, framework_id=fw,
            run_by=result["run_by"], summary=result["summary"],
            total_findings=result["total_findings"],
            critical_count=result["critical_count"], high_count=result["high_count"],
            medium_count=result["medium_count"], low_count=result["low_count"],
            total_exposure_low=result.get("total_exposure_low", 0),
            total_exposure_high=result.get("total_exposure_high", 0),
            top5_reduction_low=result.get("top5_reduction_low", 0),
            top5_reduction_high=result.get("top5_reduction_high", 0),
            quick_win_count=result.get("quick_win_count", 0),
            has_org_context=1 if result.get("has_org_context") else 0,
            findings=result["findings"], attack_chains=result["attack_chains"],
            created_at=_ago(2, hour=10),
        ))
    db.flush()

    # Compliance trend: weekly snapshots for the past quarter (the daily job
    # only starts recording today), so the Dashboard trend, the findings
    # burndown and the Audit Binder progress section have history.
    seed_history(db, org.id)

    print("Demo data seeded successfully.")
    print(f"  Organization: {org.name}")
    print(f"  Users: admin, operator (cross-company), analyst, manager, owner, contributor, auditor (password = username)")
    print(f"  Systems: ERP, SCADA, DEV, CORP")
    print(f"  Frameworks active: {len(ACTIVE_FRAMEWORKS)}{' + 1 custom (Acme Security Policy)' if custom_fw_id else ''}")
    print("  Showcase: owners assigned (My Work populated for admin/manager/owner/contributor),")
    print("            contributor scoped to SCADA only, saved views on findings/evidence/controls/assets,")
    print("            comment threads w/ @mentions on the SQL finding + a CORP control, Acme logo branding,")
    print("            custom framework active")
    print(f"  Findings: {len(findings_data)}")
    print(f"  Evidence: {len(evidence_data)}")
    print(f"  IT Assets: {len(it_assets)}")
    print(f"  OT Assets: {len(ot_assets)}")
    print(f"  Risks: {len(risks)}")
    print(f"  Advisories: 1 ICS + {kev_count} feed items ({kev_matches} asset matches)")
    print(f"  Control implementations: {impl_count}")
    print(f"  Assessments: {len(assessments)}")
    print(f"  Calendar events: {len(calendar_events)}")
    print(f"  Red team reports: {len(redteam_runs)} (with org risk context)")

    # Persistent "demo instance" marker → in-app banner (services/demo_marker).
    mark_demo(org)
    db.flush()


_TERMINAL = ("CLOSED", "RISK_ACCEPTED", "FALSE_POSITIVE")


def _as_date(dt: datetime) -> date:
    return (dt.astimezone(timezone.utc) if dt.tzinfo else dt).date()


def _open_on(f: Finding, day: date) -> bool:
    """Was the finding open on `day`? Filed on or before it and not yet resolved
    (a terminal finding's updated_at is when it reached that status)."""
    if f.created_at is None or _as_date(f.created_at) > day:
        return False
    if f.status in _TERMINAL:
        resolved = f.closed_date or (_as_date(f.updated_at) if f.updated_at else None)
        return resolved is not None and resolved > day
    return True


def seed_history(db: Session, organization_id: int, weeks: int = 12) -> int:
    """Weekly ComplianceSnapshot rows for the past `weeks` weeks for every
    (system x active framework) pair the daily job records. Finding counts are
    what was open on each day (from the backdated filing / resolution dates);
    scores ramp up to today's, so the trend shows a program improving. Today's
    point stays live (GET /dashboard/history computes it). Returns rows written."""
    from models.compliance_snapshot import ComplianceSnapshot
    from services.history import live_pair_scores

    pairs = live_pair_scores(db, organization_id, on=today)
    findings = db.query(Finding).filter(Finding.organization_id == organization_id).all()
    written = 0
    for w in range(weeks, 0, -1):
        day = today - timedelta(days=7 * w)
        ramp = 1 - 0.035 * w  # 12 weeks back: ~58% of today's implementation
        for p in pairs:
            fs = [f for f in findings
                  if f.system_id == p["system_id"] and f.framework_id == p["framework_id"] and _open_on(f, day)]
            db.add(ComplianceSnapshot(
                organization_id=organization_id, system_id=p["system_id"],
                framework_id=p["framework_id"], snapshot_date=day,
                score_percentage=round(p["score_percentage"] * ramp, 1),
                total_controls=p["total_controls"],
                implemented=round(p["implemented"] * ramp),
                open_findings=len(fs),
                critical_findings=sum(1 for f in fs if f.severity == "CRITICAL"),
                overdue_findings=sum(1 for f in fs if f.due_date and f.due_date < day),
                created_at=_ago(7 * w, hour=2),
            ))
            written += 1
    db.flush()
    return written


def _write_demo_custom_framework() -> str | None:
    """Write the demo's customer-authored framework to the data dir (idempotent)
    and refresh the app's shared loader so it shows up without a restart."""
    import json as _json

    fw_id = CUSTOM_FW_ID
    target = settings.custom_frameworks_dir / fw_id
    try:
        if not target.exists():
            target.mkdir(parents=True, exist_ok=True)
            (target / "metadata.json").write_text(_json.dumps({
                "id": fw_id, "name": "Acme Security Policy",
                "short_name": "Acme Policy", "version": "1.0",
                "catalog_version": "custom",
                "description": "Acme's internal security policy tracked alongside regulatory frameworks — built with the Framework Builder.",
                "publisher": "Acme Industrial Corp (in-house)",
                "category": "general", "tags": ["custom"],
                "status": "available", "icon": "wrench", "color": "#7c3aed",
            }, indent=2))
            (target / "catalog.json").write_text(_json.dumps({
                "framework_id": fw_id,
                "controls": [
                    {"id": "POL-1", "family": "POL", "family_name": "Policy", "title": "Acceptable use policy signed annually",
                     "description": "Every employee re-signs the acceptable use policy each January.", "baselines": []},
                    {"id": "POL-2", "family": "POL", "family_name": "Policy", "title": "Quarterly access review",
                     "description": "Line managers attest to their team's access every quarter.", "baselines": []},
                    {"id": "POL-3", "family": "POL", "family_name": "Policy", "title": "Vendor security questionnaire",
                     "description": "New vendors complete the security questionnaire before onboarding.", "baselines": []},
                    {"id": "POL-4", "family": "OPS", "family_name": "Operations", "title": "Change advisory board approval",
                     "description": "Production changes require CAB sign-off recorded in the ticket.", "baselines": []},
                    {"id": "POL-5", "family": "OPS", "family_name": "Operations", "title": "Annual tabletop exercise",
                     "description": "Run one incident-response tabletop per year with leadership.", "baselines": []},
                ],
            }, indent=2))
        _refresh_framework_registry()  # shows up without a restart
        return fw_id
    except OSError as exc:
        print(f"  (demo custom framework skipped: {exc})")
        return None


def _seed_company(db: Session, *, name, slug, industry, revenue, frameworks, primary_fw,
                  admin_username, systems_spec):
    """Create a compact-but-real second/third company so the operator
    company-switcher has visibly distinct data (different frameworks, systems,
    findings) to switch between. Idempotent per slug."""
    if db.query(Organization).filter(Organization.slug == slug).first():
        return None

    org = Organization(name=name, slug=slug, settings={"risk_context": {
        "industry": industry, "annual_revenue": revenue,
        "largest_contract_value": revenue // 8, "record_count": 100_000,
        "employee_count": 300,
    }})
    mark_demo(org)
    db.add(org)
    db.flush()

    # One locked (non-operator) admin + one assessor to demo the customer view.
    db.add_all([
        User(organization_id=org.id, username=admin_username,
             password_hash=hash_password(admin_username),
             email=f"admin@{slug}.example", display_name=f"{name} Admin", role="admin"),
        User(organization_id=org.id, username=f"{admin_username}-assessor",
             password_hash=hash_password(f"{admin_username}-assessor"),
             email=f"assessor@{slug}.example", display_name=f"{name} Assessor", role="assessor"),
    ])

    systems = []
    for acronym, sname, impact, ot in systems_spec:
        s = System(
            organization_id=org.id, name=sname, acronym=acronym,
            description=f"{sname} for {name}", system_type="General Support System",
            environment="production", criticality="high", impact_level=impact,
            authorization_status="AUTHORIZED", is_ot_enabled=ot,
            created_at=SYSTEMS_SINCE,
        )
        db.add(s)
        systems.append(s)
    db.flush()

    loader = FrameworkLoader(settings.frameworks_dir)
    for fw_id in frameworks:
        db.add(FrameworkActivation(organization_id=org.id, framework_id=fw_id,
                                   is_active=True, activated_at=SYSTEMS_SINCE))
        loader.load_catalog(fw_id, db)
        loader.load_mappings(fw_id, db)
    db.flush()

    # Implementations on the primary system: first 40 controls, ~70% implemented.
    prim_controls = db.query(Control).filter(
        Control.framework_id == primary_fw
    ).order_by(Control.control_id).all()
    for i, ctrl in enumerate(prim_controls[:40]):
        status = "IMPLEMENTED" if i % 10 < 7 else ("PARTIALLY" if i % 10 < 9 else "NOT_IMPLEMENTED")
        db.add(ControlImplementation(
            system_id=systems[0].id, framework_id=primary_fw, control_id=ctrl.control_id,
            implementation_status=status,
            narrative=("Implemented via documented policy and technical configuration."
                       if status == "IMPLEMENTED" else ""),
            responsible_party="Security Team",
            assessed_date=today - timedelta(days=30),
            assessment_result="SATISFIED" if status == "IMPLEMENTED" else "NOT_ASSESSED",
        ))
    db.flush()

    # A few findings referencing real primary-framework control ids.
    fx = prim_controls[:6]
    # (title, severity, control, status, due offset, days ago filed)
    finding_specs = [
        (f"Overdue remediation on {fx[0].control_id}", "HIGH", fx[0].control_id, "OPEN", -6, 36),
        (f"Partial coverage for {fx[1].control_id}", "MEDIUM", fx[1].control_id, "IN_PROGRESS", 21, 69),
        (f"Evidence stale for {fx[2].control_id}", "MEDIUM", fx[2].control_id, "OPEN", 30, 60),
        (f"Accepted risk on {fx[3].control_id}", "LOW", fx[3].control_id, "RISK_ACCEPTED", 0, 80),
    ] if len(fx) >= 4 else []
    for title, sev, cid, status, due_off, opened in finding_specs:
        db.add(Finding(
            organization_id=org.id, system_id=systems[0].id,
            framework_id=primary_fw, control_id=cid, title=title,
            severity=sev, status=status, due_date=today + timedelta(days=due_off),
            created_at=_ago(opened, hour=9),
            updated_at=_ago(30 if status == "RISK_ACCEPTED" else 3, hour=16),
        ))

    # A couple evidence artifacts + risks so the dashboards aren't empty.
    if len(fx) >= 2:
        db.add(EvidenceArtifact(
            organization_id=org.id, system_id=systems[0].id,
            filename=f"{slug}-control-evidence.pdf", artifact_type="attestation",
            description=f"Control evidence bundle for {name}",
            control_ids=[fx[0].control_id, fx[1].control_id], framework_ids=[primary_fw],
            **_demo_file(f"{slug}-evidence.pdf"),
            date_collected=today - timedelta(days=15),
            expiration_date=today + timedelta(days=165),
            created_at=_ago(15, hour=11),
        ))
    db.add(RiskRegisterEntry(
        organization_id=org.id, system_id=systems[0].id,
        title=f"Regulatory exposure for {name}", category="COMPLIANCE",
        likelihood="MODERATE", impact="HIGH", status="OPEN", treatment="MITIGATE",
        review_date=today + timedelta(days=90),
    ))
    db.flush()
    seed_history(db, org.id)
    return org


def seed_extra_companies(db: Session) -> None:
    """Add two more companies (beyond Acme) so the operator switcher is demoable.
    Idempotent per company; flushes only (the caller commits)."""
    created = []
    nw = _seed_company(
        db,
        name="Northwind Health", slug="northwind-health", industry="healthcare",
        revenue=80_000_000, admin_username="northwind",
        frameworks=["hipaa-security", "pci-dss-v4", "nist-csf-2.0", "iso-27001-2022"],
        primary_fw="hipaa-security",
        systems_spec=[("EHR", "Electronic Health Records", "HIGH", False),
                      ("PAY", "Patient Payment Processing", "MODERATE", False)],
    )
    if nw:
        created.append(nw.name)
    ce = _seed_company(
        db,
        name="Contoso Energy", slug="contoso-energy", industry="energy",
        revenue=210_000_000, admin_username="contoso",
        frameworks=["nerc-cip", "iec-62443", "nist-800-82-r3", "nist-800-53-r5"],
        primary_fw="nerc-cip",
        systems_spec=[("GRID", "Grid Control SCADA", "HIGH", True),
                      ("SUB", "Substation RTU Network", "HIGH", True)],
    )
    if ce:
        created.append(ce.name)
    if created:
        db.flush()
        print(f"  Extra companies seeded: {', '.join(created)}")
    else:
        print("  Extra companies already present — skipping.")
    print("  Operator login: operator / operator (can switch between all companies)")

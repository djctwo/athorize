"""Offline ICS advisory feed (ICS_FEED unset / "mock").

SAMPLE DATA. Every vendor, product, vulnerability and identifier below is
FICTIONAL (see services/sample_advisories.py). IDs use the reserved DEMO-
namespace so they can never be confused with a real CISA ICSA advisory or
CVE record, and no item links to a real advisory site.
"""
from datetime import date, timedelta


def mock_advisories() -> list[dict]:
    today = date.today()
    return [
        {
            "advisory_id": "DEMO-ICSA-26-073-01",
            "title": "VanArsdel Controls VC-1200 PLC Improper Access Control",
            "summary": (
                "Sample advisory (fictional). VanArsdel Controls VC-1200 CPUs "
                "below firmware V4.5.2 contain an improper access control "
                "vulnerability (CWE-284) allowing an unauthenticated remote "
                "attacker to read process data via crafted engineering-protocol "
                "packets on TCP/4400."
            ),
            "severity": "HIGH",
            "cvss_score": "8.1",
            "cve_ids": ["DEMO-2026-0011"],
            "affected_vendor": "VanArsdel Controls",
            "affected_product": "VC-1200 PLC",
            "affected_firmware_range": "< V4.5.2",
            "recommended_mitigations": (
                "Upgrade to V4.5.2 or later. Until patched, block TCP/4400 at "
                "the cell/zone boundary and restrict engineering connections to "
                "authorized engineering workstations only."
            ),
            "published_date": today - timedelta(days=3),
            "source_url": "",
        },
        {
            "advisory_id": "DEMO-ICSA-26-066-02",
            "title": "Tailspin Building Systems TB-400 BACnet Controller Authentication Bypass",
            "summary": (
                "Sample advisory (fictional). Tailspin Building Systems TB-400 "
                "BACnet controllers expose an authentication bypass (CWE-287) "
                "via crafted BACnet/IP WriteProperty requests, permitting an "
                "adjacent attacker to modify setpoint values on the control "
                "network."
            ),
            "severity": "CRITICAL",
            "cvss_score": "9.4",
            "cve_ids": ["DEMO-2026-0012", "DEMO-2026-0013"],
            "affected_vendor": "Tailspin Building Systems",
            "affected_product": "TB-400 BACnet Controller",
            "affected_firmware_range": "V3.x (all)",
            "recommended_mitigations": (
                "Vendor has declared end-of-life. Segment controllers behind "
                "a BACnet-aware firewall; restrict WriteProperty to the "
                "supervisory HMI address; enable BACnet/SC where supported."
            ),
            "published_date": today - timedelta(days=10),
            "source_url": "",
        },
        {
            "advisory_id": "DEMO-ICSA-26-059-04",
            "title": "Tailspin BMS Supervisor Path Traversal",
            "summary": (
                "Sample advisory (fictional). Tailspin BMS Supervisor versions "
                "prior to 4.14 contain a path traversal (CWE-22) in the station "
                "backup handler, allowing an authenticated user to read files "
                "outside the station home directory via ../ sequences."
            ),
            "severity": "MEDIUM",
            "cvss_score": "6.5",
            "cve_ids": ["DEMO-2026-0014"],
            "affected_vendor": "Tailspin Building Systems",
            "affected_product": "BMS Supervisor",
            "affected_firmware_range": "< 4.14",
            "recommended_mitigations": (
                "Update BMS Supervisor to 4.14u1 or later. Until patched, "
                "restrict station-admin role membership to the minimum viable "
                "set and audit backup-export logs."
            ),
            "published_date": today - timedelta(days=17),
            "source_url": "",
        },
        {
            "advisory_id": "DEMO-ICSA-26-052-01",
            "title": "Lamna Grid Systems VisionView HMI Stack Buffer Overflow",
            "summary": (
                "Sample advisory (fictional). Lamna Grid Systems VisionView HMI "
                "versions 6.5 SP2 and prior contain a stack-based buffer "
                "overflow (CWE-121) in the alarm handler. A local authenticated "
                "attacker can achieve code execution with SYSTEM privileges via "
                "a crafted alarm-history file."
            ),
            "severity": "HIGH",
            "cvss_score": "7.8",
            "cve_ids": ["DEMO-2026-0015"],
            "affected_vendor": "Lamna Grid Systems",
            "affected_product": "VisionView HMI",
            "affected_firmware_range": "<= 6.5 SP2",
            "recommended_mitigations": (
                "Apply VisionView HMI 6.5 SP3 or later. Restrict write access "
                "to the alarm history directory to the HMI service account only."
            ),
            "published_date": today - timedelta(days=24),
            "source_url": "",
        },
        {
            "advisory_id": "DEMO-ICSA-26-045-03",
            "title": "Proseware ProHistorian TLS Downgrade",
            "summary": (
                "Sample advisory (fictional). Proseware ProHistorian 2023 SP1 "
                "and earlier default to TLS 1.0 on the collector interface "
                "(TCP/7450), enabling a man-in-the-middle attacker on the "
                "operations network to downgrade sessions and capture process "
                "history."
            ),
            "severity": "MEDIUM",
            "cvss_score": "5.9",
            "cve_ids": ["DEMO-2026-0016"],
            "affected_vendor": "Proseware",
            "affected_product": "ProHistorian",
            "affected_firmware_range": "<= 2023 SP1",
            "recommended_mitigations": (
                "Upgrade to ProHistorian 2024, which disables TLS < 1.2 by "
                "default. In the interim, apply the vendor configuration "
                "hotfix to disable TLS 1.0/1.1 on the historian host."
            ),
            "published_date": today - timedelta(days=31),
            "source_url": "",
        },
        {
            "advisory_id": "DEMO-ICSA-26-038-05",
            "title": "Fabrikam Automation FT-7350 Thermostat Command Injection",
            "summary": (
                "Sample advisory (fictional). Fabrikam Automation FT-7350 "
                "thermostats expose a command injection (CWE-77) on the "
                "serial-over-IP gateway. A Modbus/TCP attacker can send a "
                "crafted register write that causes the thermostat to send "
                "arbitrary commands on the RS-485 bus."
            ),
            "severity": "MEDIUM",
            "cvss_score": "5.3",
            "cve_ids": ["DEMO-2026-0017"],
            "affected_vendor": "Fabrikam Automation",
            "affected_product": "FT-7350 Thermostat",
            "affected_firmware_range": "All firmware (no patch available)",
            "recommended_mitigations": (
                "Firmware is not field-updateable. Block direct network "
                "access to the thermostat serial-over-IP gateway; allow "
                "Modbus bridge traffic only from the HVAC PLC address."
            ),
            "published_date": today - timedelta(days=45),
            "source_url": "",
        },
        {
            "advisory_id": "DEMO-ICSA-26-031-02",
            "title": "Wide World Networks WW-4000 Industrial Switch Privilege Escalation",
            "summary": (
                "Sample advisory (fictional). Wide World Networks WW-4000 "
                "industrial Ethernet switches running WWOS 17.9.x expose a "
                "privilege escalation (CWE-269) via the REST management API. "
                "An authenticated operator-level user can elevate to "
                "administrator by submitting a malformed PATCH request."
            ),
            "severity": "HIGH",
            "cvss_score": "7.5",
            "cve_ids": ["DEMO-2026-0018"],
            "affected_vendor": "Wide World Networks",
            "affected_product": "WW-4000 Industrial Switch",
            "affected_firmware_range": "WWOS 17.9.x",
            "recommended_mitigations": (
                "Upgrade to WWOS 17.12.1 or later. If upgrade is not feasible, "
                "disable the REST API and use the SSH CLI for switch "
                "administration."
            ),
            "published_date": today - timedelta(days=52),
            "source_url": "",
        },
        {
            "advisory_id": "DEMO-ICSA-26-024-01",
            "title": "Adatum Networks AN-820 Management Web Interface XSS",
            "summary": (
                "Sample advisory (fictional). Adatum Networks AN-series "
                "firewalls running AdatumOS 11.0.0 through 11.1.2 contain a "
                "reflected cross-site scripting (CWE-79) in the management web "
                "interface's system log viewer. A crafted URL can execute "
                "script in the admin's browser session."
            ),
            "severity": "MEDIUM",
            "cvss_score": "4.8",
            "cve_ids": ["DEMO-2026-0019"],
            "affected_vendor": "Adatum Networks",
            "affected_product": "AN-820",
            "affected_firmware_range": "AdatumOS 11.0.0 – 11.1.2",
            "recommended_mitigations": (
                "Upgrade to AdatumOS 11.1.3 or later. Restrict management "
                "interface access to the dedicated management VLAN only."
            ),
            "published_date": today - timedelta(days=60),
            "source_url": "",
        },
        {
            "advisory_id": "DEMO-ICSA-26-017-06",
            "title": "Wingtip Security WS-2000 Door Controller Default Credentials",
            "summary": (
                "Sample advisory (fictional). Wingtip Security WS-1000/WS-2000 "
                "access control panels ship with a default service account "
                "(CWE-798) that remains active after initial commissioning. An "
                "attacker on the access-control VLAN can authenticate and "
                "release any door under the panel's control."
            ),
            "severity": "CRITICAL",
            "cvss_score": "9.8",
            "cve_ids": ["DEMO-2026-0020"],
            "affected_vendor": "Wingtip Security",
            "affected_product": "WS-2000 Door Controller",
            "affected_firmware_range": "WS-1000/WS-2000 all firmware",
            "recommended_mitigations": (
                "Rotate the service account password immediately via the "
                "panel admin console; disable the account entirely if not "
                "required by the access-control host. Place panels on a "
                "dedicated security VLAN with no operator access."
            ),
            "published_date": today - timedelta(days=67),
            "source_url": "",
        },
        {
            "advisory_id": "DEMO-ICSA-26-010-03",
            "title": "Southridge Video VMS Recording Server Authentication Flaw",
            "summary": (
                "Sample advisory (fictional). Southridge Video VMS 2024 R1 "
                "contains an authentication flaw (CWE-287) in the recording "
                "server's stream handler allowing an unauthenticated attacker "
                "on the video network to retrieve camera streams."
            ),
            "severity": "HIGH",
            "cvss_score": "7.2",
            "cve_ids": ["DEMO-2026-0021"],
            "affected_vendor": "Southridge Video",
            "affected_product": "Southridge VMS",
            "affected_firmware_range": "2024 R1",
            "recommended_mitigations": (
                "Apply the 2024 R1 hotfix or upgrade to 2024 R2. Segment the "
                "video network from the general user VLAN; restrict stream-port "
                "access to authorized recorder clients."
            ),
            "published_date": today - timedelta(days=78),
            "source_url": "",
        },
    ]

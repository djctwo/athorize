"""Sample (offline / demo) threat-advisory conventions.

Every advisory bundled with Athorize — the offline ICS feed, the KEV / NVD /
AA / PSIRT fixtures and the demo seed — is FICTIONAL: made-up vendors and
products, and identifiers in a reserved ``DEMO-`` namespace so they can never
collide with (or be mistaken for) a real CVE, CISA ICSA/AA advisory or vendor
PSIRT record. Live feeds are untouched by this module except that links to
CVE databases are only built for genuine CVE identifiers.

Fictional vendors used by the bundled samples (none is a real company):
VanArsdel Controls, Fabrikam Automation, Lamna Grid Systems, Proseware,
Tailspin Building Systems, Wingtip Security, Southridge Video,
Wide World Networks, Adatum Networks, Woodgrove Software, Litware.
"""
from __future__ import annotations

import re

SAMPLE_PREFIX = "DEMO-"

# A sample advisory id carries the reserved DEMO- segment either at the start
# (DEMO-ICSA-26-073-01, DEMO-AA26-158A) or after a feed prefix the normalizers
# add (KEV-DEMO-2026-0101, NVD-DEMO-2026-0201).
_SAMPLE_ID = re.compile(r"(?:^|-)DEMO-")
_REAL_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def is_sample_id(identifier: str | None) -> bool:
    return bool(identifier) and bool(_SAMPLE_ID.search(identifier or ""))


def is_real_cve_id(identifier: str | None) -> bool:
    return bool(identifier) and bool(_REAL_CVE.match((identifier or "").strip()))

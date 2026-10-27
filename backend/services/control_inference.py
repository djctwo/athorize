"""Infer relevant SP 800-53 controls for a threat-feed item.

Every advisory/KEV entry implies control obligations: at minimum the
vulnerability-management pair (RA-5 flaw identification, SI-2 remediation),
plus keyword-derived controls. Inferred ids are 800-53 base controls — the
hub framework — so the crosswalk fans each feed item's obligations out to
every other active framework automatically.
"""
from __future__ import annotations

import re

# Always relevant to a published vulnerability/exploitation advisory
BASE_CONTROLS = ["RA-5", "SI-2"]

# keyword pattern → controls. Patterns run case-insensitively over
# title + summary + required mitigations.
KEYWORD_RULES: list[tuple[str, list[str]]] = [
    (r"ransomware|backup|encrypt(ed|ion)? (files|data)|extortion", ["CP-9", "CP-10", "IR-4"]),
    (r"credential|password|authenticat|brute.?force|default (login|credential)", ["IA-2", "IA-5"]),
    (r"remote (access|code execution)|rce|vpn|rdp\b", ["AC-17", "SC-7"]),
    (r"privilege escalation|elevation of privilege|root access|admin(istrator)? rights", ["AC-6"]),
    (r"injection|cross.?site|xss|deserializ|input validation", ["SI-10"]),
    (r"denial.of.service|\bdos\b|resource exhaustion", ["SC-5"]),
    (r"firmware|supply.?chain|third.?party component", ["CM-8", "SR-3"]),
    (r"unencrypted|cleartext|plaintext (traffic|transmission)|man.in.the.middle", ["SC-8"]),
    (r"segment|lateral movement|network isolation", ["SC-7"]),
    (r"phishing|social engineering", ["AT-2"]),
    (r"logging|audit (log|trail)|monitoring", ["AU-6", "SI-4"]),
]


def infer_controls(advisory: dict) -> list[str]:
    text = " ".join(
        str(advisory.get(k) or "")
        for k in ("title", "summary", "recommended_mitigations")
    ).lower()
    controls = list(BASE_CONTROLS)
    for pattern, ctrl_ids in KEYWORD_RULES:
        if re.search(pattern, text):
            for c in ctrl_ids:
                if c not in controls:
                    controls.append(c)
    return controls

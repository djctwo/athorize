"""Generate frameworks/irs-1075/mappings.json — identity mapping to 800-53 r5.

IRS Publication 1075 §9.3 is a tailored selection of SP 800-53 controls: each
§9.3.x control IS a named 800-53 control with IRS-specific parameter values.
The mapping is therefore a 1:1 identity to 800-53 (relationship `equivalent`,
confidence `official`), resolved by matching the IRS control title to the
800-53 control title.

Pub 1075 predates the SP 800-53 Rev 5 renames, so 14 controls carry their Rev 4
names ("Audit Events" → AU-2 "Event Logging", "System Backup" → CP-9, the
family "... Policy and Procedures" controls → XX-1, etc.). Those are resolved
through ALIASES below — each is a documented NIST r4→r5 rename, i.e. the same
control under its updated name, not an interpretive judgment.

Usage:
    python scripts/build_mappings/build_irs1075_mappings.py

No external source file — the IRS catalog titles + the bundled 800-53 catalog
are sufficient.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "frameworks" / "irs-1075" / "mappings.json"

# IRS §9.3.x control id -> 800-53 r5 control id, for titles changed by the
# r4→r5 rename (or family "-1" policy controls). Each is a same-control rename.
ALIASES = {
    "9.3.1": "AC-1",    # Access Control Policy and Procedures → AC-1 Policy and Procedures
    "9.3.11": "AC-20",  # Use of External Information Systems → Use of External Systems
    "9.3.12": "AT-2",   # Security Awareness Training → Literacy Training and Awareness
    "9.3.13": "AT-3",   # Role-Based Security Training → Role-Based Training
    "9.3.14": "AU-2",   # Audit Events → Event Logging
    "9.3.16": "AU-4",   # Audit Storage Capacity → Audit Log Storage Capacity
    "9.3.17": "AU-5",   # Response to Audit Processing Failures → Response to Audit Logging Process Failures
    "9.3.18": "AU-6",   # Audit Review, Analysis, and Reporting → Audit Record Review, Analysis, and Reporting
    "9.3.19": "AU-7",   # Audit Reduction and Report Generation → Audit Record Reduction and Report Generation
    "9.3.26": "CP-9",   # Information System Backup → System Backup
    "9.3.27": "CP-10",  # Information System Recovery and Reconstitution → System Recovery and Reconstitution
    "9.3.28": "IA-2",   # Identification and Authentication → Identification and Authentication (Organizational Users)
    "9.3.30": "IR-1",   # Incident Response Policy and Procedures → IR-1 Policy and Procedures
    "9.3.32": "MP-1",   # Media Protection Policy → MP-1 Policy and Procedures
}


def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def main() -> int:
    hub = json.loads((REPO / "frameworks" / "nist-800-53-r5" / "catalog.json").read_text())["controls"]
    irs = json.loads((REPO / "frameworks" / "irs-1075" / "catalog.json").read_text())["controls"]
    n53_ids = {c["id"] for c in hub}
    # title -> id, but XX-1 controls all share "Policy and Procedures" — exclude
    # from the title index so they only resolve via ALIASES (family-disambiguated).
    by_title: dict[str, str] = {}
    for c in hub:
        if norm(c["title"]) == norm("Policy and Procedures"):
            continue
        by_title.setdefault(norm(c["title"]), c["id"])

    mappings = []
    unresolved = []
    for c in irs:
        target = ALIASES.get(c["id"]) or by_title.get(norm(c["title"]))
        if not target or target not in n53_ids:
            unresolved.append((c["id"], c["title"]))
            continue
        mappings.append({
            "control_id": c["id"],
            "target_framework": "nist-800-53-r5",
            "target_control": target,
            "relationship": "equivalent",
            "confidence": "official",
            "rationale": f"IRS Pub 1075 §9.3 selects SP 800-53r5 {target} ({c['title']})",
        })

    mappings.sort(key=lambda m: m["control_id"])
    OUT.write_text(json.dumps({
        "framework_id": "irs-1075",
        "version": "1.0",
        "source": "Identity mapping — IRS Pub 1075 §9.3 is a tailored SP 800-53r5 control selection (title join + documented r4→r5 rename aliases)",
        "mappings": mappings,
    }, indent=2) + "\n")
    print(f"wrote {OUT.relative_to(REPO)}: {len(mappings)}/{len(irs)} IRS controls mapped")
    if unresolved:
        print(f"WARNING — unresolved IRS controls: {unresolved}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

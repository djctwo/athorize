"""Generate frameworks/nist-800-82-r3/mappings.json — OT overlay to 800-53 r5.

SP 800-82r3 is NIST's OT overlay of SP 800-53r5: each OT-prefixed control
(OT-AC-2) is the corresponding base control (AC-2) with OT-specific tailoring
and guidance. The mapping is the prefix-stripped identity, relationship
`equivalent`, confidence `official`.

Usage:
    python scripts/build_mappings/build_80082_mappings.py
"""
from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "frameworks" / "nist-800-82-r3" / "mappings.json"


def main() -> int:
    catalog = json.loads((REPO / "frameworks" / "nist-800-82-r3" / "catalog.json").read_text())
    n53_ids = {
        c["id"]
        for c in json.loads((REPO / "frameworks" / "nist-800-53-r5" / "catalog.json").read_text())["controls"]
    }
    mappings = []
    skipped = []
    for c in catalog["controls"]:
        if not c["id"].startswith("OT-"):
            skipped.append(c["id"])
            continue
        base = c["id"][3:]
        if base not in n53_ids:
            skipped.append(c["id"])
            continue
        mappings.append({
            "control_id": c["id"],
            "target_framework": "nist-800-53-r5",
            "target_control": base,
            "relationship": "equivalent",
            "confidence": "official",
            "rationale": f"SP 800-82r3 OT overlay of SP 800-53r5 {base}",
        })
    OUT.write_text(json.dumps({
        "framework_id": "nist-800-82-r3",
        "version": "1.0",
        "source": "SP 800-82r3 OT overlay — prefix-stripped identity to the tailored SP 800-53r5 base controls",
        "mappings": mappings,
    }, indent=2) + "\n")
    print(f"wrote {OUT.relative_to(REPO)}: {len(mappings)} mappings")
    if skipped:
        print(f"WARNING — skipped (no 800-53 base): {skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

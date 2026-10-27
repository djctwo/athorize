"""Generate frameworks/stateramp/mappings.json — identity mapping to 800-53 r5.

StateRAMP, like FedRAMP, builds its baselines as selections of SP 800-53r5
controls. The StateRAMP catalog in this repo prefixes each control id with
`SR-` (SR-AC-2 = the StateRAMP-selected AC-2). The mapping is the
prefix-stripped identity: relationship `equivalent`, confidence `official`.

Usage:
    python scripts/build_mappings/build_stateramp_mappings.py
"""
from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "frameworks" / "stateramp" / "mappings.json"


def main() -> int:
    catalog = json.loads((REPO / "frameworks" / "stateramp" / "catalog.json").read_text())
    n53_ids = {
        c["id"]
        for c in json.loads((REPO / "frameworks" / "nist-800-53-r5" / "catalog.json").read_text())["controls"]
    }
    mappings = []
    skipped = []
    for c in catalog["controls"]:
        if not c["id"].startswith("SR-"):
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
            "rationale": f"StateRAMP baseline selection of SP 800-53r5 {base}",
        })
    OUT.write_text(json.dumps({
        "framework_id": "stateramp",
        "version": "1.0",
        "source": "Identity mapping — StateRAMP baselines are SP 800-53r5 control selections (SR- prefix stripped)",
        "mappings": mappings,
    }, indent=2) + "\n")
    print(f"wrote {OUT.relative_to(REPO)}: {len(mappings)} mappings")
    if skipped:
        print(f"WARNING — skipped (no 800-53 base): {skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

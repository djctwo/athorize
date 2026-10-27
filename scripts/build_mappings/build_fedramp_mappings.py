"""Generate frameworks/fedramp/mappings.json — identity mapping to 800-53 r5.

FedRAMP baselines ARE selections of SP 800-53 controls; the FedRAMP catalog in
this repo uses 800-53 control ids verbatim. Every FedRAMP control therefore
maps `equivalent` to the same-id control in nist-800-53-r5.

Usage:
    python scripts/build_mappings/build_fedramp_mappings.py
"""
from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "frameworks" / "fedramp" / "mappings.json"


def main() -> int:
    catalog = json.loads((REPO / "frameworks" / "fedramp" / "catalog.json").read_text())
    n53_ids = {
        c["id"]
        for c in json.loads((REPO / "frameworks" / "nist-800-53-r5" / "catalog.json").read_text())["controls"]
    }
    mappings = []
    skipped = []
    for c in catalog["controls"]:
        if c["id"] not in n53_ids:
            skipped.append(c["id"])
            continue
        mappings.append({
            "control_id": c["id"],
            "target_framework": "nist-800-53-r5",
            "target_control": c["id"],
            "relationship": "equivalent",
            "confidence": "official",
            "rationale": "FedRAMP baselines are SP 800-53 control selections; ids are shared",
        })
    OUT.write_text(json.dumps({
        "framework_id": "fedramp",
        "version": "1.0",
        "source": "Identity mapping — FedRAMP baseline controls are SP 800-53r5 controls",
        "mappings": mappings,
    }, indent=2) + "\n")
    print(f"wrote {OUT.relative_to(REPO)}: {len(mappings)} mappings")
    if skipped:
        print(f"WARNING — FedRAMP ids not present in the bundled 800-53 catalog: {skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

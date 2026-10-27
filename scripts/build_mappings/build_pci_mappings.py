"""Generate frameworks/pci-dss-v4/mappings.json by composing PCI→CSF through CSF→800-53.

The crosswalk hub is SP 800-53 r5, and there is no authoritative public
PCI→800-53 mapping. We therefore compose:

    PCI requirement  --(OLIR CSF↔PCI, inverted)-->  CSF subcategory
    CSF subcategory  --(our nist-csf-2.0/mappings.json)-->  800-53 control

yielding PCI requirement → 800-53 control edges, shipped as `intersects` /
`derived` (a two-hop composition through two concept crosswalks — directional
but not equivalency).

Source (CC0-1.0, public domain): OLIR informative reference #183,
"NIST CSF 2.0 ↔ PCI DSS v4.0.1" — the focal=CSF / reference=PCI workbook from
the OLIR-cataloged submission (Glimpz1/grc-mappings, CC0).

Usage:
    python scripts/build_mappings/build_pci_mappings.py /path/to/csf-pci.xlsx

Requires: openpyxl (dev-only).
"""
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "frameworks" / "pci-dss-v4" / "mappings.json"

SUBCATEGORY = re.compile(r"^[A-Z]{2}\.[A-Z]{2}-\d{2}$")  # GV.OC-01
PCI_REQ = re.compile(r"^\d+\.\d+(\.\d+)*$")  # 12.1.1


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    import openpyxl

    pci_ids = {
        c["id"]
        for c in json.loads((REPO / "frameworks" / "pci-dss-v4" / "catalog.json").read_text())["controls"]
    }

    # CSF subcategory -> set of 800-53 controls (our existing public mapping)
    csf_to_53: dict[str, set[str]] = defaultdict(set)
    for m in json.loads((REPO / "frameworks" / "nist-csf-2.0" / "mappings.json").read_text())["mappings"]:
        csf_to_53[m["control_id"]].add(m["target_control"])

    # Parse PCI↔CSF: focal=CSF subcategory (col 0), reference=PCI req (col 4)
    wb = openpyxl.load_workbook(sys.argv[1])
    ws = wb["Relationships"]
    pci_to_csf: dict[str, set[str]] = defaultdict(set)
    for row in ws.iter_rows(min_row=2, values_only=True):
        csf_el = str(row[0] or "").strip()
        pci_el = str(row[4] or "").strip()
        if not SUBCATEGORY.match(csf_el) or not PCI_REQ.match(pci_el):
            continue
        # Our PCI catalog is 2-level (12.1); the workbook is 3-level (12.1.1).
        # Map up to the catalog's granularity.
        candidate = pci_el
        while candidate and candidate not in pci_ids:
            if "." not in candidate:
                candidate = ""
                break
            candidate = candidate.rsplit(".", 1)[0]
        if candidate:
            pci_to_csf[candidate].add(csf_el)

    # Compose PCI -> CSF -> 800-53
    mappings = []
    seen = set()
    for pci_req, csf_subs in sorted(pci_to_csf.items()):
        targets: set[str] = set()
        for sub in csf_subs:
            targets |= csf_to_53.get(sub, set())
        for ctrl in sorted(targets):
            key = (pci_req, ctrl)
            if key in seen:
                continue
            seen.add(key)
            mappings.append({
                "control_id": pci_req,
                "target_framework": "nist-800-53-r5",
                "target_control": ctrl,
                "relationship": "intersects",
                "confidence": "derived",
                "rationale": f"PCI {pci_req} → CSF {'/'.join(sorted(csf_subs))} → {ctrl} (composed crosswalk)",
            })

    OUT.write_text(json.dumps({
        "framework_id": "pci-dss-v4",
        "version": "1.0",
        "source": "Composed: OLIR #183 NIST CSF 2.0 ↔ PCI DSS v4.0.1 (CC0) through the bundled CSF→800-53r5 mapping. Two-hop derived crosswalk.",
        "mappings": mappings,
    }, indent=2) + "\n")
    covered = len({m["control_id"] for m in mappings})
    print(f"wrote {OUT.relative_to(REPO)}: {len(mappings)} edges covering {covered} PCI requirements")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
